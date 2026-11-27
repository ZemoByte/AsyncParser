#!/usr/bin/env python3
"""Label downloaded MalwareBazaar samples using rat_king_parser.

Reads the append-only download ledger, checks the PE CLR header statically,
runs the parser in batches, and writes one JSON file per sample under
Data/Labels/. It never writes to the ledger.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import dnfile
except Exception:  # pragma: no cover - dnfile is a declared dependency
    dnfile = None


def detect_obfuscator(path: Path) -> str | None:
    if dnfile is None or not is_dotnet(path):
        return None
    try:
        pe = dnfile.dnPE(str(path))
    except Exception:
        return None
    names = set()
    metadata = getattr(getattr(pe, "net", None), "mdtables", None)
    if metadata is not None:
        for table_name in ("TypeDef",):
            table = getattr(metadata, table_name, None)
            if table:
                for row in table:
                    names.add(str(getattr(row, "TypeName", "") or ""))
        for table_name in ("CustomAttribute",):
            table = getattr(metadata, table_name, None)
            if table:
                for row in table:
                    typed = getattr(row, "Type", None)
                    target = getattr(typed, "row", None)
                    if target is None:
                        continue
                    # MemberRefRow: navigate Class.row -> TypeRef/TypeDef
                    if type(target).__name__ == "MemberRefRow":
                        cls = getattr(target, "Class", None)
                        cls_row = getattr(cls, "row", None) if cls is not None else None
                        if cls_row is not None:
                            names.add(str(getattr(cls_row, "TypeName", "") or ""))
                    else:
                        # TypeRefRow or TypeDefRow
                        names.add(str(getattr(target, "TypeName", "") or ""))
                    names.add(str(getattr(target, "Name", "") or ""))
    if "ConfusedByAttribute" in names:
        return "ConfuserEx"
    if "LoGiCdotNetAttribute" in names:
        return "LoGiC.NET"
    return None

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DEFAULT_DB = ROOT / "Tools" / "MBDownloader" / "samples.db"
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from Tools._label_common import canonical_family  # noqa: E402
from Tools._pe import is_dotnet  # noqa: E402

EVIDENCE_RAW_LIMIT = 1000


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def parser_version() -> str:
    proc = subprocess.run(
        ["rat-king-parser", "-v"], capture_output=True, text=True, check=True
    )
    parts = proc.stdout.strip().split()
    if len(parts) < 2:
        raise RuntimeError("could not read rat-king-parser version")
    return parts[-1]


def map_config(raw) -> dict | None:
    if isinstance(raw, str):
        if raw.startswith("Exception encountered"):
            return {"parse_error": raw}
        return None
    if not isinstance(raw, dict) or not raw:
        return None
    lookup = {str(key).lower(): value for key, value in raw.items()}
    wanted = ("hosts", "ports", "mutex", "key", "salt")
    result = {name: lookup[name] for name in wanted if name in lookup}
    return result or None


def label_status(is_net: bool, family: str) -> tuple[str, str]:
    if not is_net:
        return "rejected_non_dotnet", ""
    normalized = (family or "").strip().lower()
    if normalized == "asyncrat":
        return "verified", ""
    if normalized and normalized != "no match":
        return "review", family.strip()
    return "unverified", ""


def obfuscation_level(is_net: bool, report: dict | None, path: Path) -> str:
    if report is None or isinstance(report.get("config"), str):
        return "unknown"
    if not is_net:
        return "unknown"
    fingerprint = detect_obfuscator(path)
    if fingerprint is not None:
        return f"obfuscated:{fingerprint}"
    return "unknown"


def run_parser(paths: list[Path]) -> dict[str, dict]:
    reports: dict[str, dict] = {}
    if not paths:
        return reports
    for start in range(0, len(paths), 100):
        chunk = paths[start:start + 100]
        proc = subprocess.run(
            ["rat-king-parser", "-n"] + [str(path) for path in chunk],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            raise RuntimeError(proc.stderr.strip() or "rat-king-parser failed")
        try:
            parsed = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"invalid parser JSON: {exc}") from exc
        if not isinstance(parsed, list):
            raise RuntimeError("parser output is not a JSON list")
        for report in parsed:
            sha256 = str(report.get("sha256") or "").lower()
            if sha256:
                reports[sha256] = report
    return reports


def build_sample_index(samples_root: Path) -> dict[str, Path]:
    index = {}
    for class_dir in (samples_root / "AsyncRAT", samples_root / "OtherMalwares",
                      samples_root / "Benign"):
        if not class_dir.is_dir():
            continue
        for path in class_dir.iterdir():
            if path.is_file():
                index[path.stem.lower()] = path
    return index


def find_sample_path(index: dict[str, Path], sha256: str) -> Path | None:
    return index.get(sha256.lower())


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def write_evidence(out_root: Path, sha256: str, source_version: str, verdict: str,
                   strength: str, raw: dict) -> None:
    payload = {
        "schema_version": 1,
        "sha256": sha256,
        "kind": "evidence",
        "producer": "voter:rat_king_parser",
        "fields": {
            "source": "rat_king_parser",
            "source_version": source_version,
            "independence_group": "yara:rat-king",
            "verdict": verdict,
            "strength": strength,
            "raw": raw,
            "observed_at": utc_now(),
        },
    }
    write_json(out_root / "Evidence" / sha256 / "rat_king_parser.json", payload)


def load_benign_manifest(path: Path) -> dict[str, dict]:
    manifest: dict[str, dict] = {}
    if not path.is_file():
        return manifest
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            sha256 = str(row.get("sha256") or "").strip()
            if not sha256:
                continue
            manifest[sha256] = {
                "source": str(row.get("source") or "unknown"),
                "origin": str(row.get("origin") or row.get("source") or "unknown"),
                "ext": str(row.get("ext") or ""),
            }
    return manifest


def benign_provenance(entry: dict, path: Path) -> dict:
    ext = str(entry.get("ext") or path.suffix.lower())
    kind = "exe" if ext == ".exe" else ("dll" if ext == ".dll" else "other")
    return {
        "source": str(entry.get("source") or "unknown"),
        "origin": str(entry.get("origin") or "unknown"),
        "kind": kind,
    }


def benign_only(args) -> int:
    """Label only Samples/Benign; no ledger read, no parser, no truncation."""
    benign_root = args.benign_root.resolve()
    out_root = args.out.resolve()
    labels_dir = out_root / "Labels"
    evidence_dir = out_root / "Evidence"
    labels_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir.mkdir(parents=True, exist_ok=True)

    manifest = load_benign_manifest(out_root / "BenignSources.csv")
    written = 0
    if benign_root.is_dir():
        for path in sorted(benign_root.iterdir()):
            if not path.is_file():
                continue
            sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
            label_path = labels_dir / f"{sha256}.json"
            evidence_path = evidence_dir / sha256 / "rat_king_parser.json"
            entry = manifest.get(sha256, {})
            provenance = benign_provenance(entry, path)
            source = provenance["source"]
            origin = provenance["origin"]
            sample_kind = provenance["kind"]
            is_net = is_dotnet(path)
            status = "benign" if is_net else "rejected_non_dotnet"
            suggested = "Benign" if is_net else ""
            if label_path.is_file():
                payload = json.loads(label_path.read_text(encoding="utf-8"))
                fields = payload.setdefault("fields", {})
                if (fields.get("source") != source
                        or fields.get("origin") != origin
                        or fields.get("kind") != sample_kind):
                    fields.update(provenance)
                    write_json(label_path, payload)
                    written += 1
            else:
                payload = {
                    "schema_version": 1,
                    "sha256": sha256,
                    "kind": "label",
                    "producer": "labeler",
                    "fields": {
                        "sha256": sha256,
                        "lbl_sts": status,
                        "sug_fam": suggested,
                        "is_dotnet": is_net,
                        "obf_lvl": "unknown",
                        "parser_version": "",
                        "config": None,
                        "source": source,
                        "origin": origin,
                        "kind": sample_kind,
                    },
                }
                write_json(label_path, payload)
                written += 1
            if not evidence_path.is_file():
                raw = {"reason": "benign_not_parsed" if is_net else "not_dotnet"}
                write_evidence(out_root, sha256, "benign-only", "no_match",
                               "strong", raw)
                written += 1

    total_labels = len(list(labels_dir.glob("*.json")))
    total_evidence = len(list(evidence_dir.glob("*/rat_king_parser.json")))
    (labels_dir / ".labeler.done").write_text(
        json.dumps({"producer": "labeler", "count": total_labels,
                    "mode": "benign-only"}, sort_keys=True),
        encoding="utf-8",
    )
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / ".rat_king_parser.done").write_text(
        json.dumps({"producer": "voter:rat_king_parser",
                    "source_version": "benign-only", "count": total_evidence},
                   sort_keys=True),
        encoding="utf-8",
    )
    print(f"benign-only: wrote {written} files, total labels {total_labels}, "
          f"total evidence {total_evidence}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Label downloaded samples")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--benign-root", type=Path, default=DEFAULT_SAMPLES / "Benign")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--benign-only", action="store_true",
                        help="label Samples/Benign only; no ledger, no parser")
    args = parser.parse_args()

    if args.benign_only:
        return benign_only(args)

    samples_root = args.samples_root.resolve()
    benign_root = args.benign_root.resolve()
    out_root = args.out.resolve()
    labels_dir = out_root / "Labels"
    evidence_dir = out_root / "Evidence"
    sample_index = build_sample_index(samples_root)
    manifest = load_benign_manifest(out_root / "BenignSources.csv")

    connection = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    try:
        rows = connection.execute(
            "SELECT sha256_hash, status FROM downloads ORDER BY sha256_hash"
        ).fetchall()
    finally:
        connection.close()

    if args.limit is not None:
        rows = rows[:args.limit]

    ledger_targets = []
    for sha256, status in rows:
        if status not in {"success", "adopted"}:
            continue
        path = find_sample_path(sample_index, sha256)
        if path is None:
            raise RuntimeError(f"sample file not found for {sha256}")
        ledger_targets.append((sha256, path))

    benign_targets = []
    if benign_root.is_dir():
        for path in sorted(benign_root.iterdir()):
            if not path.is_file():
                continue
            benign_targets.append((hashlib.sha256(path.read_bytes()).hexdigest(), path))

    reports = run_parser([path for _, path in ledger_targets])
    detected_parser_version = parser_version()

    targets = ledger_targets + benign_targets
    benign_paths = {path for _, path in benign_targets}
    evidence_count = 0
    for sha256, path in targets:
        report = reports.get(sha256.lower()) if (sha256, path) in ledger_targets else None
        is_net = is_dotnet(path)
        is_benign = path in benign_paths
        family = ""
        config = None
        if report is not None:
            family = str(report.get("yara_possible_family") or "")
            config = map_config(report.get("config"))
        if is_benign:
            status = "benign" if is_net else "rejected_non_dotnet"
            suggested_family = "Benign" if is_net else ""
        else:
            status, suggested_family = label_status(is_net, family)
            if family and family.lower() not in {"", "no match", "asyncrat"} and status == "review":
                suggested_family = family
        payload = {
            "schema_version": 1,
            "sha256": sha256,
            "kind": "label",
            "producer": "labeler",
            "fields": {
                "sha256": sha256,
                "lbl_sts": status,
                "sug_fam": suggested_family,
                "is_dotnet": is_net,
                "obf_lvl": obfuscation_level(is_net, report, path),
                "parser_version": detected_parser_version if report is not None else "",
                "config": config,
            },
        }
        if is_benign:
            entry = manifest.get(sha256, {})
            payload["fields"].update(benign_provenance(entry, path))
        write_json(labels_dir / f"{sha256}.json", payload)

        if not is_net:
            verdict = "no_match"
            raw = {"reason": "not_dotnet"}
        elif is_benign:
            verdict = "no_match"
            raw = {"reason": "benign_not_parsed"}
        elif report is None:
            verdict = "no_match"
            raw = {"reason": "no_parser_report"}
        else:
            raw_family = str(report.get("yara_possible_family") or "")
            canonical_error = None
            try:
                verdict = canonical_family(raw_family) or "no_match"
            except RuntimeError as exc:
                verdict = "no_match"
                canonical_error = str(exc)
            config_raw = report.get("config")
            raw = {
                "yara_possible_family": raw_family,
                "config_present": isinstance(config_raw, dict) and bool(config_raw),
                "config_error": (
                    config_raw[:EVIDENCE_RAW_LIMIT] if isinstance(config_raw, str) else None
                ),
                "canonical_error": canonical_error,
            }
        write_evidence(out_root, sha256, detected_parser_version,
                       verdict, "strong", raw)
        evidence_count += 1

    marker = labels_dir / ".labeler.done"
    marker.write_text(json.dumps({"producer": "labeler", "count": len(targets)}, sort_keys=True),
                     encoding="utf-8")
    evidence_dir.mkdir(parents=True, exist_ok=True)
    evidence_marker = evidence_dir / ".rat_king_parser.done"
    evidence_marker.write_text(
        json.dumps({"producer": "voter:rat_king_parser",
                    "source_version": detected_parser_version,
                    "count": evidence_count}, sort_keys=True),
        encoding="utf-8",
    )
    print(f"labeled {len(targets)} samples into {labels_dir}")
    print(f"wrote {evidence_count} rat_king_parser evidence files into {evidence_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

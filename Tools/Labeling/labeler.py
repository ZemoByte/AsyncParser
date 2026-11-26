#!/usr/bin/env python3
"""Label downloaded MalwareBazaar samples using rat_king_parser.

Reads the append-only download ledger, checks the PE CLR header statically,
runs the parser in batches, and writes one JSON file per sample under
Data/Labels/. It never writes to the ledger.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

import pefile

try:
    import dnfile
except Exception:  # pragma: no cover - dnfile is a declared dependency
    dnfile = None

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DEFAULT_DB = ROOT / "Tools" / "MBDownloader" / "samples.db"
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
PARSER_VERSION = "4.2.4"
def is_dotnet(path: Path) -> bool:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(data_directory) > 14 and data_directory[14].Size > 0
    except Exception:
        return False


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


def obfuscation_level(is_net: bool, report: dict | None) -> str:
    if report is None or isinstance(report.get("config"), str):
        return "unknown"
    if not is_net:
        return "unknown"
    # Obfuscator fingerprints are not detected by raw byte scans. They are
    # supplied and checked separately; until then every successful parse is
    # reported as unknown rather than guessed.
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


def find_sample_path(samples_root: Path, sha256: str) -> Path | None:
    matches = [path for path in samples_root.rglob("*")
               if path.is_file() and path.stem.lower() == sha256.lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Label downloaded samples")
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--benign-root", type=Path, default=DEFAULT_SAMPLES / "Benign")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    benign_root = args.benign_root.resolve()
    out_root = args.out.resolve()
    labels_dir = out_root / "Labels"

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
        path = find_sample_path(samples_root, sha256)
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

    targets = ledger_targets + benign_targets
    for sha256, path in targets:
        report = reports.get(sha256.lower()) if (sha256, path) in ledger_targets else None
        is_net = is_dotnet(path)
        family = ""
        config = None
        if report is not None:
            family = str(report.get("yara_possible_family") or "")
            config = map_config(report.get("config"))
        if path in [p for _, p in benign_targets]:
            status = "unverified" if is_net else "rejected_non_dotnet"
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
                "obf_lvl": obfuscation_level(is_net, report),
                "parser_version": PARSER_VERSION if report is not None else "",
                "config": config,
            },
        }
        write_json(labels_dir / f"{sha256}.json", payload)

    marker = labels_dir / ".labeler.done"
    marker.write_text(json.dumps({"producer": "labeler", "count": len(targets)}, sort_keys=True),
                     encoding="utf-8")
    print(f"labeled {len(targets)} samples into {labels_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

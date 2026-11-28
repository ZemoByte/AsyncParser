#!/usr/bin/env python3
"""Build the human gold-review sheet (read-only for pipeline outputs).

Reads Data/Gold/gold.csv, the final labels and voter evidence for the gold
sha256 values only, and writes:
  Data/Gold/review/gold_review_sheet.csv
  Data/Gold/review/gold_review_sheet.md

Sample paths are resolved by **SHA-256**, never by file name: the fast path
`<class>/<sha>.exe` is verified by hashing, otherwise every file in the three
sample class dirs is hashed and matched. Missing or partially written JSON is
reported as `pending`, never fatal.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import GOLD_COLUMNS, load_final_label  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_SOURCES = ROOT / "Data" / "BenignSources.csv"
SAMPLE_DIRS = ("AsyncRAT", "OtherMalwares", "Benign")
VOTERS = ("rat_king_parser", "own_yara", "elastic", "malpedia",
          "malwarebazaar", "detect_it_easy", "yaraify")
PROVENANCE_COLUMNS = ("file_path", "sample_class", "sample_origin",
                      "sample_source")
EXTRA_COLUMNS = PROVENANCE_COLUMNS + (
    "file_size", "is_dotnet", "config_present", "obf_lvl",
    *VOTERS, "label_reason", "notes_for_analyst",
    "gold_snapshot_status", "gold_snapshot_family",
)


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_sources(path: Path) -> dict[str, dict]:
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return {str(row.get("sha256") or "").strip(): row
                for row in csv.DictReader(handle)}


def build_sample_index(samples_root: Path, wanted: set[str]) -> tuple[dict, list]:
    """Map sha256 -> (class, path); deterministic class precedence."""
    cache: dict[Path, str] = {}
    matches: dict[str, list[tuple[str, Path]]] = defaultdict(list)

    for class_name in SAMPLE_DIRS:
        class_dir = samples_root / class_name
        if not class_dir.is_dir():
            continue
        for sha256 in wanted:
            candidate = class_dir / f"{sha256}.exe"
            if not candidate.is_file():
                continue
            digest = cache.get(candidate) or sha256_file(candidate)
            cache[candidate] = digest
            if digest == sha256:
                matches[sha256].append((class_name, candidate))

    for class_name in SAMPLE_DIRS:
        class_dir = samples_root / class_name
        if not class_dir.is_dir():
            continue
        for candidate in sorted(class_dir.iterdir()):
            if not candidate.is_file() or candidate in cache:
                continue
            digest = sha256_file(candidate)
            cache[candidate] = digest
            if digest in wanted:
                matches[digest].append((class_name, candidate))

    order = {name: index for index, name in enumerate(SAMPLE_DIRS)}
    index: dict[str, tuple[str, Path]] = {}
    duplicates = []
    for sha256, found in matches.items():
        found.sort(key=lambda item: (order[item[0]], str(item[1])))
        index[sha256] = found[0]
        if len(found) > 1:
            duplicates.append({"sha256": sha256,
                               "paths": [f"{name}/{path.name}"
                                         for name, path in found]})
    return index, duplicates


def find_sample(index: dict, sha256: str) -> Path | None:
    match = index.get(sha256)
    return match[1] if match else None


def read_json_atomic(path: Path) -> dict | None:
    """Read a JSON written by the pipeline; None if absent or mid-write."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def evidence_fields(data_root: Path, sha256: str, voter: str) -> dict | None:
    payload = read_json_atomic(data_root / "Evidence" / sha256 / f"{voter}.json")
    if payload is None:
        return None
    fields = payload.get("fields")
    return fields if isinstance(fields, dict) else None


def evidence_cell(fields: dict | None) -> str:
    if fields is None:
        return "pending"
    verdict = str(fields.get("verdict") or "-")
    strength = str(fields.get("strength") or "-")
    scope = str(fields.get("scope") or "-")
    return f"{verdict}/{strength}/{scope}"


def derive_current_family(status: str, sug_fam: str) -> str:
    if status == "verified":
        return "AsyncRAT"
    if status == "benign":
        return "Benign"
    return str(sug_fam or "")


def load_db_labels(data_root: Path) -> dict[str, tuple[str, str]]:
    path = data_root / "DataSet.db"
    if not path.is_file():
        return {}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {row[0]: (str(row[1] or ""), str(row[2] or ""))
                for row in conn.execute(
                    "SELECT sha256, lbl_sts, sug_fam FROM dataset")}
    finally:
        conn.close()


def final_fields(data_root: Path, sha256: str) -> dict:
    try:
        return load_final_label(sha256, data_root)
    except (RuntimeError, OSError, json.JSONDecodeError):
        return {}


def label_reason(data_root: Path, sha256: str) -> str:
    payload = read_json_atomic(data_root / "Aggregated" / f"{sha256}.json")
    if payload is None:
        return ""
    fields = payload.get("fields")
    if not isinstance(fields, dict):
        return ""
    return str(fields.get("lbl_reason") or "")[:500]


def provenance(class_name: str, entry: dict | None) -> tuple[str, str]:
    """Return (origin, source) for one resolved sample."""
    source = str((entry or {}).get("source") or "").strip()
    origin = str((entry or {}).get("origin") or "").strip().lower()
    if class_name == "Benign":
        if not entry:
            return "unknown", "Benign"
        sample_origin = "fixture" if origin == "fixture" or source.lower() == "fixture" else "real"
        return sample_origin, source or class_name
    if class_name in SAMPLE_DIRS:
        return "real", class_name
    return "unknown", ""


def build_rows(data_root: Path, samples_root: Path,
               sources_path: Path) -> tuple[list[dict], list[dict]]:
    gold_path = data_root / "Gold" / "gold.csv"
    with gold_path.open(encoding="utf-8-sig", newline="") as handle:
        gold_rows = list(csv.DictReader(handle))
    sources = load_sources(sources_path)
    db_labels = load_db_labels(data_root)
    index, duplicates = build_sample_index(
        samples_root, {str(row.get("sha256") or "") for row in gold_rows})

    rows = []
    for gold in gold_rows:
        sha256 = str(gold.get("sha256") or "")
        fields = final_fields(data_root, sha256)
        die = evidence_fields(data_root, sha256, "detect_it_easy")
        die_raw = die.get("raw") if isinstance(die, dict) else {}
        obf_lvl = str(fields.get("obf_lvl") or "unknown")
        die_level = str((die_raw or {}).get("obf_lvl") or "")
        if die_level and die_level != "unknown":
            obf_lvl = die_level
        match = index.get(sha256)
        sample = find_sample(index, sha256)
        class_name = match[0] if match else ""
        origin, source = provenance(class_name, sources.get(sha256))
        config = fields.get("config")
        row = {column: str(gold.get(column) or "") for column in GOLD_COLUMNS}
        row["gold_snapshot_status"] = row["current_status"]
        row["gold_snapshot_family"] = row["current_family"]
        db_status, db_sug_fam = db_labels.get(sha256, ("", ""))
        row["current_status"] = db_status
        row["current_family"] = derive_current_family(db_status, db_sug_fam)
        for column in ("gold_status", "gold_family", "confidence", "analyst",
                       "date", "notes", "evidence"):
            row[column] = ""
        row["file_path"] = display_path(sample) if sample else ""
        row["sample_class"] = class_name
        row["sample_origin"] = origin
        row["sample_source"] = source
        row["file_size"] = str(sample.stat().st_size) if sample else ""
        row["is_dotnet"] = str(fields.get("is_dotnet", ""))
        row["config_present"] = str(bool(config)).lower() if fields else ""
        row["obf_lvl"] = obf_lvl
        for voter in VOTERS:
            row[voter] = evidence_cell(evidence_fields(data_root, sha256, voter))
        row["_fresh_status"] = str(fields.get("lbl_sts") or "")
        row["_fresh_family"] = str(fields.get("sug_fam") or "")
        row["label_reason"] = label_reason(data_root, sha256)
        row["notes_for_analyst"] = ""
        rows.append(row)
    return rows, duplicates


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    columns = list(GOLD_COLUMNS) + list(EXTRA_COLUMNS)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in columns})
    temporary.replace(path)


def write_md(path: Path, rows: list[dict], duplicates: list[dict]) -> None:
    sizes = [int(row["file_size"]) for row in rows if row["file_size"]]
    statuses = Counter(row["current_status"] for row in rows)
    clusters = len({row["cluster_id"] for row in rows})
    dotnet = sum(1 for row in rows if row["is_dotnet"] == "True")
    missing = sum(1 for row in rows if not row["file_path"])
    lines = [
        "# Gold review sheet", "",
        f"- candidates: **{len(rows)}**; clusters: **{clusters}**",
        f"- current statuses: " + ", ".join(
            f"`{key}` {value}" for key, value in sorted(statuses.items())),
        f"- .NET: {dotnet}/{len(rows)}; config present: "
        f"{sum(1 for row in rows if row['config_present'] == 'true')}/{len(rows)}",
        f"- sample files missing: {missing}",
        f"- duplicate sha256 paths: {len(duplicates)}",
    ]
    if sizes:
        lines.append(f"- size min/median/max: {min(sizes)} / "
                     f"{int(statistics.median(sizes))} / {max(sizes)} bytes")
    for duplicate in duplicates:
        lines.append(f"  - `{duplicate['sha256'][:12]}...`: "
                     + ", ".join(f"`{item}`" for item in duplicate["paths"]))
    lines += ["", "| # | sha256 | cluster | current | class | origin | file | size | obf |",
              "|---:|---|---|---|---|---|---|---:|---|"]
    for index, row in enumerate(rows, 1):
        lines.append(
            f"| {index} | `{row['sha256'][:12]}...` | "
            f"`{row['cluster_id'][:12]}` | {row['current_status']} | "
            f"{row['sample_class'] or '-'} | {row['sample_origin']} | "
            f"`{row['file_path'] or 'MISSING'}` | {row['file_size'] or '-'} | "
            f"{row['obf_lvl']} |")
    lines += ["", "## Per-sample notes", ""]
    for index, row in enumerate(rows, 1):
        lines += [
            f"### {index}. `{row['sha256']}`", "",
            f"- cluster: `{row['cluster_id']}`",
            f"- current label (DataSet.db): `{row['current_status']}`"
            f" / `{row['current_family'] or '-'}`",
            f"- gold.csv snapshot (historical): `{row['gold_snapshot_status']}`"
            f" / `{row['gold_snapshot_family'] or '-'}`",
            f"- fresh aggregated label: `{row['_fresh_status'] or 'missing'}`"
            f" / `{row['_fresh_family'] or '-'}`",
            f"- file: `{row['file_path'] or 'missing'}`"
            f" ({row['file_size'] or '?'} bytes); class: "
            f"`{row['sample_class'] or '-'}`; origin: "
            f"`{row['sample_origin']}`; source: `{row['sample_source'] or '-'}`",
            f"- .NET: `{row['is_dotnet']}`; config present: "
            f"`{row['config_present']}`; obf_lvl: `{row['obf_lvl']}`",
            "- voters: " + "; ".join(f"{voter}={row[voter]}" for voter in VOTERS),
            "- what to check: CLR header and entry point; TypeRef/MemberRef; "
            "config strings; loader/reflection; server/builder markers; "
            "family namespaces",
            f"- gold_status: `{row['gold_status']}`; "
            f"gold_family: `{row['gold_family']}`", "",
        ]
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text("\n".join(lines) + "\n", encoding="utf-8")
    temporary.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description="Gold review sheet")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--sources-csv", type=Path, default=DEFAULT_SOURCES)
    parser.add_argument("--out-dir", type=Path, default=None)
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    samples_root = args.samples_root.resolve()
    sources_path = args.sources_csv.resolve()
    out_dir = args.out_dir or (data_root / "Gold" / "review")
    rows, duplicates = build_rows(data_root, samples_root, sources_path)
    write_csv(out_dir / "gold_review_sheet.csv", rows)
    write_md(out_dir / "gold_review_sheet.md", rows, duplicates)
    filled = sum(1 for row in rows if row["gold_status"])
    pending = sum(1 for row in rows for voter in VOTERS if row[voter] == "pending")
    print(f"gold review: {out_dir} rows={len(rows)} filled={filled} "
          f"pending_voter_cells={pending} "
          f"missing_files={sum(1 for row in rows if not row['file_path'])} "
          f"duplicates={len(duplicates)}")
    for duplicate in duplicates:
        print(f"DUPLICATE: {duplicate['sha256']} -> {duplicate['paths']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

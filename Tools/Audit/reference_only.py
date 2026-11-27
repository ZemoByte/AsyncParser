#!/usr/bin/env python3
"""Mark server/builder/stub/panel samples as reference_only.

File names are labeling metadata only; they are never model features. Flagged
rows keep their previous status in `previous_status` and are excluded from the
class DBs and from every split by the importer.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_DATA = ROOT / "Data"
DEFAULT_LEDGER = ROOT / "Tools" / "MBDownloader" / "samples.db"
PATTERN = re.compile(r"(server|builder|stub|panel)", re.IGNORECASE)
FLAGGABLE = {"verified", "verified_other"}


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True),
                         encoding="utf-8")
    os.replace(temporary, path)


def ledger_names(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {str(sha): str(name or "")
                for sha, name in conn.execute(
                    "SELECT sha256_hash, api_file_name FROM downloads")}
    finally:
        conn.close()


def name_matches(names: dict[str, str]) -> dict[str, str]:
    matches = {}
    for sha256, name in names.items():
        found = PATTERN.search(name)
        if found:
            matches[sha256] = f"file_name:{found.group(1).lower()}"
    return matches


def manual_flags(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    flags = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sha256, _, reason = line.partition(" ")
        flags[sha256.strip().lower()] = reason.strip() or "manual_review"
    return flags


def apply_flags(data_root: Path, flags: dict[str, str], names: dict[str, str],
                dry_run: bool) -> dict:
    labels_dir = data_root / "Labels"
    changed = []
    skipped = Counter()
    for sha256, reason in sorted(flags.items()):
        path = labels_dir / f"{sha256}.json"
        if not path.is_file():
            skipped["missing_label"] += 1
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        fields = payload.get("fields", {})
        status = str(fields.get("lbl_sts") or "")
        if status == "reference_only":
            skipped["already_flagged"] += 1
            continue
        if status not in FLAGGABLE:
            skipped[f"status:{status or 'empty'}"] += 1
            continue
        changed.append({"sha256": sha256, "previous_status": status,
                        "reason": reason, "file_name": names.get(sha256, "")})
        if dry_run:
            continue
        fields["previous_status"] = status
        fields["lbl_sts"] = "reference_only"
        fields["scope_reason"] = reason
        write_json(path, payload)
    return {"changed": changed, "skipped": dict(skipped),
            "dry_run": dry_run}


def main() -> int:
    parser = argparse.ArgumentParser(description="Flag server/builder samples")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--manual", type=Path, default=None,
                        help="optional sha256 [reason] per line")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    names = ledger_names(args.ledger)
    flags = name_matches(names)
    flags.update(manual_flags(args.manual))
    result = apply_flags(args.data_root.resolve(), flags, names,
                         args.dry_run)
    report = {
        "schema_version": 1,
        "producer": "reference_only_audit",
        "pattern": PATTERN.pattern,
        "ledger_rows": len(names),
        "name_matches": len(name_matches(names)),
        "manual_flags": len(manual_flags(args.manual)),
        **result,
    }
    if not args.dry_run:
        write_json(args.data_root.resolve() / "Audit" / "reference_only.json",
                   report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

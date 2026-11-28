#!/usr/bin/env python3
"""Validate and merge a filled gold-review sheet into Data/Gold/gold.csv.

Dry-run by default. `--write` replaces gold.csv atomically. Only the seven
human columns are copied, and only for rows with a non-empty filled
`gold_status`. Existing filled verdicts are never overwritten without
`--force`.
"""

from __future__ import annotations

import argparse
import csv
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import (  # noqa: E402
    FAMILY_VERDICTS,
    GOLD_COLUMNS,
    LABEL_STATUSES,
)

HUMAN_FIELDS = ("gold_status", "gold_family", "confidence", "analyst",
                "date", "notes", "evidence")
EXPECTED_ROWS = 30


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as handle:
        return list(csv.DictReader(handle))


def merge_gold(gold_path: Path, review_path: Path, write: bool = False,
               force: bool = False) -> dict:
    gold_rows = read_csv(gold_path)
    review_rows = read_csv(review_path)
    errors: list[str] = []
    summary = {"gold_rows": len(gold_rows), "review_rows": len(review_rows),
               "filled": 0, "blank": 0, "skipped_existing": 0,
               "unknown_status": 0, "unknown_family": 0, "written": False}

    if len(review_rows) != EXPECTED_ROWS:
        errors.append(f"expected {EXPECTED_ROWS} review rows, "
                      f"found {len(review_rows)}")
    if len(gold_rows) != EXPECTED_ROWS:
        errors.append(f"expected {EXPECTED_ROWS} gold rows, "
                      f"found {len(gold_rows)}")

    gold_by_sha = {str(row.get("sha256") or ""): row for row in gold_rows}
    if "" in gold_by_sha:
        errors.append("gold.csv has a row without sha256")
    seen: set[str] = set()
    for row in review_rows:
        sha256 = str(row.get("sha256") or "").strip()
        if not sha256:
            errors.append("review row without sha256")
            continue
        if sha256 in seen:
            errors.append(f"duplicate review sha256 {sha256}")
            continue
        seen.add(sha256)
        if sha256 not in gold_by_sha:
            errors.append(f"review sha256 not in gold.csv: {sha256}")

    for row in review_rows:
        sha256 = str(row.get("sha256") or "").strip()
        status = str(row.get("gold_status") or "").strip()
        family = str(row.get("gold_family") or "").strip()
        if not status:
            summary["blank"] += 1
            continue
        if status not in LABEL_STATUSES:
            errors.append(f"unknown gold_status {status!r} for {sha256}")
            summary["unknown_status"] += 1
            continue
        if family and family not in FAMILY_VERDICTS:
            errors.append(f"unknown gold_family {family!r} for {sha256}")
            summary["unknown_family"] += 1
            continue
        if status == "verified_other" and not family:
            errors.append(f"verified_other without gold_family for {sha256}")
            summary["unknown_family"] += 1
            continue
        summary["filled"] += 1

    if errors:
        return {**summary, "errors": errors}

    updates = {}
    for row in review_rows:
        sha256 = str(row.get("sha256") or "").strip()
        status = str(row.get("gold_status") or "").strip()
        if not status:
            continue
        gold_row = gold_by_sha[sha256]
        if str(gold_row.get("gold_status") or "").strip() and not force:
            summary["skipped_existing"] += 1
            continue
        updates[sha256] = {field: str(row.get(field) or "").strip()
                           for field in HUMAN_FIELDS}

    if write and updates:
        path = gold_path
        temporary = path.with_suffix(path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(GOLD_COLUMNS),
                                    lineterminator="\n")
            writer.writeheader()
            for row in gold_rows:
                merged = {column: str(row.get(column) or "")
                          for column in GOLD_COLUMNS}
                update = updates.get(str(row.get("sha256") or ""))
                if update:
                    merged.update(update)
                writer.writerow(merged)
        os.replace(temporary, path)
        summary["written"] = True
    summary["updates"] = len(updates)
    return {**summary, "errors": []}


def main() -> int:
    parser = argparse.ArgumentParser(description="Merge filled gold verdicts")
    parser.add_argument("--gold", type=Path,
                        default=ROOT / "Data" / "Gold" / "gold.csv")
    parser.add_argument("--review", type=Path,
                        default=ROOT / "Data" / "Gold" / "review"
                        / "gold_review_sheet.csv")
    parser.add_argument("--dry-run", action="store_true",
                        help="validate only (default)")
    parser.add_argument("--write", action="store_true",
                        help="replace gold.csv (default: dry run)")
    parser.add_argument("--force", action="store_true",
                        help="overwrite already filled gold_status values")
    args = parser.parse_args()

    if args.write and args.dry_run:
        parser.error("choose either --dry-run or --write")
    result = merge_gold(args.gold.resolve(), args.review.resolve(),
                        write=args.write and not args.dry_run, force=args.force)
    print(f"gold merge: gold_rows={result['gold_rows']} "
          f"review_rows={result['review_rows']} filled={result['filled']} "
          f"blank={result['blank']} "
          f"skipped_existing={result['skipped_existing']} "
          f"unknown_status={result['unknown_status']} "
          f"unknown_family={result['unknown_family']} "
          f"updates={result.get('updates', 0)} "
          f"write={'yes' if result['written'] else 'no'}")
    for error in result["errors"][:20]:
        print(f"ERROR: {error}")
    if result["errors"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

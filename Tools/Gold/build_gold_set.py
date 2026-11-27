#!/usr/bin/env python3
"""Build a stratified gold-set template from clusters.

One sample per cluster, stratified by current label status. Human fields are
left blank; fill them in dnSpyEx and rerun the aggregator/importer. Gold rows
stay in DataSet.db only and are excluded from class DBs and training splits.
"""

from __future__ import annotations

import argparse
import csv
import sqlite3
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import GOLD_COLUMNS  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
TOTAL = 30
QUOTAS = (
    ("verified", 8),
    ("review", 7),
    ("unverified", 5),
    ("benign", 5),
    ("rejected_non_dotnet", 5),
)


def read_rows(dataset_path: Path) -> list[dict]:
    if not dataset_path.is_file():
        raise RuntimeError(f"dataset DB not found: {dataset_path}")
    conn = sqlite3.connect(f"file:{dataset_path}?mode=ro", uri=True)
    try:
        return [
            {"sha256": row[0], "lbl_sts": row[1] or "", "sug_fam": row[2] or "",
             "cluster_id": row[3] or ""}
            for row in conn.execute(
                "SELECT sha256, lbl_sts, sug_fam, cluster_id FROM dataset"
            )
        ]
    finally:
        conn.close()


def build_selection(rows: list[dict]) -> tuple[list[dict], dict[str, int]]:
    clusters: dict[str, list[dict]] = {}
    for row in rows:
        clusters.setdefault(row["cluster_id"], []).append(row)
    for members in clusters.values():
        members.sort(key=lambda item: item["sha256"])

    selected: list[dict] = []
    used: set[str] = set()
    quota_counts: dict[str, int] = {}

    def pick(status: str) -> dict | None:
        for cluster_id in sorted(clusters):
            if cluster_id in used:
                continue
            members = clusters[cluster_id]
            matching = [item for item in members if item["lbl_sts"] == status]
            if matching:
                return matching[0]
        return None

    for status, quota in QUOTAS:
        for _ in range(quota):
            item = pick(status)
            if item is None:
                break
            selected.append(item)
            used.add(item["cluster_id"])
            quota_counts[status] = quota_counts.get(status, 0) + 1

    # Fill any shortfall from remaining clusters, preferring harder rows.
    preference = ["review", "verified", "unverified", "benign", "rejected_non_dotnet"]
    for cluster_id in sorted(clusters):
        if len(selected) >= TOTAL:
            break
        if cluster_id in used:
            continue
        members = clusters[cluster_id]
        members = sorted(
            members,
            key=lambda item: (preference.index(item["lbl_sts"])
                              if item["lbl_sts"] in preference else len(preference),
                              item["sha256"]),
        )
        selected.append(members[0])
        used.add(cluster_id)
    return selected, quota_counts


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the gold-set template")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--force", action="store_true",
                        help="overwrite an existing gold.csv")
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    out_path = (args.out or (data_root / "Gold" / "gold.csv")).resolve()
    if out_path.is_file() and not args.force:
        raise RuntimeError(f"gold CSV already exists: {out_path}; use --force to overwrite")
    rows = read_rows(data_root / "DataSet.db")
    selected, quota_counts = build_selection(rows)
    for status, quota in QUOTAS:
        got = quota_counts.get(status, 0)
        if got < quota:
            print(f"WARNING: quota {status} {quota} not met (selected {got})")
    substituted = selected[sum(quota_counts.values()):]
    if substituted:
        print(f"WARNING: substituted {len(substituted)} rows for unmet quotas: "
              f"{dict(sorted(Counter(item['lbl_sts'] for item in substituted).items()))}")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=GOLD_COLUMNS)
        writer.writeheader()
        for item in selected:
            writer.writerow({
                "sha256": item["sha256"],
                "cluster_id": item["cluster_id"],
                "current_status": item["lbl_sts"],
                "current_family": item["sug_fam"],
                "gold_status": "",
                "gold_family": "",
                "confidence": "",
                "analyst": "",
                "date": "",
                "notes": "",
                "evidence": "",
            })
    marker = out_path.parent / ".gold.done"
    marker.write_text(f"{len(selected)}\n", encoding="utf-8")
    counts: dict[str, int] = {}
    for item in selected:
        counts[item["lbl_sts"]] = counts.get(item["lbl_sts"], 0) + 1
    print(f"gold template: {len(selected)} samples into {out_path}")
    print(f"by current status: {dict(sorted(counts.items()))}")
    if len(selected) < TOTAL:
        print(f"WARNING: only {len(selected)} distinct clusters available")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

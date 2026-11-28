#!/usr/bin/env python3
"""Cluster and temporal splits for the primary Stage 1 dataset.

Primary rows are verified/verified_other positives and benign EXEs whose
origin is not fixture. No sample is executed.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import load_final_label  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
DEFAULT_OUT = ROOT / "Data" / "Splits"
SEED = 42


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def benign_dates(path: Path) -> dict[str, str]:
    result = {}
    if not path.is_file():
        return result
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        for row in csv.DictReader(handle):
            sha = str(row.get("sha256") or "")
            if sha:
                result[sha] = str(row.get("collected_at") or "")
    return result


def ledger_dates(data_root: Path) -> dict[str, str]:
    path = data_root.parent / "Tools" / "MBDownloader" / "samples.db"
    if not path.is_file():
        return {}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {str(sha): str(first_seen or "")
                for sha, first_seen in conn.execute(
                    "SELECT sha256_hash, first_seen FROM downloads"
                )}
    finally:
        conn.close()


def read_rows(data_root: Path) -> tuple[list[dict], int]:
    db = data_root / "DataSet.db"
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(dataset)")}
        first_expr = "first_seen" if "first_seen" in columns else "NULL"
        raw = list(conn.execute(
            f"SELECT sha256, lbl_sts, cluster_id, {first_expr}, is_gold FROM dataset"
        ))
    finally:
        conn.close()
    dates = benign_dates(data_root / "BenignSources.csv")
    ledger = ledger_dates(data_root)
    rows = []
    missing_date = 0
    missing_labels = 0
    for sha, status, cluster_id, first_seen, is_gold in raw:
        if is_gold:
            continue
        if status in {"verified", "verified_other"}:
            sample_class = "positive"
        elif status == "benign":
            try:
                fields = load_final_label(sha, data_root)
            except RuntimeError:
                if not list((data_root.parent / "Samples" / "Benign").glob(f"{sha}.*")):
                    missing_labels += 1
                    continue
                raise
            if fields.get("source") == "clrheader2023" \
                    or fields.get("origin") in {"fixture", "clrheader2023"} \
                    or fields.get("kind") != "exe":
                continue
            sample_class = "negative"
        else:
            continue
        seen = str(first_seen or ledger.get(sha) or dates.get(sha) or "")
        if not seen:
            seen = "1970-01-01 00:00:00"
            missing_date += 1
        rows.append({"sha256": sha, "label": sample_class,
                     "cluster_id": cluster_id, "first_seen": seen})
    if missing_labels:
        print(f"WARNING: skipped {missing_labels} rows with missing labels "
              f"and no sample file (retired artifacts)")
    return rows, missing_date


def pack_clusters(cluster_sizes: dict[str, int]) -> dict[str, str]:
    """Greedy whole-cluster packing to 70/15/15 of rows, deterministic."""
    total = sum(cluster_sizes.values())
    fractions = {"train": 0.70, "val": 0.15, "test": 0.15}
    targets = {split: total * share for split, share in fractions.items()}
    assigned = {"train": 0, "val": 0, "test": 0}
    assignment: dict[str, str] = {}
    for cluster_id, size in sorted(cluster_sizes.items(),
                                   key=lambda item: (-item[1], item[0])):
        split = min(("train", "val", "test"),
                    key=lambda name: (assigned[name] - targets[name], name))
        assignment[cluster_id] = split
        assigned[split] += size
    return assignment


def cluster_split(rows: list[dict]) -> dict[str, str]:
    result = {}
    for sample_class in ("positive", "negative"):
        class_rows = [row for row in rows if row["label"] == sample_class]
        sizes = Counter(row["cluster_id"] for row in class_rows)
        by_cluster = pack_clusters(dict(sizes))
        for row in class_rows:
            result[row["sha256"]] = by_cluster[row["cluster_id"]]
    return result


def temporal_split(rows: list[dict]) -> dict[str, str]:
    result = {}
    for sample_class in ("positive", "negative"):
        class_rows = sorted(
            [row for row in rows if row["label"] == sample_class],
            key=lambda row: (row["first_seen"], row["sha256"]),
        )
        n = len(class_rows)
        n_train = int(n * 0.70)
        n_val = int(n * 0.15)
        for index, row in enumerate(class_rows):
            if index < n_train:
                split = "train"
            elif index < n_train + n_val:
                split = "val"
            else:
                split = "test"
            result[row["sha256"]] = split
    return result


def split_stats(rows: list[dict], assignment: dict[str, str],
                class_cluster_totals: dict[str, int]) -> dict:
    stats = {}
    for split in ("train", "val", "test"):
        selected = [row for row in rows if assignment.get(row["sha256"]) == split]
        positives = sum(1 for row in selected if row["label"] == "positive")
        negatives = sum(1 for row in selected if row["label"] == "negative")
        positive_clusters = Counter(row["cluster_id"] for row in selected
                                    if row["label"] == "positive")
        negative_clusters = Counter(row["cluster_id"] for row in selected
                                    if row["label"] == "negative")
        largest_positive = max(positive_clusters.values(), default=0)
        largest_positive_share = (largest_positive / positives) if positives else 0.0
        degenerate = (positive_clusters.total() < 2
                      or largest_positive_share > 0.40)
        if split == "train" and (len(positive_clusters) < 5
                                 or largest_positive_share > 0.60):
            degenerate = True
        stats[split] = {
            "rows": len(selected),
            "positives": positives,
            "negatives": negatives,
            "positive_clusters": len(positive_clusters),
            "negative_clusters": len(negative_clusters),
            "clusters": len({row["cluster_id"] for row in selected}),
            "per_class": {"positive": positives, "negative": negatives},
            "clusters_per_class": {"positive": len(positive_clusters),
                                   "negative": len(negative_clusters)},
            "largest_positive_share": largest_positive_share,
            "degenerate": degenerate,
        }
    for sample_class, total in class_cluster_totals.items():
        if total < 10:
            for item in stats.values():
                item["degenerate"] = True
    return stats


def cleanup_stale_splits(out_root: Path, keep: set[str]) -> list[str]:
    """Delete split JSONs for rows that are no longer primary."""
    removed = []
    if not out_root.is_dir():
        return removed
    for path in sorted(out_root.glob("*.json")):
        if path.stem not in keep:
            path.unlink()
            removed.append(path.stem)
    return removed


def cluster_spans(rows: list[dict], assignment: dict[str, str]) -> int:
    by_cluster: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        by_cluster[row["cluster_id"]].add(assignment.get(row["sha256"], ""))
    return sum(1 for splits in by_cluster.values() if len(splits) > 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create cluster and temporal splits")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    out_root = args.out.resolve()
    rows, missing_date = read_rows(data_root)
    if not rows:
        raise RuntimeError("no primary rows found")

    cluster_assign = cluster_split(rows)
    temporal_assign = temporal_split(rows)
    spans = cluster_spans(rows, cluster_assign)
    if spans:
        raise RuntimeError(f"{spans} clusters span cluster splits; refusing")
    temporal_spans = cluster_spans(rows, temporal_assign)

    class_cluster_totals = {
        sample_class: len({row["cluster_id"] for row in rows
                           if row["label"] == sample_class})
        for sample_class in ("positive", "negative")
    }
    cluster_stats = split_stats(rows, cluster_assign, class_cluster_totals)
    temporal_stats = split_stats(rows, temporal_assign, class_cluster_totals)
    degenerate = any(item["degenerate"] for item in cluster_stats.values()) \
        or any(item["degenerate"] for item in temporal_stats.values())

    for row in rows:
        sha256 = row["sha256"]
        payload = {
            "schema_version": 1,
            "sha256": sha256,
            "kind": "split",
            "producer": "split",
            "fields": {
                "cluster_split": cluster_assign[sha256],
                "temporal_split": temporal_assign[sha256],
                "degenerate": degenerate,
            },
        }
        write_json(out_root / f"{sha256}.json", payload)
    removed = cleanup_stale_splits(out_root, {row["sha256"] for row in rows})
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / ".done").write_text(
        json.dumps({"producer": "split", "count": len(rows),
                    "seed": args.seed, "degenerate": degenerate}, sort_keys=True),
        encoding="utf-8",
    )

    print(f"split {len(rows)} primary rows; stale_removed={len(removed)}; "
          f"cluster_spans={spans} temporal_cluster_spans={temporal_spans} "
          f"missing_date={missing_date}")
    for name, stats in (("cluster", cluster_stats), ("temporal", temporal_stats)):
        print(f"## {name} split")
        for split in ("train", "val", "test"):
            item = stats[split]
            print(f"{split}: rows={item['rows']} positives={item['positives']} "
                  f"negatives={item['negatives']} "
                  f"positive_clusters={item['positive_clusters']} "
                  f"negative_clusters={item['negative_clusters']} "
                  f"largest_positive_share={item['largest_positive_share']:.3f} "
                  f"degenerate={item['degenerate']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

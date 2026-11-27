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
import random
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

from sklearn.model_selection import GroupShuffleSplit

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
    for sha, status, cluster_id, first_seen, is_gold in raw:
        if is_gold:
            continue
        if status in {"verified", "verified_other"}:
            sample_class = "positive"
        elif status == "benign":
            fields = load_final_label(sha, data_root)
            if fields.get("origin") == "fixture" or fields.get("kind") != "exe":
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
    return rows, missing_date


def _manual_cluster_split(rows: list[dict], seed: int) -> dict[str, str]:
    clusters = sorted({row["cluster_id"] for row in rows})
    rng = random.Random(seed)
    rng.shuffle(clusters)
    n = len(clusters)
    n_train = max(1, int(round(n * 0.70))) if n else 0
    n_val = max(1, int(round(n * 0.15))) if n >= 3 else 0
    if n >= 3 and n - n_train - n_val < 1:
        n_train = max(1, n - n_val - 1)
    assignment = {}
    for index, cluster_id in enumerate(clusters):
        if index < n_train:
            split = "train"
        elif index < n_train + n_val:
            split = "val"
        else:
            split = "test"
        assignment[cluster_id] = split
    return assignment


def split_class_clusters(rows: list[dict], seed: int) -> dict[str, str]:
    groups = [row["cluster_id"] for row in rows]
    if len(set(groups)) >= 3:
        try:
            gss = GroupShuffleSplit(n_splits=1, train_size=0.70,
                                    test_size=0.30, random_state=seed)
            train_idx, temp_idx = next(gss.split(rows, groups=groups))
            temp_rows = [rows[index] for index in temp_idx]
            temp_groups = [row["cluster_id"] for row in temp_rows]
            if len(set(temp_groups)) >= 2:
                gss2 = GroupShuffleSplit(n_splits=1, train_size=0.50,
                                         test_size=0.50, random_state=seed)
                val_idx, test_idx = next(gss2.split(temp_rows, groups=temp_groups))
                assignment = {}
                for index in train_idx:
                    assignment[rows[index]["sha256"]] = "train"
                for index in val_idx:
                    assignment[temp_rows[index]["sha256"]] = "val"
                for index in test_idx:
                    assignment[temp_rows[index]["sha256"]] = "test"
                by_cluster: dict[str, str] = {}
                for row in rows:
                    by_cluster[row["cluster_id"]] = assignment[row["sha256"]]
                return by_cluster
        except ValueError:
            pass
    return _manual_cluster_split(rows, seed)


def cluster_split(rows: list[dict], seed: int) -> dict[str, str]:
    result = {}
    for sample_class in ("positive", "negative"):
        class_rows = [row for row in rows if row["label"] == sample_class]
        by_cluster = split_class_clusters(class_rows, seed)
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


def split_stats(rows: list[dict], assignment: dict[str, str]) -> dict:
    stats = {}
    for split in ("train", "val", "test"):
        selected = [row for row in rows if assignment.get(row["sha256"]) == split]
        positives = sum(1 for row in selected if row["label"] == "positive")
        clusters = len({row["cluster_id"] for row in selected})
        per_class = Counter(row["label"] for row in selected)
        class_clusters = {
            sample_class: len({
                row["cluster_id"] for row in selected
                if row["label"] == sample_class
            })
            for sample_class in ("positive", "negative")
        }
        degenerate = (
            positives == 0
            or any(count < 2 for count in class_clusters.values())
        )
        stats[split] = {
            "rows": len(selected),
            "positives": positives,
            "clusters": clusters,
            "per_class": dict(per_class),
            "clusters_per_class": class_clusters,
            "degenerate": degenerate,
        }
    return stats


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

    cluster_assign = cluster_split(rows, args.seed)
    temporal_assign = temporal_split(rows)
    spans = cluster_spans(rows, cluster_assign)
    if spans:
        raise RuntimeError(f"{spans} clusters span cluster splits; refusing")
    temporal_spans = cluster_spans(rows, temporal_assign)

    cluster_stats = split_stats(rows, cluster_assign)
    temporal_stats = split_stats(rows, temporal_assign)
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
    out_root.mkdir(parents=True, exist_ok=True)
    (out_root / ".done").write_text(
        json.dumps({"producer": "split", "count": len(rows),
                    "seed": args.seed, "degenerate": degenerate}, sort_keys=True),
        encoding="utf-8",
    )

    print(f"split {len(rows)} primary rows; cluster_spans={spans} "
          f"temporal_cluster_spans={temporal_spans} missing_date={missing_date}")
    for name, stats in (("cluster", cluster_stats), ("temporal", temporal_stats)):
        print(f"## {name} split")
        for split in ("train", "val", "test"):
            item = stats[split]
            print(f"{split}: rows={item['rows']} positives={item['positives']} "
                  f"clusters={item['clusters']} per_class={item['per_class']} "
                  f"clusters_per_class={item['clusters_per_class']} "
                  f"degenerate={item['degenerate']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

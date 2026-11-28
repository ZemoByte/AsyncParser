#!/usr/bin/env python3
"""Read-only cross-family TLSH audit for Stage 1 test/train clusters.

For every positive test cluster, find the nearest positive train cluster by
TLSH. If distance <=100 and the families differ, report the pair with sizes,
families, voter groups, config presence and sample paths. Never merges or
relabels anything.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tlsh  # noqa: E402

from Tools._label_common import load_final_label  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
DEFAULT_SAMPLES = ROOT / "Samples"
THRESHOLD = 100
POSITIVE = {"verified", "verified_other"}


def load_rows(data_root: Path) -> list[dict]:
    conn = sqlite3.connect(f"file:{data_root / 'DataSet.db'}?mode=ro", uri=True)
    try:
        raw = list(conn.execute(
            "SELECT sha256, lbl_sts, sug_fam, cluster_id, split, is_gold "
            "FROM dataset"))
    finally:
        conn.close()
    rows = []
    for sha, status, family, cluster, split, is_gold in raw:
        if status not in POSITIVE or is_gold or not cluster or split not in {"train", "test"}:
            continue
        rows.append({"sha256": sha, "status": status,
                     "family": "AsyncRAT" if status == "verified"
                     else (family or "unknown"),
                     "cluster_id": cluster, "split": split})
    return rows


def load_tlsh(data_root: Path) -> dict[str, str]:
    hashes = {}
    for path in (data_root / "Clusters").glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        value = payload.get("fields", {}).get("tlsh")
        if isinstance(value, str) and value:
            hashes[payload["sha256"]] = value
    return hashes


def load_groups(data_root: Path) -> dict[str, dict]:
    groups = {}
    for path in (data_root / "Aggregated").glob("*.json"):
        try:
            fields = json.loads(path.read_text(encoding="utf-8")).get("fields", {})
        except (OSError, json.JSONDecodeError):
            continue
        reason = fields.get("lbl_reason")
        if isinstance(reason, str):
            try:
                reason = json.loads(reason)
            except json.JSONDecodeError:
                reason = {}
        groups[path.stem] = (reason or {}).get("groups", {})
    return groups


def sample_path(samples_root: Path, sha256: str) -> str:
    for path in samples_root.rglob(f"{sha256}.*"):
        if path.is_file():
            try:
                return str(path.relative_to(ROOT))
            except ValueError:
                return str(path)
    return ""


def build_clusters(rows: list[dict], split: str) -> dict[str, dict]:
    result = {}
    for row in rows:
        if row["split"] != split:
            continue
        item = result.setdefault(row["cluster_id"], {
            "cluster_id": row["cluster_id"], "family": row["family"],
            "members": []})
        item["members"].append(row["sha256"])
    return result


def find_cross_family_pairs(test_clusters: dict, train_clusters: dict,
                            hashes: dict[str, str],
                            threshold: int = THRESHOLD) -> list[dict]:
    pairs = []
    for test_id, test in sorted(test_clusters.items()):
        best = None
        for test_sha in test["members"]:
            target = hashes.get(test_sha)
            if not target:
                continue
            for train_id, train in train_clusters.items():
                if train["family"] == test["family"]:
                    continue
                for train_sha in train["members"]:
                    candidate = hashes.get(train_sha)
                    if not candidate:
                        continue
                    try:
                        distance = tlsh.diff(target, candidate)
                    except Exception:
                        continue
                    if best is None or distance < best[0]:
                        best = (distance, train_id, train_sha)
        if best is not None and best[0] <= threshold:
            pairs.append({"test_cluster": test_id,
                          "train_cluster": best[1],
                          "distance": best[0],
                          "test_family": test["family"],
                          "train_family": train_clusters[best[1]]["family"],
                          "test_size": len(test["members"]),
                          "train_size": len(train_clusters[best[1]]["members"])})
    return pairs


def describe(data_root: Path, samples_root: Path, cluster_id: str,
             row_by_sha: dict[str, dict], hashes: dict[str, str],
             groups: dict[str, dict]) -> dict:
    members = [sha for sha, row in row_by_sha.items()
               if row["cluster_id"] == cluster_id]
    group_counter = Counter()
    config_count = 0
    for sha in members:
        for family, group_list in groups.get(sha, {}).items():
            for group in group_list:
                group_counter[f"{family}:{group}"] += 1
        try:
            fields = load_final_label(sha, data_root)
        except RuntimeError:
            fields = {}
        if isinstance(fields.get("config"), dict) and fields["config"]:
            config_count += 1
    row = row_by_sha[members[0]]
    return {"cluster_id": cluster_id, "family": row["family"],
            "split": row["split"], "rows": len(members),
            "voter_groups": dict(sorted(group_counter.items())),
            "config_present": config_count,
            "sample_paths": [sample_path(samples_root, sha)
                             for sha in sorted(members)]}


def main() -> int:
    parser = argparse.ArgumentParser(description="Cross-family TLSH audit")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out-dir", type=Path, default=None)
    parser.add_argument("--threshold", type=int, default=THRESHOLD)
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    samples_root = args.samples_root.resolve()
    out_dir = args.out_dir or (data_root / "Audit")
    rows = load_rows(data_root)
    hashes = load_tlsh(data_root)
    groups = load_groups(data_root)
    test_clusters = build_clusters(rows, "test")
    train_clusters = build_clusters(rows, "train")
    pairs = find_cross_family_pairs(test_clusters, train_clusters, hashes,
                                    args.threshold)
    row_by_sha = {row["sha256"]: row for row in rows}
    details = []
    for pair in pairs:
        details.append({
            "pair": pair,
            "test": describe(data_root, samples_root, pair["test_cluster"],
                             row_by_sha, hashes, groups),
            "train": describe(data_root, samples_root, pair["train_cluster"],
                              row_by_sha, hashes, groups),
        })
    report = {"schema_version": 1, "producer": "cross_family_audit",
              "threshold": args.threshold, "pairs": details}
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "cross_family.json").write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    lines = ["# Cross-family TLSH audit", "",
             f"Pairs at distance <= {args.threshold}: **{len(details)}**. "
             "No merge or relabel was applied.", ""]
    for item in details:
        pair = item["pair"]
        lines += [
            f"## test `{pair['test_cluster'][:12]}…` "
            f"({pair['test_family']}, {pair['test_size']} rows) ↔ "
            f"train `{pair['train_cluster'][:12]}…` "
            f"({pair['train_family']}, {pair['train_size']} rows)",
            f"- TLSH distance: **{pair['distance']}**",
            f"- test groups: {item['test']['voter_groups']}",
            f"- train groups: {item['train']['voter_groups']}",
            f"- config present: test {item['test']['config_present']}/"
            f"{item['test']['rows']}, train {item['train']['config_present']}/"
            f"{item['train']['rows']}",
            "- no automatic action; inspect manually.", ""]
    (out_dir / "cross_family.md").write_text("\n".join(lines) + "\n",
                                             encoding="utf-8")
    print(f"cross-family audit: {len(details)} pairs -> "
          f"{out_dir / 'cross_family.md'}")
    for item in details:
        pair = item["pair"]
        print(f"  {pair['test_cluster'][:12]} ({pair['test_family']}) ~ "
              f"{pair['train_cluster'][:12]} ({pair['train_family']}) "
              f"distance={pair['distance']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

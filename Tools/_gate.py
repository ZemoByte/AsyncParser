#!/usr/bin/env python3
"""Single dataset-gate implementation used by the report and baselines.

Stage 1: AsyncRAT (>=10 clusters, largest <=50%) and active benign
(EXE, not fixture, not external holdout; >=10 clusters, largest <=50%).
Stage 2: AsyncRAT plus every verified_other family; each needs >=2 clusters
and <=50% share, and at least two families must exist.
"""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import load_final_label  # noqa: E402

STAGE1_MIN_CLUSTERS = 10
STAGE2_MIN_CLUSTERS = 2
MAX_SHARE = 50.0
MIN_FAMILIES = 2
HOLDOUT_SOURCE = "clrheader2023"


def cluster_stats(cluster_ids: list[str]) -> dict:
    counts: dict[str, int] = {}
    for cluster_id in cluster_ids:
        counts[cluster_id] = counts.get(cluster_id, 0) + 1
    sizes = sorted(counts.values(), reverse=True)
    total = len(cluster_ids)
    largest = sizes[0] if sizes else 0
    return {
        "rows": total,
        "clusters": len(counts),
        "largest": largest,
        "share": (100.0 * largest / total) if total else 100.0,
    }


def benign_stratum(sha256: str, data_root: Path) -> str:
    try:
        fields = load_final_label(sha256, data_root)
    except (RuntimeError, OSError):
        return "aux"
    source = str(fields.get("source") or "")
    origin = str(fields.get("origin") or "")
    kind = str(fields.get("kind") or "")
    if source == HOLDOUT_SOURCE:
        return "holdout"
    if source == "fixture" or origin == "fixture":
        return "fixture"
    if kind != "exe":
        return "aux"
    return "active"


def evaluate_gate(data_root: Path) -> dict:
    db = data_root / "DataSet.db"
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        rows = list(conn.execute(
            "SELECT sha256, lbl_sts, sug_fam, target_class_db, cluster_id, is_gold "
            "FROM dataset"
        ))
    finally:
        conn.close()

    async_clusters = [row[4] for row in rows
                      if row[3] == "AsyncRAT.db" and row[4] and not row[5]]
    benign_clusters = [row[4] for row in rows
                       if row[1] == "benign" and row[4] and not row[5]
                       and benign_stratum(row[0], data_root) == "active"]
    async_stats = cluster_stats(async_clusters)
    benign_stats = cluster_stats(benign_clusters)
    async_stats["ok"] = (async_stats["clusters"] >= STAGE1_MIN_CLUSTERS
                         and async_stats["share"] <= MAX_SHARE)
    benign_stats["ok"] = (benign_stats["clusters"] >= STAGE1_MIN_CLUSTERS
                          and benign_stats["share"] <= MAX_SHARE)

    families: dict[str, list[str]] = {}
    async_rows = [row[4] for row in rows
                  if row[1] == "verified" and not row[5] and row[4]]
    if async_rows:
        families["AsyncRAT"] = async_rows
    for row in rows:
        if row[1] != "verified_other" or row[5] or not row[4]:
            continue
        family = str(row[2] or "").strip()
        if family:
            families.setdefault(family, []).append(row[4])
    family_stats = {}
    for family, cluster_ids in sorted(families.items()):
        stats = cluster_stats(cluster_ids)
        stats["ok"] = (stats["clusters"] >= STAGE2_MIN_CLUSTERS
                       and stats["share"] <= MAX_SHARE)
        family_stats[family] = stats
    stage2_ok = (len(family_stats) >= MIN_FAMILIES
                 and all(item["ok"] for item in family_stats.values()))

    reasons = []
    if not async_stats["ok"]:
        reasons.append(f"AsyncRAT: {async_stats['clusters']} clusters, "
                       f"largest {async_stats['share']:.1f}%")
    if not benign_stats["ok"]:
        reasons.append(f"active benign: {benign_stats['clusters']} clusters, "
                       f"largest {benign_stats['share']:.1f}%")
    if not stage2_ok:
        reasons.append("stage 2: " + ", ".join(
            f"{family} {item['clusters']}/{item['share']:.1f}%"
            for family, item in family_stats.items()) or "stage 2: no families")

    return {
        "thresholds": {
            "stage1_min_clusters": STAGE1_MIN_CLUSTERS,
            "stage2_min_clusters": STAGE2_MIN_CLUSTERS,
            "max_share": MAX_SHARE,
            "min_families": MIN_FAMILIES,
        },
        "stage1": {"asyncrat": async_stats, "benign": benign_stats,
                   "ok": async_stats["ok"] and benign_stats["ok"]},
        "stage2": {"families": family_stats, "ok": stage2_ok},
        "overall": async_stats["ok"] and benign_stats["ok"] and stage2_ok,
        "reasons": reasons,
    }

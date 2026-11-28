#!/usr/bin/env python3
"""Deterministic cluster partition for the proposed D2 Hassan 70/30 split.

Read-only helper. It does not touch DataSet.db, splits, features or labels.
"""

from __future__ import annotations

import random
from typing import Iterable

SEED = 42
TARGET_FRACTION = 0.70
TRAIN = "train"
HOLDOUT = "holdout"


def build_partition(rows: Iterable[dict], seed: int = SEED,
                    target_fraction: float = TARGET_FRACTION) -> dict:
    """Build the cluster -> train/holdout manifest from synthetic row dicts.

    Each row needs sha256, cluster_id, hassan (bool), fixture (bool).
    Non-Hassan rows force their whole cluster to train. Fixtures are
    non-Hassan by definition and are never placed in the holdout.
    """
    clusters: dict[str, dict] = {}
    for row in rows:
        cluster = str(row.get("cluster_id") or "")
        if not cluster:
            raise ValueError("row has no cluster_id")
        entry = clusters.setdefault(cluster, {
            "hassan_rows": 0, "total_rows": 0,
            "fixture_rows": 0, "forced_train": False,
        })
        entry["total_rows"] += 1
        if bool(row.get("hassan")):
            entry["hassan_rows"] += 1
        if bool(row.get("fixture")):
            entry["fixture_rows"] += 1
        if not bool(row.get("hassan")):
            entry["forced_train"] = True

    hassan_rows = sum(entry["hassan_rows"] for entry in clusters.values())
    target_rows = round(hassan_rows * target_fraction)
    assignment: dict[str, str] = {}
    train_rows = 0

    for cluster in sorted(clusters):
        if clusters[cluster]["forced_train"]:
            assignment[cluster] = TRAIN
            train_rows += clusters[cluster]["hassan_rows"]

    remaining = [cluster for cluster in sorted(clusters)
                 if not clusters[cluster]["forced_train"]
                 and clusters[cluster]["hassan_rows"] > 0]
    random.Random(seed).shuffle(remaining)
    for cluster in remaining:
        if train_rows < target_rows:
            assignment[cluster] = TRAIN
            train_rows += clusters[cluster]["hassan_rows"]
        else:
            assignment[cluster] = HOLDOUT

    for cluster in clusters:
        if cluster not in assignment:
            assignment[cluster] = TRAIN

    for cluster, entry in clusters.items():
        entry["partition"] = assignment[cluster]
        entry["forced_train"] = bool(entry["forced_train"])

    train_clusters = {cluster for cluster, part in assignment.items()
                      if part == TRAIN and clusters[cluster]["hassan_rows"] > 0}
    holdout_clusters = {cluster for cluster, part in assignment.items()
                        if part == HOLDOUT}
    overlap = sum(1 for cluster in assignment
                  if cluster in train_clusters and cluster in holdout_clusters)
    holdout_rows = sum(clusters[cluster]["hassan_rows"]
                       for cluster in holdout_clusters)
    return {
        "seed": seed,
        "target_fraction": target_fraction,
        "target_rows": target_rows,
        "assignment": dict(sorted(assignment.items())),
        "clusters": dict(sorted(clusters.items())),
        "counts": {
            "hassan_rows": hassan_rows,
            "hassan_clusters": sum(1 for entry in clusters.values()
                                   if entry["hassan_rows"] > 0),
            "train_rows": sum(clusters[cluster]["hassan_rows"]
                              for cluster in assignment
                              if assignment[cluster] == TRAIN),
            "train_clusters": len(train_clusters),
            "holdout_rows": holdout_rows,
            "holdout_clusters": len(holdout_clusters),
            "holdout_fraction": (holdout_rows / hassan_rows
                                 if hassan_rows else 0.0),
            "forced_train_clusters": sum(
                1 for entry in clusters.values() if entry["forced_train"]),
            "fixture_rows": sum(entry["fixture_rows"]
                                for entry in clusters.values()),
        },
        "overlap": overlap,
    }


def assign_clusters(rows: Iterable[dict], seed: int = SEED,
                    target_fraction: float = TARGET_FRACTION) -> dict[str, str]:
    """Return the cluster -> train|holdout assignment only."""
    return build_partition(rows, seed, target_fraction)["assignment"]


def assignment_for(manifest: dict, cluster_id: str) -> str:
    """Return train for unknown clusters (conservative; never holdout)."""
    return manifest["assignment"].get(str(cluster_id), TRAIN)

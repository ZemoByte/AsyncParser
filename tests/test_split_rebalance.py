#!/usr/bin/env python3
"""Synthetic tests for the deterministic split rebalance post-pass."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Splits.split import rebalance_splits  # noqa: E402


def build(positive: dict[str, list[int]],
          negative: dict[str, int]) -> tuple[list[dict], dict[str, str]]:
    rows: list[dict] = []
    assignment: dict[str, str] = {}
    for split, sizes in positive.items():
        for index, size in enumerate(sizes):
            cluster_id = f"{split}-p{index}"
            for item in range(size):
                sha = f"{cluster_id}-{item}"
                rows.append({"sha256": sha, "label": "positive",
                             "cluster_id": cluster_id})
                assignment[sha] = split
    for split, size in negative.items():
        cluster_id = f"{split}-n"
        for item in range(size):
            sha = f"{cluster_id}-{item}"
            rows.append({"sha256": sha, "label": "negative",
                         "cluster_id": cluster_id})
            assignment[sha] = split
    return rows, assignment


BASE_TRAIN = [86, 10, 8, 7, 5, 3]          # 119
BASE_VAL = [4, 3] + [1] * 18               # 25 over 20 clusters
BASE_TEST = [14] + [1] * 12                # 26 over 13 clusters


def rows_and_assignment(val_negative: int = 19, val_positive=None,
                        test_positive=None):
    positive = {"train": BASE_TRAIN,
                "val": val_positive or BASE_VAL,
                "test": test_positive or BASE_TEST}
    negative = {"train": 90, "val": val_negative, "test": 20}
    return build(positive, negative)


class RebalanceTests(unittest.TestCase):
    def test_dominant_test_cluster_moves_to_val(self):
        rows, assignment = rows_and_assignment()
        moves = rebalance_splits(rows, assignment)
        self.assertEqual(len(moves), 1)
        self.assertEqual(moves[0]["cluster_id"], "test-p0")
        self.assertEqual((moves[0]["from"], moves[0]["to"]), ("test", "val"))
        self.assertEqual(moves[0]["rows"], 14)
        final = dict(assignment)
        for row in rows:
            if row["cluster_id"] == "test-p0":
                final[row["sha256"]] = "val"
        test_positives = sum(1 for row in rows if row["label"] == "positive"
                             and final[row["sha256"]] == "test")
        val_positives = sum(1 for row in rows if row["label"] == "positive"
                            and final[row["sha256"]] == "val")
        self.assertEqual(test_positives, 12)
        self.assertEqual(val_positives, 39)

    def test_no_move_when_destination_would_exceed_share(self):
        rows, assignment = rows_and_assignment(val_positive=[20, 5])
        self.assertEqual(rebalance_splits(rows, assignment), [])

    def test_no_move_when_row_fraction_leaves_tolerance(self):
        rows, assignment = rows_and_assignment(val_negative=55)
        self.assertEqual(rebalance_splits(rows, assignment), [])

    def test_healthy_split_is_untouched(self):
        rows, assignment = rows_and_assignment(
            val_positive=[5] + [1] * 20, test_positive=[4] + [1] * 12)
        self.assertEqual(rebalance_splits(rows, assignment), [])


if __name__ == "__main__":
    unittest.main()

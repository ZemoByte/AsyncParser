#!/usr/bin/env python3
"""Synthetic tests for the Hassan 70/30 cluster partition."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools import _partition  # noqa: E402


def row(sha: str, cluster: str, hassan: bool = True,
        fixture: bool = False) -> dict:
    return {"sha256": sha, "cluster_id": cluster, "hassan": hassan,
            "fixture": fixture}


class PartitionTests(unittest.TestCase):
    def test_same_input_is_deterministic(self):
        rows = [row(f"a{i}", f"c{i}") for i in range(10)]
        first = _partition.build_partition(rows)
        second = _partition.build_partition(rows)
        self.assertEqual(first["assignment"], second["assignment"])
        self.assertEqual(first["counts"], second["counts"])

    def test_seventy_thirty_and_no_overlap(self):
        rows = [row(f"s{i}", f"c{i}") for i in range(100)]
        result = _partition.build_partition(rows)
        counts = result["counts"]
        self.assertGreaterEqual(counts["train_rows"], 70)
        self.assertLessEqual(counts["train_rows"], 72)
        self.assertEqual(counts["train_rows"] + counts["holdout_rows"], 100)
        self.assertEqual(result["overlap"], 0)
        self.assertEqual(set(result["assignment"].values()),
                         {"train", "holdout"})

    def test_cluster_with_non_hassan_row_goes_train(self):
        rows = [
            row("h1", "mixed"), row("h2", "mixed"),
            row("n1", "mixed", hassan=False),
            row("h3", "clean"),
            row("h4", "clean"),
        ]
        result = _partition.build_partition(rows)
        self.assertEqual(result["assignment"]["mixed"], "train")
        self.assertTrue(result["clusters"]["mixed"]["forced_train"])

    def test_fixture_cluster_stays_train(self):
        rows = [row("f1", "fixture-cluster", hassan=False, fixture=True),
                row("h1", "hassan")]
        result = _partition.build_partition(rows)
        self.assertEqual(result["assignment"]["fixture-cluster"], "train")
        self.assertEqual(result["counts"]["fixture_rows"], 1)

    def test_no_cluster_is_in_both(self):
        rows = [row(f"s{i}", f"c{i}") for i in range(20)]
        result = _partition.build_partition(rows)
        train = {key for key, value in result["assignment"].items()
                 if value == "train"}
        holdout = {key for key, value in result["assignment"].items()
                   if value == "holdout"}
        self.assertFalse(train & holdout)


if __name__ == "__main__":
    unittest.main()

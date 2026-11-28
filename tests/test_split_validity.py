#!/usr/bin/env python3
"""Synthetic tests for greedy cluster packing and baseline validity flags."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Models import baseline  # noqa: E402
from Tools.Splits import split  # noqa: E402


def make_rows(sizes: dict[str, int], label: str = "positive") -> list[dict]:
    rows = []
    for cluster_id, size in sizes.items():
        for index in range(size):
            rows.append({"sha256": f"{cluster_id}-{index}", "label": label,
                         "cluster_id": cluster_id,
                         "first_seen": "2021-01-01 00:00:00"})
    return rows


class PackingTests(unittest.TestCase):
    def test_whole_clusters_and_row_targets(self):
        assignment = split.pack_clusters({"a": 8, "b": 1, "c": 1})
        self.assertEqual(assignment, {"a": "train", "b": "test", "c": "val"})

    def test_deterministic_for_equal_sizes(self):
        first = split.pack_clusters({"b": 2, "a": 2, "c": 2})
        second = split.pack_clusters({"c": 2, "a": 2, "b": 2})
        self.assertEqual(first, second)

    def test_no_cluster_spans_splits(self):
        rows = make_rows({"a": 8, "b": 1, "c": 1})
        assignment = split.cluster_split(rows)
        for cluster_id in ("a", "b", "c"):
            splits = {assignment[row["sha256"]] for row in rows
                      if row["cluster_id"] == cluster_id}
            self.assertEqual(len(splits), 1)


class SplitStatsTests(unittest.TestCase):
    def test_largest_share_marks_degenerate(self):
        rows = make_rows({"big": 9, "small": 1})
        assignment = {"big-0": "test", "big-1": "test", "big-2": "test",
                      "big-3": "test", "big-4": "test", "big-5": "test",
                      "big-6": "test", "big-7": "test", "big-8": "test",
                      "small-0": "test"}
        stats = split.split_stats(rows, assignment,
                                  {"positive": 2, "negative": 20})
        self.assertGreater(stats["test"]["largest_positive_share"], 0.40)
        self.assertTrue(stats["test"]["degenerate"])

    def test_under_ten_class_clusters_marks_every_split(self):
        rows = make_rows({"a": 1, "b": 1})
        assignment = {"a-0": "train", "b-0": "test"}
        stats = split.split_stats(rows, assignment,
                                  {"positive": 2, "negative": 20})
        self.assertTrue(all(item["degenerate"] for item in stats.values()))


class ValidityTests(unittest.TestCase):
    def split_dict(self, positive_groups: list[str],
                   negatives: int = 10) -> dict:
        y = np.array([1] * len(positive_groups) + [0] * negatives)
        groups = np.array(list(positive_groups)
                          + [f"neg{i}" for i in range(negatives)])
        return {"y": y, "groups": groups,
                "sha256": np.array([f"s{i}" for i in range(len(y))])}

    def test_small_test_is_not_a_result(self):
        test = self.split_dict(["c1", "c1", "c2", "c2"])
        train = self.split_dict(["t1"] * 30 + ["t2"] * 20 + ["t3"] * 10)
        results = [{"name": "lightgbm_full", "metrics": {"f1": 0.9}},
                   {"name": "lightgbm_structural_only", "metrics": {"f1": 0.5}}]
        with tempfile.TemporaryDirectory() as directory:
            report = baseline.validity_report(train, test, results,
                                              {"triggered": False},
                                              Path(directory))
        self.assertTrue(report["not_a_result"])
        self.assertEqual(report["test_positive_clusters"], 2)
        self.assertFalse(report["structural_confound"])
        self.assertTrue(any("test_positives" in reason
                            for reason in report["reasons"]))

    def test_structural_confound_is_flagged(self):
        test = self.split_dict([f"c{i}" for i in range(6)] * 5)
        train = self.split_dict(["t1"] * 40 + ["t2"] * 20)
        results = [{"name": "lightgbm_full", "metrics": {"f1": 0.99}},
                   {"name": "lightgbm_structural_only", "metrics": {"f1": 0.98}}]
        with tempfile.TemporaryDirectory() as directory:
            report = baseline.validity_report(train, test, results,
                                              {"triggered": False},
                                              Path(directory))
        self.assertTrue(report["structural_confound"])
        self.assertTrue(report["not_a_result"])

    def test_loco_without_positives_forces_diagnostic(self):
        test = self.split_dict([f"c{i}" for i in range(6)] * 5)
        train = self.split_dict(["t1"] * 40)
        results = [{"name": "lightgbm_full", "metrics": {"f1": 0.9}},
                   {"name": "lightgbm_structural_only", "metrics": {"f1": 0.5}}]
        with tempfile.TemporaryDirectory() as directory:
            report = baseline.validity_report(
                train, test, results,
                {"triggered": True, "positives": 0, "f1": 0.0},
                Path(directory))
        self.assertTrue(report["loco_empty"])
        self.assertTrue(report["not_a_result"])
        self.assertTrue(any("LOCO has no positive rows" in reason
                            for reason in report["reasons"]))

    def test_degenerate_split_forces_diagnostic(self):
        test = self.split_dict([f"c{i}" for i in range(6)] * 5)
        train = self.split_dict(["t1"] * 40)
        results = [{"name": "lightgbm_full", "metrics": {"f1": 0.9}},
                   {"name": "lightgbm_structural_only", "metrics": {"f1": 0.5}}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Splits").mkdir()
            (root / "Splits" / ".done").write_text('{"degenerate": true}')
            report = baseline.validity_report(train, test, results,
                                              {"triggered": False}, root)
        self.assertTrue(report["split_degenerate"])
        self.assertTrue(report["not_a_result"])
        self.assertIn("cluster split is degenerate", report["reasons"])

    def test_loco_perfect_with_few_clusters_is_inspected(self):
        test = self.split_dict([f"c{i}" for i in range(6)] * 5)
        train = self.split_dict(["t1"] * 20 + ["t2"] * 10 + ["t3"] * 10)
        results = [{"name": "lightgbm_full", "metrics": {"f1": 0.9}},
                   {"name": "lightgbm_structural_only", "metrics": {"f1": 0.5}}]
        with tempfile.TemporaryDirectory() as directory:
            report = baseline.validity_report(
                train, test, results, {"triggered": True, "f1": 1.0},
                Path(directory))
        self.assertTrue(report["loco_inspect"])
        self.assertTrue(report["not_a_result"])


if __name__ == "__main__":
    unittest.main()

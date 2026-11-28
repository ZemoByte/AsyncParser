#!/usr/bin/env python3
"""Synthetic tests for split cleanup and importer split assignment."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Importer.importer import split_assignment  # noqa: E402
from Tools.Splits.split import cleanup_stale_splits  # noqa: E402


class SplitCleanupTests(unittest.TestCase):
    def test_stale_split_is_deleted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "keep.json").write_text(json.dumps({"sha256": "keep"}))
            (root / "stale.json").write_text(json.dumps({"sha256": "stale"}))
            removed = cleanup_stale_splits(root, {"keep"})
            self.assertEqual(removed, ["stale"])
            self.assertEqual(sorted(p.stem for p in root.glob("*.json")),
                             ["keep"])
            self.assertEqual(len(list(root.glob("*.json"))), 1)


class SplitAssignmentTests(unittest.TestCase):
    def test_primary_row_keeps_current_split(self):
        label = {"lbl_sts": "verified"}
        split, temporal = split_assignment(
            "abc", label, 0, {"abc": {"cluster_split": "train",
                                      "temporal_split": "val"}}, True,
            "test", "test")
        self.assertEqual((split, temporal), ("train", "val"))

    def test_excluded_row_gets_null(self):
        for status in ("reference_only", "unverified", "review",
                       "rejected_non_dotnet"):
            split, temporal = split_assignment(
                "abc", {"lbl_sts": status}, 0, {}, True, "train", "val")
            self.assertEqual((split, temporal), (None, None), status)

    def test_gold_row_gets_null(self):
        split, _ = split_assignment(
            "abc", {"lbl_sts": "verified"}, 1,
            {"abc": {"cluster_split": "train"}}, True, "test", "test")
        self.assertIsNone(split)

    def test_fixture_benign_gets_null(self):
        split, _ = split_assignment(
            "abc", {"lbl_sts": "benign", "source": "fixture",
                    "origin": "fixture"}, 0,
            {"abc": {"cluster_split": "train"}}, True, "test", "test")
        self.assertIsNone(split)

    def test_stale_split_is_cleared_when_marker_exists(self):
        split, temporal = split_assignment(
            "abc", {"lbl_sts": "verified"}, 0, {}, True, "train", "val")
        self.assertEqual((split, temporal), (None, None))

    def test_no_marker_preserves_existing(self):
        split, temporal = split_assignment(
            "abc", {"lbl_sts": "verified"}, 0, {}, False, "train", "val")
        self.assertEqual((split, temporal), ("train", "val"))

    def test_holdout_benign_without_split_file_is_null(self):
        split, _ = split_assignment(
            "abc", {"lbl_sts": "benign", "source": "clrheader2023",
                    "origin": "github", "kind": "exe"}, 0, {}, True,
            "train", "val")
        self.assertIsNone(split)


if __name__ == "__main__":
    unittest.main()

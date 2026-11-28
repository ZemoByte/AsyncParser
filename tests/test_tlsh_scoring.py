#!/usr/bin/env python3
"""Synthetic tests for TLSH pair failure handling and kNN scores."""

from __future__ import annotations

import contextlib
import io
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Clustering import clusterer  # noqa: E402
from Tools.Models import baseline  # noqa: E402


class TlshPairTests(unittest.TestCase):
    def test_diff_failure_warns_and_returns_false(self):
        fake = SimpleNamespace(diff=mock.Mock(side_effect=ValueError("boom")))
        buffer = io.StringIO()
        with mock.patch.object(clusterer, "tlsh", fake), \
                contextlib.redirect_stderr(buffer):
            result = clusterer.tls_pair_match("a" * 64, "b" * 64,
                                              {"a" * 64: "x", "b" * 64: "y"},
                                              100)
        self.assertFalse(result)
        warning = buffer.getvalue()
        self.assertIn("WARNING: TLSH diff failed", warning)
        self.assertIn("a" * 64, warning)
        self.assertIn("b" * 64, warning)
        self.assertIn("boom", warning)

    def test_missing_hash_is_false_without_warning(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            self.assertFalse(clusterer.tls_pair_match("a", "b", {}, 100))
        self.assertEqual(buffer.getvalue(), "")


class DistanceScoreTests(unittest.TestCase):
    def test_closer_neighbour_scores_higher(self):
        self.assertGreater(baseline.distance_score(10),
                           baseline.distance_score(100))
        self.assertGreater(baseline.distance_score(100),
                           baseline.distance_score(500))

    def test_zero_distance_is_one(self):
        self.assertEqual(baseline.distance_score(0), 1.0)

    def test_no_neighbour_is_zero(self):
        self.assertEqual(baseline.distance_score(None), 0.0)


if __name__ == "__main__":
    unittest.main()

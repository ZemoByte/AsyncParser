#!/usr/bin/env python3
"""Synthetic tests for Phase 4 LOCO/abstention/explainability/Stage 2."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Models import evaluate  # noqa: E402


class LocoFoldTests(unittest.TestCase):
    def test_every_cluster_is_held_out_once(self):
        data = {"groups": np.array(["c1", "c1", "c2", "c3", "c3", "c3"]),
                "y": np.array([1, 1, 0, 1, 1, 0])}
        folds = evaluate.loco_folds(data)
        self.assertEqual([fold[0] for fold in folds], ["c1", "c2", "c3"])
        for _cluster, train_idx, test_idx in folds:
            self.assertFalse(set(train_idx) & set(test_idx))
            self.assertEqual(len(train_idx) + len(test_idx), len(data["y"]))

    def test_positive_only_filter(self):
        data = {"groups": np.array(["c1", "c2", "c3"]),
                "y": np.array([1, 0, 1])}
        self.assertEqual([fold[0] for fold in evaluate.loco_folds(data, True)],
                         ["c1", "c3"])


class AbstentionTests(unittest.TestCase):
    def test_threshold_uses_fifth_percentile(self):
        values = list(range(1, 101))
        self.assertEqual(evaluate.choose_threshold(values), 5)
        self.assertEqual(evaluate.choose_threshold([]), 1)

    def test_threshold_is_at_least_one(self):
        self.assertEqual(evaluate.choose_threshold([0, 0, 0]), 1)


class TemplateTests(unittest.TestCase):
    def test_template_contains_features_and_neighbour(self):
        text = evaluate.template_sentence(
            ["System.Net.Sockets.Socket::Connect", "System.IO.File::ReadAllBytes"],
            "a" * 64, 42)
        self.assertIn("System.Net.Sockets.Socket::Connect", text)
        self.assertIn("distance 42", text)
        self.assertIn("a" * 12, text)

    def test_missing_neighbour(self):
        text = evaluate.template_sentence(["X"], "", None)
        self.assertIn("no nonzero features" if not any(["X"]) else "references X",
                      text)
        self.assertIn("none", text)
        self.assertIn("n/a", text)


class Stage2Tests(unittest.TestCase):
    def test_confident_xworm(self):
        self.assertEqual(
            evaluate.stage2_decision(["XWorm", "XWorm"], "XWorm", 40),
            "XWorm")

    def test_quasar_abstains(self):
        self.assertEqual(
            evaluate.stage2_decision(["QuasarRAT", "QuasarRAT"],
                                     "QuasarRAT", 10),
            "abstain")

    def test_disagreement_abstains(self):
        self.assertEqual(
            evaluate.stage2_decision(["DcRat", "DcRat"], "AsyncRAT", 10),
            "abstain")

    def test_venom_confident(self):
        self.assertEqual(
            evaluate.stage2_decision(["VenomRAT", "VenomRAT"],
                                     "VenomRAT", 30),
            "VenomRAT")


if __name__ == "__main__":
    unittest.main()

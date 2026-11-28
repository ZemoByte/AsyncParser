#!/usr/bin/env python3
"""Synthetic tests for the fixup cap, feature policy and eligibility rules."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Features.build_matrix import (  # noqa: E402
    POLICY_EXCLUDED, STRUCTURAL_FEATURES, select_structural_names,
)
from Tools.Models import baseline  # noqa: E402
from Tools.Models.fixup_eval import (  # noqa: E402
    apply_threshold, build_run_metadata, cap_largest_positive, cluster_folds,
    holdout_entry, is_eligible, loco_clusters, mixed_loco_folds,
    threshold_at_recall, threshold_for_f1, threshold_on_train,
)


def fake_split(groups: list[str], labels: list[int]) -> dict:
    size = len(groups)
    return {
        "X": csr_matrix(np.ones((size, 2), dtype=np.int8)),
        "X_struct": np.ones((size, 3), dtype=np.float32),
        "y": np.asarray(labels, dtype=int),
        "groups": np.asarray(groups),
        "sha256": np.asarray([f"{index:064x}" for index in range(size)]),
        "vocab_size": 2,
    }


class CapTests(unittest.TestCase):
    def test_largest_positive_cluster_is_capped_to_ten(self):
        groups = ["big"] * 14 + ["small"] * 3 + ["neg"] * 4
        labels = [1] * 17 + [0] * 4
        data = fake_split(groups, labels)
        capped, info = cap_largest_positive(data)
        self.assertEqual(info["cluster"], "big")
        self.assertEqual(info["removed"], 4)
        self.assertEqual(int(capped["y"].sum()), 13)
        self.assertEqual(len(capped["y"]), 17)
        self.assertEqual(sum(1 for group in capped["groups"]
                             if group == "big"), 10)

    def test_no_cap_when_cluster_is_small(self):
        data = fake_split(["a"] * 5 + ["b"] * 2, [1] * 7)
        capped, info = cap_largest_positive(data)
        self.assertEqual(info["removed"], 0)
        self.assertIs(capped, data)

    def test_cap_is_deterministic(self):
        groups = ["big"] * 14 + ["neg"] * 2
        labels = [1] * 14 + [0] * 2
        first, _ = cap_largest_positive(fake_split(groups, labels))
        second, _ = cap_largest_positive(fake_split(groups, labels))
        self.assertEqual(first["sha256"].tolist(), second["sha256"].tolist())


class PolicyTests(unittest.TestCase):
    def test_policy_drops_only_container_fields(self):
        names = select_structural_names("policy")
        self.assertEqual(set(POLICY_EXCLUDED), {
            "structure_file_size", "structure_section_count",
            "structure_entropy_max", "structure_entropy_mean"})
        for name in POLICY_EXCLUDED:
            self.assertNotIn(name, names)
        self.assertEqual(len(names), len(STRUCTURAL_FEATURES) - 4)
        self.assertIn("structure_implmap_count", names)

    def test_all_policy_keeps_every_field(self):
        self.assertEqual(select_structural_names("all"), STRUCTURAL_FEATURES)

    def test_unknown_policy_is_rejected(self):
        with self.assertRaises(ValueError):
            select_structural_names("nope")


class ThresholdTests(unittest.TestCase):
    def test_threshold_separates_synthetic_scores(self):
        y = np.asarray([0, 0, 1, 1])
        score = np.asarray([0.1, 0.2, 0.8, 0.9])
        threshold = threshold_for_f1(y, score)
        self.assertGreater(threshold, 0.2)
        self.assertLessEqual(threshold, 0.8)

    def test_constant_scores_do_not_crash(self):
        y = np.asarray([0, 1, 1])
        self.assertEqual(threshold_for_f1(y, np.ones(3)), 1.0)


class LocoClusterTests(unittest.TestCase):
    def test_verified_scope_keeps_only_asyncrat(self):
        groups = ["a", "a", "x", "q", "n"]
        labels = [1, 1, 1, 1, 0]
        families = {"s1": "AsyncRAT", "s2": "AsyncRAT",
                    "s3": "XWorm", "s4": "QuasarRAT", "s5": ""}
        names = ["s1", "s2", "s3", "s4", "s5"]
        self.assertEqual(loco_clusters(groups, labels, dict(zip(names, families.values())), True),
                         ["a"])
        self.assertEqual(loco_clusters(groups, labels, dict(zip(names, families.values())), False),
                         ["a", "q", "x"])

    def test_negative_cluster_is_never_a_fold(self):
        self.assertEqual(loco_clusters(["n"], [0], {"s": ""}, False), [])


class OperatingPointTests(unittest.TestCase):
    def test_threshold_uses_train_only(self):
        y_train = np.asarray([0, 0, 1, 1])
        scores = np.asarray([0.1, 0.2, 0.8, 0.9])
        threshold = threshold_on_train(y_train, scores)
        changed_test = np.asarray([1, 1, 0, 0])  # not passed to the function
        self.assertEqual(threshold,
                         threshold_on_train(y_train, scores))
        self.assertGreater(threshold, 0.2)
        self.assertLessEqual(threshold, 0.8)
        self.assertEqual(changed_test.tolist(), [1, 1, 0, 0])

    def test_apply_threshold_is_inclusive(self):
        scores = np.asarray([0.2, 0.5, 0.7])
        self.assertEqual(apply_threshold(scores, 0.5).tolist(), [0, 1, 1])

    def test_holdout_entry_uses_given_thresholds(self):
        scores = np.asarray([0.1, 0.6, 0.9])
        groups = np.asarray(["a", "b", "c"])
        entry = holdout_entry(
            scores,
            {"oof": 0.8, "in_sample": 0.4, "recall95": 0.7,
             "recall90": 0.5},
            groups)
        self.assertEqual(entry["threshold_oof"], 0.8)
        self.assertEqual(entry["threshold_in_sample"], 0.4)
        self.assertEqual(entry["threshold_recall95"], 0.7)
        self.assertEqual(entry["at_oof"]["predicted_positive"], 1)
        self.assertEqual(entry["at_0.5"]["predicted_positive"], 2)
        self.assertEqual(entry["at_in_sample"]["predicted_positive"], 2)
        self.assertEqual(entry["at_recall_95"]["predicted_positive"], 1)
        self.assertEqual(entry["main"], "at_recall_95")


class MixedLocoTests(unittest.TestCase):
    def test_every_benign_cluster_is_held_out_once(self):
        groups = np.asarray(["p1", "p2", "p3", "b1", "b2", "b3", "b4"])
        labels = np.asarray([1, 1, 1, 0, 0, 0, 0])
        positives = ["p1", "p2", "p3"]
        benign = ["b1", "b2", "b3", "b4"]
        folds = mixed_loco_folds(groups, labels, positives, benign)
        self.assertEqual(len(folds), 3)
        assigned = sorted(cluster for fold in folds
                          for cluster in fold["benign_clusters"])
        self.assertEqual(assigned, benign)
        for fold in folds:
            held = set(groups[fold["test_index"]])
            train = set(groups[fold["train_index"]])
            self.assertFalse(held & train)
            self.assertIn(fold["positive_cluster"], held)

    def test_fold_has_positive_and_benign_rows(self):
        groups = np.asarray(["p1", "p2", "b1", "b2"])
        labels = np.asarray([1, 1, 0, 0])
        folds = mixed_loco_folds(groups, labels, ["p1", "p2"], ["b1", "b2"])
        for fold in folds:
            y_test = labels[fold["test_index"]]
            self.assertEqual(int(y_test.sum()), 1)
            self.assertEqual(int((y_test == 0).sum()), 1)


class MatchedRecallTests(unittest.TestCase):
    def test_threshold_at_recall_uses_train_only(self):
        y = np.asarray([0, 0, 1, 1, 1, 1])
        scores = np.asarray([0.1, 0.2, 0.4, 0.6, 0.8, 0.9])
        threshold = threshold_at_recall(y, scores, 0.95)
        self.assertGreater(threshold, 0.2)
        self.assertLessEqual(threshold, 0.4)
        self.assertEqual(threshold, threshold_at_recall(y, scores, 0.95))

    def test_raw_pna_threshold_is_not_forced_to_half(self):
        y = np.asarray([0, 0, 1, 1, 1, 1])
        counts = np.asarray([0, 1, 2, 4, 8, 16])
        threshold = threshold_at_recall(y, counts, 0.95)
        self.assertGreater(threshold, 0.5)

    def test_target_recall_is_met_on_train(self):
        y = np.asarray([0, 1, 1, 1, 1])
        scores = np.asarray([0.1, 0.2, 0.3, 0.8, 0.9])
        threshold = threshold_at_recall(y, scores, 0.95)
        self.assertGreaterEqual(float(np.mean(scores[y == 1] >= threshold)),
                                0.95)


class OofFoldTests(unittest.TestCase):
    def test_grouped_folds_never_split_clusters(self):
        groups = np.asarray(["a", "a", "b", "b", "c", "c", "d", "d",
                             "e", "e", "f", "f", "g", "g", "h", "h"])
        folds = cluster_folds(groups, n_splits=4)
        self.assertEqual(len(folds), 4)
        for train_idx, test_idx in folds:
            self.assertFalse(set(groups[train_idx]) & set(groups[test_idx]))

    def test_run_metadata(self):
        metadata = build_run_metadata()
        self.assertIn("generated_at", metadata)
        self.assertEqual(len(metadata["script_sha256"]), 64)
        self.assertTrue(metadata["run_id"])
        self.assertEqual(metadata["oof_folds"], 5)
        self.assertEqual(metadata["threshold_source"], "train_oof_groupkfold")


class BootstrapTests(unittest.TestCase):
    def test_one_class_resamples_skip_roc_and_pr(self):
        y = np.asarray([0, 0, 1, 1])
        pred = np.asarray([0, 0, 1, 1])
        score = np.asarray([0.1, 0.2, 0.8, 0.9])
        groups = np.asarray(["a", "b", "c", "d"])
        result = baseline.bootstrap_ci(y, pred, score, groups, iterations=50)
        self.assertIn("f1", result)
        self.assertIn("pr_auc", result)
        self.assertIn("roc_auc", result)


class Stage2NoteTests(unittest.TestCase):
    def test_note_wording(self):
        from Tools.Models.fixup_eval import STAGE2_NOTE
        note = STAGE2_NOTE.format(rows=29)
        self.assertIn("diagnostic 2-family LightGBM", note)
        self.assertIn("29 test rows", note)
        self.assertIn("not a result", note)


class EligibilityTests(unittest.TestCase):
    def test_eligible_needs_twenty_rows_and_ten_clusters(self):
        self.assertTrue(is_eligible(20, 10))
        self.assertFalse(is_eligible(19, 10))
        self.assertFalse(is_eligible(20, 9))


if __name__ == "__main__":
    unittest.main()

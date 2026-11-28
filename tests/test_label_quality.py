#!/usr/bin/env python3
"""Synthetic tests for the automated label-quality classifier."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Audit.label_quality import (  # noqa: E402
    classify_conflict, classify_evidence, config_present,
)


class LabelQualityTests(unittest.TestCase):
    def test_mb_only(self):
        self.assertEqual(classify_evidence({"malwarebazaar": "AsyncRAT"}),
                         "mb_only")

    def test_mb_plus_family_voter_is_multi_source(self):
        self.assertEqual(classify_evidence({
            "malwarebazaar": "AsyncRAT",
            "own_yara": "AsyncRAT",
        }), "multi_source")

    def test_no_family_vote(self):
        self.assertEqual(classify_evidence({"elastic": "no_match"}),
                         "no_family")

    def test_non_mb_only_is_other_sources(self):
        self.assertEqual(classify_evidence({"own_yara": "AsyncRAT"}),
                         "other_sources")

    def test_conflict_majority_support(self):
        self.assertEqual(classify_conflict(
            {"malwarebazaar": "AsyncRAT", "own_yara": "AsyncRAT"},
            "AsyncRAT"), "majority_support")

    def test_conflict_majority_different(self):
        self.assertEqual(classify_conflict(
            {"malwarebazaar": "XWorm", "own_yara": "XWorm"},
            "AsyncRAT"), "majority_different")

    def test_conflict_tie(self):
        self.assertEqual(classify_conflict(
            {"malwarebazaar": "AsyncRAT", "own_yara": "XWorm"},
            "AsyncRAT"), "tie")

    def test_conflict_no_family(self):
        self.assertEqual(classify_conflict({}, "AsyncRAT"), "no_family")

    def test_config_present_rejects_parse_error(self):
        self.assertTrue(config_present('{"hosts": ["127.0.0.1"]}'))
        self.assertFalse(config_present('{"parse_error": "x"}'))
        self.assertFalse(config_present(''))


if __name__ == "__main__":
    unittest.main()

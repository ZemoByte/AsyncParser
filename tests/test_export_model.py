#!/usr/bin/env python3
"""Synthetic tests for the model exporter metadata path."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

import joblib

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Models import export_model  # noqa: E402


class FakeModel:
    def predict_proba(self, X):
        return [[0.2, 0.8]]


class ExportModelTests(unittest.TestCase):
    def test_save_artifact_metadata_and_reload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capability.joblib"
            payload = export_model.save_artifact(path, FakeModel(), {
                "vocab_size": 3,
                "feature_names": ["a", "b", "c"],
                "threshold": 0.559,
                "abstain_threshold": 357,
                "run_id": "c7a21a6c",
                "script_sha256": "6598bfce",
                "feature_policy": "capability",
            })
            loaded = joblib.load(path)
        self.assertEqual(payload["model"].__class__, FakeModel)
        self.assertEqual(loaded["vocab_size"], 3)
        self.assertEqual(loaded["threshold"], 0.559)
        self.assertEqual(loaded["feature_policy"], "capability")
        self.assertIn("model", loaded)


if __name__ == "__main__":
    unittest.main()

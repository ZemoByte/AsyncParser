#!/usr/bin/env python3
"""Synthetic tests for the static single-EXE prototype."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import joblib
import numpy as np
from scipy.sparse import csr_matrix

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Models import predict  # noqa: E402


class FakeModel:
    def __init__(self, positive: float):
        self.positive = positive

    def predict_proba(self, X):
        return np.asarray([[1.0 - self.positive, self.positive]])


class FakeFamily:
    def predict_proba(self, X):
        return np.asarray([[0.75, 0.25]])


def artifact(positive: float = 0.8) -> dict:
    return {"model": FakeModel(positive), "vocab_size": 3,
            "feature_names": ["a", "b", "c"], "threshold": 0.559,
            "abstain_threshold": 357}


def family_artifact() -> dict:
    return {"model": FakeFamily(), "classes": ["AsyncRAT", "XWorm"]}


class PredictTests(unittest.TestCase):
    def test_non_dotnet_abstains_without_score(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "notdotnet.bin"
            path.write_bytes(b"MZ" + b"\x00" * 32)
            result = predict.evaluate(path, artifact(), family_artifact())
        self.assertEqual(result["stage1"]["status"], "abstain")
        self.assertTrue(result["stage1"]["reason"] == "rejected_non_dotnet"
                        or result["stage1"]["reason"].startswith(
                            "parse_failure:"))
        self.assertNotIn("score", result["stage1"])

    def test_too_few_references_abstains(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "weak.exe"
            path.write_bytes(b"fixture")
            with mock.patch.object(predict, "parse_static"), \
                    mock.patch.object(predict, "carve_typeref",
                                      return_value=["a"]), \
                    mock.patch.object(predict, "carve_memberref",
                                      return_value=[]), \
                    mock.patch.object(predict, "carve_assemblyref",
                                      return_value=[]), \
                    mock.patch.object(predict, "carve_implmap",
                                      return_value=[]), \
                    mock.patch.object(predict, "carve_imports",
                                      return_value=[]), \
                    mock.patch.object(predict, "carve_structure",
                                      return_value={}):
                result = predict.evaluate(path, artifact(), family_artifact())
        self.assertEqual(result["stage1"]["status"], "abstain")
        self.assertIn("too_few_typeref_memberref", result["abstain"])

    def test_stage1_and_stage2_scored(self):
        X = csr_matrix(np.asarray([[1, 0, 1]], dtype=np.float32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benign.exe"
            path.write_bytes(b"fixture")
            with mock.patch.object(predict, "extract",
                                   return_value=(X, 400, {})), \
                    mock.patch.object(predict, "nearest_reference",
                                      return_value={"sha256": "a" * 64,
                                                    "family": "AsyncRAT",
                                                    "distance": 10}):
                result = predict.evaluate(path, artifact(0.8),
                                          family_artifact())
        self.assertEqual(result["stage1"]["predicted"], "RAT")
        self.assertEqual(result["stage2"]["status"], "scored")
        self.assertIn("diagnostic, n=29", result["stage2"]["note"])

    def test_stage2_ineligible_family_abstains(self):
        X = csr_matrix(np.asarray([[1, 0, 1]], dtype=np.float32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benign.exe"
            path.write_bytes(b"fixture")
            with mock.patch.object(predict, "extract",
                                   return_value=(X, 400, {})):
                result = predict.evaluate(path, artifact(0.2),
                                          family_artifact())
        self.assertEqual(result["stage1"]["predicted"], "benign")
        self.assertEqual(result["stage2"]["status"], "abstain")
        self.assertEqual(result["stage2"]["reason"], predict.FAMILY_REASON)

    def test_json_and_exit_codes(self):
        X = csr_matrix(np.asarray([[1, 0, 1]], dtype=np.float32))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "benign.exe"
            path.write_bytes(b"fixture")
            expected_hash = predict.sha256_file(path)
            model_path = Path(directory) / "capability.joblib"
            family_path = Path(directory) / "family.joblib"
            joblib.dump(artifact(0.8), model_path)
            joblib.dump(family_artifact(), family_path)
            argv = ["predict.py", "--file", str(path), "--json",
                    "--model", str(model_path),
                    "--family-model", str(family_path)]
            with mock.patch.object(predict, "extract",
                                   return_value=(X, 400, {})), \
                    mock.patch.object(sys, "argv", argv):
                output = io.StringIO()
                with redirect_stdout(output):
                    code = predict.main()
        payload = json.loads(output.getvalue())
        self.assertEqual(code, 0)
        self.assertFalse(payload["validated"])
        self.assertEqual(payload["gate"], "FAIL")
        self.assertEqual(payload["sha256"], expected_hash)
        self.assertEqual(payload["stage1"]["status"], "scored")
        self.assertIn("stage2", payload)
        self.assertIn("abstain", payload)

    def test_family_scope_requires_asyncrat_or_xworm(self):
        self.assertTrue(predict.family_eligible(
            {"family": "AsyncRAT", "distance": 10}))
        self.assertTrue(predict.family_eligible(
            {"family": "XWorm", "distance": 100}))
        self.assertFalse(predict.family_eligible(
            {"family": "DcRat", "distance": 10}))
        self.assertFalse(predict.family_eligible(
            {"family": "AsyncRAT", "distance": 101}))

    def test_banner_is_first_line(self):
        result = {"stage1": {"status": "abstain", "reason": "x"},
                  "stage2": {"status": "abstain", "reason": "x"},
                  "abstain": "x"}
        text = predict.render_text(result)
        self.assertTrue(text.startswith(predict.BANNER))


if __name__ == "__main__":
    unittest.main()

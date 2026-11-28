#!/usr/bin/env python3
"""Synthetic tests: a bad parser result must not abort labeling."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Labeling import labeler  # noqa: E402


def result(stdout: str, returncode: int = 0, stderr: str = "") -> SimpleNamespace:
    return SimpleNamespace(stdout=stdout, returncode=returncode, stderr=stderr)


class ParserFallbackTests(unittest.TestCase):
    def test_bad_chunk_falls_back_per_file(self):
        paths = [Path("a.exe"), Path("b.exe")]
        report = {"sha256": "a" * 64, "yara_possible_family": "asyncrat"}
        calls = [
            result("not json"),
            result(json.dumps([report])),
            result("error Error decrypting ciphertext"),
        ]
        with mock.patch.object(labeler.subprocess, "run",
                               side_effect=calls):
            reports = labeler.run_parser(paths)
        self.assertIn("a" * 64, reports)
        self.assertEqual(len(reports), 1)

    def test_failed_chunk_returncode_falls_back(self):
        paths = [Path("a.exe")]
        report = {"sha256": "a" * 64}
        with mock.patch.object(labeler.subprocess, "run",
                               side_effect=[result("", 1, "boom"),
                                            result(json.dumps([report]))]):
            reports = labeler.run_parser(paths)
        self.assertIn("a" * 64, reports)

    def test_good_chunk_is_used_directly(self):
        paths = [Path("a.exe")]
        report = {"sha256": "a" * 64}
        with mock.patch.object(labeler.subprocess, "run",
                               return_value=result(json.dumps([report]))):
            reports = labeler.run_parser(paths)
        self.assertEqual(reports, {"a" * 64: report})


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Synthetic tests for the own-YARA rule and raw-summary helper."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

import yara

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Voters.OwnYara.own_yara import match_raw  # noqa: E402

RULE_PATH = REPO / "Tools" / "Voters" / "OwnYara" / "asyncrat_own.yar"
STRINGS = [
    "Invalid message authentication code (MAC).",
    "Select * from Win32_ComputerSystem",
    "--donate-level=",
    "Err HWID",
]


def fake_pe(strings: list[str]) -> bytes:
    return b"MZ" + b"\x00" * 64 + b"".join(s.encode("utf-16le") for s in strings)


class OwnYaraRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = yara.compile(filepath=str(RULE_PATH))

    def test_four_strings_match(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fake.exe"
            path.write_bytes(fake_pe(STRINGS))
            matches = self.rules.match(str(path))
            self.assertEqual([match.rule for match in matches],
                             ["AsyncRAT_Own_Client_Strings"])
            raw = match_raw(matches)
            self.assertEqual(raw["rule"], "AsyncRAT_Own_Client_Strings")
            self.assertEqual(len(raw["matched_strings"]), 4)
            self.assertNotIn("matched_data", json.dumps(raw))

    def test_three_strings_do_not_match(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "fake3.exe"
            path.write_bytes(fake_pe(STRINGS[:3]))
            self.assertEqual(self.rules.match(str(path)), [])

    def test_benign_like_file_does_not_match(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "benign.exe"
            path.write_bytes(fake_pe(["hello world", "another harmless string"]))
            self.assertEqual(self.rules.match(str(path)), [])


if __name__ == "__main__":
    unittest.main()

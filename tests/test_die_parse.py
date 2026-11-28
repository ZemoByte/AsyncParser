#!/usr/bin/env python3
"""Synthetic tests for the Detect It Easy JSON parsing (no diec needed)."""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Voters.DIE.die_voter import parse_diec_output  # noqa: E402


def version4(values: list[dict]) -> str:
    return json.dumps({"detects": [{"filetype": "PE64", "values": values}]})


class DieParseTests(unittest.TestCase):
    def test_plain_die4(self):
        level, raw = parse_diec_output(version4([
            {"type": "compiler", "name": "VB.NET", "version": "4.8"},
            {"type": "linker", "name": "Microsoft Linker", "version": ""},
        ]))
        self.assertEqual(level, "plain")
        self.assertEqual(raw["record_count"], 2)

    def test_obfuscator_die4(self):
        level, raw = parse_diec_output(version4([
            {"type": "Protector", "name": "ConfuserEx", "version": "1.6"},
        ]))
        self.assertEqual(level, "obfuscated:ConfuserEx")
        self.assertEqual(len(raw["obfuscator_records"]), 1)

    def test_legacy_records_schema(self):
        payload = {"records": [{"type": "Packer", "name": "UPX", "version": "4"}]}
        level, _ = parse_diec_output(json.dumps(payload))
        self.assertEqual(level, "obfuscated:UPX")

    def test_invalid_json(self):
        level, raw = parse_diec_output("not json")
        self.assertEqual(level, "unknown")
        self.assertTrue(raw["reason"].startswith("diec_json_error"))

    def test_empty_payload(self):
        level, raw = parse_diec_output("{}")
        self.assertEqual(level, "unknown")
        self.assertEqual(raw["reason"], "diec_no_records")


if __name__ == "__main__":
    unittest.main()

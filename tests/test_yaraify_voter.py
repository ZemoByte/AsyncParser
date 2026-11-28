#!/usr/bin/env python3
"""Synthetic tests for the YARAify response parser (no network)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Voters.YARAify import yaraify_voter as voter  # noqa: E402


def payload(tasks: list[dict], metadata: dict | None = None) -> dict:
    return {"query_status": "ok",
            "data": {"metadata": metadata or {}, "tasks": tasks}}


class CollectNamesTests(unittest.TestCase):
    def test_static_results(self):
        data = payload([{"static_results": [
            {"rule_name": "asyncrat", "description": "AsyncRAT_057B"},
            {"rule_name": "asyncrat_kingrat", "description": "AsyncRat"},
        ]}])
        verdict, detail = voter.evaluate_payload(data)
        self.assertEqual(verdict, "AsyncRAT")
        self.assertEqual(detail["strength"], "medium")
        self.assertEqual(detail["raw"]["families"], ["AsyncRAT"])

    def test_clamav_results(self):
        data = payload([{"clamav_results": [
            "Win.Packed.AsyncRAT-9856570-1", "YARA.SEKOIA_Rat_Win_Asyncrat.UNOFFICIAL",
        ]}])
        verdict, detail = voter.evaluate_payload(data)
        self.assertEqual(verdict, "AsyncRAT")
        self.assertEqual(detail["strength"], "medium")

    def test_unpacked_yara_matches(self):
        data = payload([{"unpack_results": [
            {"unpacked_yara_matches": [{"rule_name": "DcRat"}]},
        ]}])
        verdict, detail = voter.evaluate_payload(data)
        self.assertEqual(verdict, "DcRat")
        self.assertEqual(detail["raw"]["families"], ["DcRat"])

    def test_malware_family_field(self):
        data = payload([{"static_results": [{"malpedia_family": "win.xworm"}]}])
        verdict, _ = voter.evaluate_payload(data)
        self.assertEqual(verdict, "XWorm")

    def test_metadata_signature(self):
        data = payload([], metadata={"signature": "AsyncRAT"})
        verdict, _ = voter.evaluate_payload(data)
        self.assertEqual(verdict, "AsyncRAT")

    def test_list_shaped_old_response(self):
        data = {"query_status": "ok", "data": [
            {"yara_rules": [{"rule_name": "AsyncRat Payload"}]},
        ]}
        verdict, _ = voter.evaluate_payload(data)
        self.assertEqual(verdict, "AsyncRAT")

    def test_top_level_tasks_list(self):
        data = {"query_status": "ok",
                "tasks": [{"static_results": [{"rule_name": "DcRat"}]}]}
        verdict, _ = voter.evaluate_payload(data)
        self.assertEqual(verdict, "DcRat")

    def test_empty_tasks(self):
        verdict, detail = voter.evaluate_payload(payload([]))
        self.assertEqual(verdict, "no_match")
        self.assertEqual(detail["strength"], "weak")
        self.assertEqual(detail["raw"]["reason"], "no_family")

    def test_multiple_families(self):
        data = payload([{"static_results": [{"rule_name": "AsyncRAT"}],
                         "clamav_results": ["Win.Trojan.XWorm"]}])
        verdict, detail = voter.evaluate_payload(data)
        self.assertEqual(verdict, "no_match")
        self.assertEqual(detail["strength"], "weak")
        self.assertEqual(detail["raw"]["reason"], "multiple_families")

    def test_substring_family_mapping(self):
        for name in ("asyncrat", "AsyncRAT_057B", "asyncrat_kingrat",
                     "Win.Packed.AsyncRAT", "Rat_Win_Asyncrat"):
            self.assertEqual(voter.families_for_names([name]), ["AsyncRAT"],
                             name)


if __name__ == "__main__":
    unittest.main()

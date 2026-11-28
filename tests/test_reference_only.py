#!/usr/bin/env python3
"""Synthetic tests for the server/builder reference-only audit."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Audit import reference_only  # noqa: E402


def make_label(root: Path, sha: str, status: str, config=None,
               directory: str = "Labels", **extra) -> Path:
    path = root / directory / f"{sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = {"sha256": sha, "lbl_sts": status}
    if config is not None:
        fields["config"] = config
    fields.update(extra)
    path.write_text(json.dumps({
        "schema_version": 1, "sha256": sha, "kind": "label",
        "producer": "labeler", "fields": fields,
    }), encoding="utf-8")
    return path


class AuditTests(unittest.TestCase):
    def test_name_pattern(self):
        names = {"a": "AsyncRAT Server.exe", "b": "client.exe",
                 "c": "x_builder_y.exe", "d": "panel-stub.exe"}
        matches = reference_only.name_matches(names)
        self.assertEqual(set(matches), {"a", "c", "d"})

    def test_only_positives_are_flagged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "verified")
            make_label(root, "b" * 64, "benign")
            auto = {"a" * 64: "file_name:server", "b" * 64: "file_name:server"}
            result = reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            self.assertEqual([item["sha256"] for item in result["changed"]],
                             ["a" * 64])
            self.assertEqual(result["skipped"], {"status:benign": 1})
            fields = json.loads(
                (root / "Labels" / f"{'a' * 64}.json").read_text())["fields"]
            self.assertEqual(fields["lbl_sts"], "reference_only")
            self.assertEqual(fields["previous_status"], "verified")

    def test_valid_config_blocks_auto_flag(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "verified",
                       config={"hosts": ["x.example"], "ports": [4782]})
            auto = {"a" * 64: "file_name:stub"}
            result = reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            self.assertEqual(result["changed"], [])
            self.assertEqual(result["skipped"], {"client_evidence": 1})
            fields = json.loads(
                (root / "Labels" / f"{'a' * 64}.json").read_text())["fields"]
            self.assertEqual(fields["lbl_sts"], "verified")

    def test_parse_error_config_does_not_block(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "verified",
                       config={"parse_error": "no config found"})
            auto = {"a" * 64: "file_name:stub"}
            result = reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            self.assertEqual([item["sha256"] for item in result["changed"]],
                             ["a" * 64])
            self.assertEqual(result["skipped"], {})

    def test_manual_flag_wins_over_valid_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "verified",
                       config={"hosts": ["x.example"]})
            manual = {"a" * 64: "server_panel_in_dnspy"}
            result = reference_only.apply_flags(root, {}, manual, {},
                                                dry_run=False)
            self.assertEqual(len(result["changed"]), 1)
            fields = json.loads(
                (root / "Labels" / f"{'a' * 64}.json").read_text())["fields"]
            self.assertEqual(fields["scope_reason"], "server_panel_in_dnspy")

    def test_auto_flag_is_restored_when_client_evidence_appears(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "reference_only",
                       config={"hosts": ["x.example"]},
                       directory="Aggregated", previous_status="verified",
                       scope_reason="file_name:stub")
            auto = {"a" * 64: "file_name:stub"}
            result = reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            self.assertEqual(result["changed"], [])
            self.assertEqual([item["restored_status"] for item in result["restored"]],
                             ["verified"])
            fields = json.loads(
                (root / "Aggregated" / f"{'a' * 64}.json").read_text())["fields"]
            self.assertEqual(fields["lbl_sts"], "verified")
            self.assertNotIn("scope_reason", fields)

    def test_auto_flag_stays_when_still_suspicious(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "reference_only", directory="Labels",
                       previous_status="verified", scope_reason="file_name:stub")
            auto = {"a" * 64: "file_name:stub"}
            result = reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            self.assertEqual(result["restored"], [])
            self.assertEqual(result["skipped"], {"already_flagged": 1})

    def test_rerun_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "verified")
            auto = {"a" * 64: "file_name:builder"}
            reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            result = reference_only.apply_flags(root, auto, {}, {}, dry_run=False)
            self.assertEqual(result["changed"], [])
            self.assertEqual(result["skipped"], {"already_flagged": 1})

    def test_manual_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "manual.txt"
            path.write_text("# comment\n" + "a" * 64 + " server_in_dnspy\n",
                            encoding="utf-8")
            flags = reference_only.manual_flags(path)
            self.assertEqual(flags, {"a" * 64: "server_in_dnspy"})

    def test_ledger_names_reader(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "samples.db"
            conn = sqlite3.connect(path)
            try:
                conn.execute("CREATE TABLE downloads (sha256_hash TEXT, api_file_name TEXT)")
                conn.execute("INSERT INTO downloads VALUES ('a', 'x.exe')")
                conn.commit()
            finally:
                conn.close()
            self.assertEqual(reference_only.ledger_names(path), {"a": "x.exe"})


if __name__ == "__main__":
    unittest.main()

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


def make_label(root: Path, sha: str, status: str) -> Path:
    path = root / "Labels" / f"{sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 1, "sha256": sha, "kind": "label",
        "producer": "labeler", "fields": {"sha256": sha, "lbl_sts": status},
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
            flags = {"a" * 64: "file_name:server", "b" * 64: "file_name:server"}
            result = reference_only.apply_flags(root, flags, {}, dry_run=False)
            self.assertEqual([item["sha256"] for item in result["changed"]],
                             ["a" * 64])
            self.assertEqual(result["skipped"], {"status:benign": 1})
            fields = json.loads(
                (root / "Labels" / f"{'a' * 64}.json").read_text())["fields"]
            self.assertEqual(fields["lbl_sts"], "reference_only")
            self.assertEqual(fields["previous_status"], "verified")

    def test_rerun_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            make_label(root, "a" * 64, "verified")
            flags = {"a" * 64: "file_name:builder"}
            reference_only.apply_flags(root, flags, {}, dry_run=False)
            result = reference_only.apply_flags(root, flags, {}, dry_run=False)
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

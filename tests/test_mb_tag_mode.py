#!/usr/bin/env python3
"""Synthetic tests for MB tag modes and signature backfill."""

from __future__ import annotations

import sqlite3
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from contextlib import redirect_stdout  # noqa: E402
from io import StringIO  # noqa: E402
import tempfile  # noqa: E402

from Tools.MBDownloader.mb_downloader import (  # noqa: E402
    backfill_signature,
    check_ledger,
    composite_tag,
    init_main_db,
    sample_passes,
)


class TagModeTests(unittest.TestCase):
    def test_exact_mode(self):
        self.assertTrue(sample_passes("AsyncRAT,exe", "AsyncRAT", "exe"))
        self.assertFalse(sample_passes("AsyncRAT,exe,upx", "AsyncRAT", "exe"))

    def test_contains_mode(self):
        self.assertTrue(sample_passes("AsyncRAT,exe,upx", "AsyncRAT", "exe",
                                      tag_mode="contains"))
        self.assertFalse(sample_passes("AsyncRAT,exe,xworm", "AsyncRAT", "exe",
                                       tag_mode="contains"))
        self.assertFalse(sample_passes("AsyncRAT,exe,dcrat", "AsyncRAT", "exe",
                                       tag_mode="contains"))
        self.assertTrue(sample_passes("AsyncRAT,exe,rat", "AsyncRAT", "exe",
                                      tag_mode="contains"))

    def test_contains_requires_file_type(self):
        self.assertFalse(sample_passes("AsyncRAT,upx", "AsyncRAT", "exe",
                                       tag_mode="contains"))

    def test_composite_tag(self):
        self.assertEqual(composite_tag("AsyncRAT", "", False, "contains"),
                         "AsyncRAT,contains")


class SignatureBackfillTests(unittest.TestCase):
    def test_backfill_from_poll_cache(self):
        conn = sqlite3.connect(":memory:")
        try:
            conn.execute("CREATE TABLE downloads (sha256_hash TEXT, signature TEXT)")
            conn.execute("CREATE TABLE poll_cache (sha256_hash TEXT, signature TEXT)")
            conn.execute("INSERT INTO downloads VALUES ('a', NULL)")
            conn.execute("INSERT INTO poll_cache VALUES ('a', 'AsyncRAT')")
            backfill_signature(conn)
            value = conn.execute("SELECT signature FROM downloads").fetchone()[0]
            self.assertEqual(value, "AsyncRAT")
        finally:
            conn.close()


class LedgerCheckTests(unittest.TestCase):
    def test_missing_rows_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = sqlite3.connect(":memory:")
            try:
                init_main_db(conn)
                conn.execute("INSERT INTO downloads (sha256_hash) VALUES ('a')")
                conn.commit()
                (root / "a.exe").write_bytes(b"a")
                (root / "b.exe").write_bytes(b"b")
                buffer = StringIO()
                with redirect_stdout(buffer):
                    check_ledger(conn, root, "exe")
                output = buffer.getvalue()
                self.assertIn("1 files on disk have no ledger row", output)
                self.assertIn("  b", output)
            finally:
                conn.close()

    def test_consistent_ledger_reports_ok(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            conn = sqlite3.connect(":memory:")
            try:
                init_main_db(conn)
                conn.execute("INSERT INTO downloads (sha256_hash) VALUES ('a')")
                conn.commit()
                (root / "a.exe").write_bytes(b"a")
                buffer = StringIO()
                with redirect_stdout(buffer):
                    check_ledger(conn, root, "exe")
                self.assertIn("LEDGER  ok", buffer.getvalue())
            finally:
                conn.close()

    def test_rejected_table_exists(self):
        conn = sqlite3.connect(":memory:")
        try:
            init_main_db(conn)
            tables = {row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            self.assertIn("downloads_rejected", tables)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

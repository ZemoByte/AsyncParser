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

from Tools.MBDownloader.mb_downloader import (  # noqa: E402
    backfill_signature,
    composite_tag,
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


if __name__ == "__main__":
    unittest.main()

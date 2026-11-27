#!/usr/bin/env python3
"""Synthetic tests for the benign collector. No network, no real samples."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from pe_fixtures import make_pe  # noqa: E402
from Tools.BenignCollect.collect import (  # noqa: E402
    append_sources_csv,
    dedupe_candidates,
    iter_zip_candidates,
    select_candidates,
)


class BenignCollectTests(unittest.TestCase):
    def _zip(self, path: Path) -> None:
        big = make_pe(True) + b"\x00" * 100_000
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("small.exe", make_pe(True))
            archive.writestr("big.exe", big)
            archive.writestr("native.exe", make_pe(False))
            archive.writestr("big.dll", make_pe(True))
            archive.writestr("readme.txt", "not a PE")

    def test_zip_candidates_filter_and_preference(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "fake.nupkg"
            self._zip(archive)
            candidates = iter_zip_candidates(
                archive, "nuget", "https://example.invalid/fake.nupkg", "test",
                "nuget", "any", 0)
            names = {item["name"] for item in candidates}
            self.assertEqual(names, {"small.exe", "big.exe", "big.dll"})
            selected = select_candidates(candidates, limit=2)
            self.assertEqual([item["name"] for item in selected], ["big.exe", "small.exe"])

    def test_dedupe_against_existing(self):
        candidates = [{
            "name": "a.exe", "ext": ".exe", "data": b"a", "sha256": "a" * 64,
            "size": 1, "source": "test", "url": "u", "license": "l",
        }]
        unique, duplicates, existing_count = dedupe_candidates(candidates, {"a" * 64})
        self.assertEqual(unique, [])
        self.assertEqual(duplicates, 1)
        self.assertEqual(existing_count, 1)

    def test_csv_append_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "sources.csv"
            row = {
                "sha256": "b" * 64, "source": "nuget", "origin": "nuget",
                "ext": ".exe", "url": "u", "license": "l", "size": 10,
                "collected_at": "2026-01-01T00:00:00+00:00",
            }
            self.assertEqual(append_sources_csv(path, [row]), 1)
            self.assertEqual(append_sources_csv(path, [row]), 0)
            with path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["sha256"], "b" * 64)


if __name__ == "__main__":
    unittest.main()

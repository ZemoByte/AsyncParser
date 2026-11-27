#!/usr/bin/env python3
"""Synthetic tests for the MalwareBazaar full-export selection path."""

from __future__ import annotations

import hashlib
import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

import tlsh

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.MBDownloader import mb_downloader  # noqa: E402

HEADER = ('# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",'
          '"file_name","file_type_guess","mime_type","signature","clamav",'
          '"vtpercent","imphash","ssdeep","tlsh"')


def tlsh_of(seed: str) -> str:
    data = b"".join(hashlib.sha256(f"{seed}:{index}".encode()).digest()
                    for index in range(200))
    value = tlsh.hash(data)
    if value == "TNULL":
        raise RuntimeError("synthetic TLSH failed")
    return value


def row(first_seen: str, sha: str, name: str, kind: str, signature: str,
        tlsh_value: str) -> str:
    return (f'"{first_seen}", "{sha}", "md5", "sha1", "abuse_ch", "{name}", '
            f'"{kind}", "mime", "{signature}", "n/a", "n/a", "imp", "ss", '
            f'"{tlsh_value}"')


class ExportZipTests(unittest.TestCase):
    def make_zip(self, rows: list[str]) -> Path:
        directory = tempfile.mkdtemp()
        path = Path(directory) / "full.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("full.csv", "\r\n".join(
                ["####", "# preamble", HEADER] + rows) + "\r\n")
        return path

    def test_rows_are_normalized(self):
        sha = "a" * 64
        path = self.make_zip([row("2021-05-01 10:00:00", sha, "x.exe", "exe",
                                  "AsyncRAT", tlsh_of("a"))])
        rows = list(mb_downloader.iter_export_rows(path))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["sha256_hash"], sha)
        self.assertEqual(rows[0]["file_name"], "x.exe")
        self.assertEqual(rows[0]["signature"], "AsyncRAT")
        self.assertEqual(rows[0]["first_seen_utc"], "2021-05-01 10:00:00")

    def test_candidate_filters(self):
        good = tlsh_of("good")
        path = self.make_zip([
            row("2020-01-01 00:00:00", "1" * 64, "a.exe", "exe", "AsyncRAT", good),
            row("2020-01-02 00:00:00", "2" * 64, "b.exe", "exe", "AsyncRat", good),
            row("2020-01-03 00:00:00", "3" * 64, "c.dll", "dll", "AsyncRAT", good),
            row("2020-01-04 00:00:00", "4" * 64, "d.exe", "exe", "XWorm", good),
            row("2020-01-05 00:00:00", "5" * 64, "e.exe", "exe", "AsyncRAT", "TNA"),
        ])
        result = mb_downloader.export_candidates(
            path, ledger={"2" * 64}, selected={"3" * 64}, years=[2020])
        stats = result["stats"]
        self.assertEqual((stats["rows"], stats["signature"], stats["exe"]), (5, 4, 3))
        self.assertEqual(stats["ledger"], 1)
        self.assertEqual(stats["manifest"], 0)
        self.assertEqual(stats["tlsh_missing"], 1)
        self.assertEqual([item["sha256"] for item in result["by_year"][2020]],
                         ["1" * 64])

    def test_year_range(self):
        self.assertEqual(mb_downloader.parse_years("2020-2022"), [2020, 2021, 2022])
        self.assertEqual(mb_downloader.parse_years("2020,2022"), [2020, 2022])


class SelectionTests(unittest.TestCase):
    def candidate(self, sha: str, first_seen: str, tlsh_value: str) -> dict:
        return {"sha256": sha, "year": 2020, "first_seen": first_seen,
                "tlsh": tlsh_value, "file_name": f"{sha}.exe"}

    def test_per_year_cap_and_order(self):
        rows = {
            2020: [self.candidate("b" * 64, "2020-02-01", tlsh_of("b")),
                   self.candidate("a" * 64, "2020-01-01", tlsh_of("a"))],
            2021: [self.candidate("c" * 64, "2021-01-01", tlsh_of("c"))],
        }
        result = mb_downloader.select_export_batch(rows, [], per_year=1,
                                                   threshold=0, limit=0)
        self.assertEqual([item["sha256"] for item in result["selected"]],
                         ["a" * 64, "c" * 64])
        self.assertEqual(result["per_year"], {2020: 1, 2021: 1})

    def test_near_duplicate_is_rejected(self):
        same = tlsh_of("same")
        rows = {2020: [self.candidate("a" * 64, "2020-01-01", same),
                       self.candidate("b" * 64, "2020-01-02", same)]}
        result = mb_downloader.select_export_batch(rows, [], per_year=50,
                                                   threshold=100, limit=0)
        self.assertEqual([item["sha256"] for item in result["selected"]],
                         ["a" * 64])
        self.assertEqual(result["rejected"], [("b" * 64, "tlsh_reject")])

    def test_manifest_anchors_exclude_previous_batch(self):
        first = tlsh_of("first")
        second = tlsh_of("second")
        rows = {2020: [self.candidate("a" * 64, "2020-01-01", first),
                       self.candidate("b" * 64, "2020-01-02", second)]}
        result = mb_downloader.select_export_batch(rows, [first], per_year=50,
                                                   threshold=100, limit=0)
        self.assertEqual([item["sha256"] for item in result["selected"]],
                         ["b" * 64])

    def test_limit_stops_selection(self):
        rows = {year: [self.candidate(f"{year}{index}" + "0" * 60,
                                      f"{year}-01-0{index}",
                                      tlsh_of(f"{year}{index}"))]
                for year in (2020, 2021) for index in (1, 2)}
        result = mb_downloader.select_export_batch(rows, [], per_year=5,
                                                   threshold=0, limit=2)
        self.assertEqual(len(result["selected"]), 2)


class ManifestTests(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "selection.json"
            payload = {"schema_version": 1,
                       "entries": [{"sha256": "a" * 64, "status": "selected"}],
                       "runs": [{"batch": 1}]}
            mb_downloader.save_selection_manifest(path, payload)
            loaded = mb_downloader.load_selection_manifest(path)
            self.assertEqual(loaded["entries"], payload["entries"])
            self.assertEqual(loaded["runs"], payload["runs"])

    def test_missing_manifest_is_empty(self):
        with tempfile.TemporaryDirectory() as directory:
            loaded = mb_downloader.load_selection_manifest(
                Path(directory) / "absent.json")
            self.assertEqual(loaded["entries"], [])


if __name__ == "__main__":
    unittest.main()

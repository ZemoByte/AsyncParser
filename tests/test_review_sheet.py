#!/usr/bin/env python3
"""Synthetic tests for SHA-256 based gold-sheet path resolution."""

from __future__ import annotations

import csv
import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Gold import review_sheet  # noqa: E402
from Tools._label_common import GOLD_COLUMNS  # noqa: E402

SOURCE_COLUMNS = ("sha256", "source", "origin", "ext", "url", "license",
                  "size", "collected_at", "status")


def sha_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write_gold(data_root: Path, shas: list[str]) -> None:
    path = data_root / "Gold" / "gold.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(GOLD_COLUMNS),
                                lineterminator="\n")
        writer.writeheader()
        for sha in shas:
            writer.writerow({"sha256": sha, "cluster_id": f"c-{sha[:8]}",
                             "current_status": "benign", "current_family": ""})


def write_gold_rows(data_root: Path, rows: list[dict]) -> None:
    path = data_root / "Gold" / "gold.csv"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(GOLD_COLUMNS),
                                lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in GOLD_COLUMNS})


def write_dataset_db(data_root: Path, rows: list[tuple[str, str, str]]) -> None:
    path = data_root / "DataSet.db"
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE dataset (sha256 TEXT, lbl_sts TEXT, "
                     "sug_fam TEXT)")
        conn.executemany("INSERT INTO dataset VALUES (?, ?, ?)", rows)
        conn.commit()
    finally:
        conn.close()


def write_sources(data_root: Path, rows: list[dict]) -> Path:
    path = data_root / "BenignSources.csv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SOURCE_COLUMNS),
                                lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    return path


class ReviewSheetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "Data"
        self.samples = self.root / "Samples"
        for class_name in review_sheet.SAMPLE_DIRS:
            (self.samples / class_name).mkdir(parents=True)

    def tearDown(self):
        self.temp.cleanup()

    def test_friendly_name_is_found_by_hash(self):
        data = b"fixture-friendly-bytes"
        sha = sha_of(data)
        (self.samples / "Benign" / "FriendlyName.exe").write_bytes(data)
        write_gold(self.data, [sha])
        sources = write_sources(self.data, [{"sha256": sha, "source": "fixture",
                                             "origin": "fixture"}])
        rows, duplicates = review_sheet.build_rows(self.data, self.samples,
                                                   sources)
        self.assertEqual(len(rows), 1)
        self.assertEqual(Path(rows[0]["file_path"]).name, "FriendlyName.exe")
        self.assertEqual(rows[0]["sample_class"], "Benign")
        self.assertEqual(rows[0]["sample_origin"], "fixture")
        self.assertEqual(rows[0]["sample_source"], "fixture")
        self.assertEqual(duplicates, [])

    def test_current_labels_come_from_dataset_db(self):
        sha = "1" * 64
        write_gold_rows(self.data, [{
            "sha256": sha, "cluster_id": "c-1",
            "current_status": "verified", "current_family": "",
        }])
        write_dataset_db(self.data, [(sha, "unverified", "QuasarRAT")])
        sources = write_sources(self.data, [])
        rows, _ = review_sheet.build_rows(self.data, self.samples, sources)
        self.assertEqual(rows[0]["current_status"], "unverified")
        self.assertEqual(rows[0]["current_family"], "QuasarRAT")
        self.assertEqual(rows[0]["gold_snapshot_status"], "verified")
        self.assertEqual(rows[0]["gold_snapshot_family"], "")

    def test_verified_current_family_is_asyncrat(self):
        sha = "2" * 64
        write_gold_rows(self.data, [{
            "sha256": sha, "cluster_id": "c-2",
            "current_status": "unverified", "current_family": "XWorm",
        }])
        write_dataset_db(self.data, [(sha, "verified", "")])
        sources = write_sources(self.data, [])
        rows, _ = review_sheet.build_rows(self.data, self.samples, sources)
        self.assertEqual(rows[0]["current_status"], "verified")
        self.assertEqual(rows[0]["current_family"], "AsyncRAT")
        self.assertEqual(rows[0]["gold_snapshot_status"], "unverified")
        self.assertEqual(rows[0]["gold_snapshot_family"], "XWorm")

    def test_absent_hash_stays_missing(self):
        absent = "f" * 64
        write_gold(self.data, [absent])
        sources = write_sources(self.data, [])
        rows, _ = review_sheet.build_rows(self.data, self.samples, sources)
        self.assertEqual(rows[0]["file_path"], "")
        self.assertEqual(rows[0]["sample_class"], "")
        self.assertEqual(rows[0]["sample_origin"], "unknown")
        self.assertEqual(rows[0]["file_size"], "")

    def test_origin_defaults_are_not_guessed(self):
        data = b"benign-unlisted"
        sha = sha_of(data)
        (self.samples / "Benign" / "unlisted.exe").write_bytes(data)
        write_gold(self.data, [sha])
        sources = write_sources(self.data, [])
        rows, _ = review_sheet.build_rows(self.data, self.samples, sources)
        self.assertEqual(rows[0]["sample_class"], "Benign")
        self.assertEqual(rows[0]["sample_origin"], "unknown")
        self.assertEqual(rows[0]["sample_source"], "Benign")

    def test_duplicate_precedence_is_deterministic(self):
        data = b"same-bytes-in-two-dirs"
        sha = sha_of(data)
        (self.samples / "Benign" / "friendly.exe").write_bytes(data)
        (self.samples / "AsyncRAT" / "copy.exe").write_bytes(data)
        write_gold(self.data, [sha])
        sources = write_sources(self.data, [{"sha256": sha, "source": "fixture",
                                             "origin": "fixture"}])
        rows, duplicates = review_sheet.build_rows(self.data, self.samples,
                                                   sources)
        self.assertEqual(rows[0]["sample_class"], "AsyncRAT")
        self.assertEqual(Path(rows[0]["file_path"]).name, "copy.exe")
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(len(duplicates[0]["paths"]), 2)

    def test_fast_path_requires_matching_hash(self):
        data = b"real-content"
        sha = sha_of(data)
        (self.samples / "OtherMalwares" / f"{sha}.exe").write_bytes(b"wrong")
        (self.samples / "OtherMalwares" / "actual.exe").write_bytes(data)
        index, duplicates = review_sheet.build_sample_index(
            self.samples, {sha})
        self.assertEqual(Path(index[sha][1]).name, "actual.exe")
        self.assertEqual(duplicates, [])


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Synthetic tests for the gold-review merge tool."""

from __future__ import annotations

import csv
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Gold.merge_gold_review import (  # noqa: E402
    GOLD_COLUMNS,
    merge_gold,
)


def sha(index: int) -> str:
    return f"{index:064x}"


def write_csv(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(GOLD_COLUMNS),
                                lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "")
                             for column in GOLD_COLUMNS})


def gold_rows(filled: dict[int, str] | None = None) -> list[dict]:
    rows = []
    for index in range(30):
        rows.append({"sha256": sha(index), "cluster_id": f"c{index}",
                     "current_status": "verified", "current_family": "",
                     "gold_status": (filled or {}).get(index, "")})
    return rows


class MergeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.gold = self.root / "gold.csv"
        self.review = self.root / "review.csv"

    def tearDown(self):
        self.temp.cleanup()

    def test_dry_run_does_not_write(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[0]["gold_status"] = "verified"
        review[0]["gold_family"] = "AsyncRAT"
        write_csv(self.review, review)
        before = self.gold.read_text()
        result = merge_gold(self.gold, self.review, write=False)
        self.assertEqual(result["errors"], [])
        self.assertFalse(result["written"])
        self.assertEqual(result["filled"], 1)
        self.assertEqual(result["blank"], 29)
        self.assertEqual(self.gold.read_text(), before)

    def test_write_applies_only_filled_rows(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[0].update({"gold_status": "verified",
                          "gold_family": "AsyncRAT",
                          "confidence": "high", "analyst": "tester",
                          "date": "2026-11-28", "notes": "client",
                          "evidence": "config keys"})
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertTrue(result["written"])
        with self.gold.open(encoding="utf-8") as handle:
            merged = list(csv.DictReader(handle))
        self.assertEqual(merged[0]["gold_status"], "verified")
        self.assertEqual(merged[0]["gold_family"], "AsyncRAT")
        self.assertEqual(merged[0]["confidence"], "high")
        self.assertEqual(merged[1]["gold_status"], "")
        self.assertFalse(list(self.root.glob("*.tmp")))

    def test_existing_verdict_is_not_overwritten(self):
        write_csv(self.gold, gold_rows({3: "verified"}))
        review = gold_rows()
        review[3]["gold_status"] = "reference_only"
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertEqual(result["skipped_existing"], 1)
        with self.gold.open(encoding="utf-8") as handle:
            merged = list(csv.DictReader(handle))
        self.assertEqual(merged[3]["gold_status"], "verified")

    def test_force_overwrites(self):
        write_csv(self.gold, gold_rows({3: "verified"}))
        review = gold_rows()
        review[3]["gold_status"] = "reference_only"
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True, force=True)
        self.assertEqual(result["skipped_existing"], 0)
        with self.gold.open(encoding="utf-8") as handle:
            merged = list(csv.DictReader(handle))
        self.assertEqual(merged[3]["gold_status"], "reference_only")

    def test_duplicate_review_rows_are_rejected(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[1]["sha256"] = review[0]["sha256"]
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertTrue(any("duplicate" in error for error in result["errors"]))
        self.assertFalse(result["written"])

    def test_unknown_status_is_rejected(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[0]["gold_status"] = "probably_malware"
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertEqual(result["unknown_status"], 1)
        self.assertFalse(result["written"])

    def test_verified_other_requires_family(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[0]["gold_status"] = "verified_other"
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertEqual(result["unknown_family"], 1)
        self.assertFalse(result["written"])

    def test_unknown_family_is_rejected(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[0]["gold_status"] = "verified_other"
        review[0]["gold_family"] = "AsyncRAT2"
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertEqual(result["unknown_family"], 1)

    def test_sha_not_in_gold_is_rejected(self):
        write_csv(self.gold, gold_rows())
        review = gold_rows()
        review[0]["sha256"] = "f" * 64
        write_csv(self.review, review)
        result = merge_gold(self.gold, self.review, write=True)
        self.assertTrue(any("not in gold" in error
                            for error in result["errors"]))

    def test_wrong_row_count_is_rejected(self):
        write_csv(self.gold, gold_rows())
        write_csv(self.review, gold_rows()[:-1])
        result = merge_gold(self.gold, self.review, write=True)
        self.assertTrue(any("expected 30" in error for error in result["errors"]))


if __name__ == "__main__":
    unittest.main()

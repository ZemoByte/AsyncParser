#!/usr/bin/env python3
"""Synthetic tests for vocabulary, matrix alignment and primary-row filtering."""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

import numpy as np

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Features.build_matrix import (  # noqa: E402
    STRUCTURAL_FEATURES,
    build_arrays,
    build_vocab,
)
from Tools.Splits.split import read_rows  # noqa: E402


def struct_fields(value=1.0):
    return {name.replace("structure_", "", 1): value for name in STRUCTURAL_FEATURES}


class MatrixTests(unittest.TestCase):
    def test_vocab_uses_train_clusters_only(self):
        rows = [
            {"sha256": "a", "cluster_id": "c1", "label": "positive"},
            {"sha256": "b", "cluster_id": "c2", "label": "positive"},
            {"sha256": "c", "cluster_id": "c3", "label": "negative"},
            {"sha256": "d", "cluster_id": "c4", "label": "negative"},
        ]
        carved = {
            "a": {"TypeRef": {"A", "B"}},
            "b": {"TypeRef": {"A"}},
            "c": {"TypeRef": {"A", "C"}},
            "d": {"TypeRef": {"D"}},
        }
        vocab, counts = build_vocab(rows[:2], carved, min_clusters=2)
        self.assertEqual(vocab, ["A"])
        self.assertEqual(counts, {"A": 2})
        self.assertNotIn("B", vocab)
        self.assertNotIn("C", vocab)
        self.assertNotIn("D", vocab)

    def test_arrays_align_and_no_nan(self):
        rows = [
            {"sha256": "a", "cluster_id": "c1", "label": "positive"},
            {"sha256": "b", "cluster_id": "c2", "label": "negative"},
        ]
        splits = {"a": "train", "b": "test"}
        carved = {"a": {"TypeRef": {"A"}}, "b": {"TypeRef": {"B"}}}
        structure = {sha: struct_fields() for sha in ("a", "b")}
        arrays = build_arrays(rows, splits, carved, structure, ["A", "B"])
        self.assertEqual(arrays["presence"].shape, (2, 2))
        self.assertEqual(arrays["structural"].shape, (2, len(STRUCTURAL_FEATURES)))
        self.assertEqual(len(arrays["y"]), 2)
        self.assertEqual(len(arrays["groups"]), 2)
        self.assertEqual(len(arrays["sha256"]), 2)
        self.assertTrue(np.isfinite(arrays["structural"]).all())
        self.assertEqual(arrays["y"].tolist(), [1, 0])

    def test_primary_rows_exclude_other_labels_and_fixtures(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Labels").mkdir()
            (root / "Aggregated").mkdir()
            conn = sqlite3.connect(root / "DataSet.db")
            conn.execute(
                "CREATE TABLE dataset (sha256 TEXT, lbl_sts TEXT, cluster_id TEXT, "
                "first_seen TEXT, is_gold INTEGER)"
            )
            rows = [
                ("v", "verified", "c1", "2026-01-01", 0),
                ("o", "verified_other", "c2", "2026-01-02", 0),
                ("b", "benign", "c3", "2026-01-03", 0),
                ("f", "benign", "c4", "2026-01-04", 0),
                ("d", "benign", "c5", "2026-01-05", 0),
                ("u", "unverified", "c6", "2026-01-06", 0),
                ("r", "review", "c7", "2026-01-07", 0),
                ("x", "rejected_non_dotnet", "c8", "2026-01-08", 0),
            ]
            conn.executemany("INSERT INTO dataset VALUES (?,?,?,?,?)", rows)
            conn.commit()
            conn.close()
            for sha in ("v", "o", "b", "f", "d", "u", "r", "x"):
                fields = {"lbl_sts": "benign", "origin": "github", "kind": "exe"}
                if sha == "f":
                    fields["origin"] = "fixture"
                if sha == "d":
                    fields["kind"] = "dll"
                if sha in ("v", "o"):
                    fields = {"lbl_sts": "verified" if sha == "v" else "verified_other"}
                (root / "Labels" / f"{sha}.json").write_text(json.dumps({
                    "schema_version": 1, "sha256": sha, "kind": "label",
                    "producer": "test", "fields": fields,
                }))
            selected, _ = read_rows(root)
            shas = {row["sha256"] for row in selected}
            self.assertEqual(shas, {"v", "o", "b"})


if __name__ == "__main__":
    unittest.main()

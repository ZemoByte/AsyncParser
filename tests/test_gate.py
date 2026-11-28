#!/usr/bin/env python3
"""Synthetic tests for the single dataset gate implementation."""

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

from Tools._gate import evaluate_gate  # noqa: E402


def make_root() -> Path:
    root = Path(tempfile.mkdtemp())
    conn = sqlite3.connect(root / "DataSet.db")
    conn.execute(
        "CREATE TABLE dataset (sha256 TEXT PRIMARY KEY, lbl_sts TEXT, "
        "sug_fam TEXT, target_class_db TEXT, cluster_id TEXT, is_gold INTEGER)")
    conn.commit()
    conn.close()
    return root


def add_rows(root: Path, rows: list[tuple]) -> None:
    conn = sqlite3.connect(root / "DataSet.db")
    conn.executemany(
        "INSERT INTO dataset (sha256, lbl_sts, sug_fam, target_class_db, "
        "cluster_id, is_gold) VALUES (?, ?, ?, ?, ?, ?)", rows)
    conn.commit()
    conn.close()


def add_label(root: Path, sha: str, status: str, source: str = "dike",
              origin: str = "github", kind: str = "exe") -> None:
    path = root / "Labels" / f"{sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 1, "sha256": sha, "kind": "label",
        "fields": {"sha256": sha, "lbl_sts": status, "source": source,
                   "origin": origin, "kind": kind},
    }), encoding="utf-8")


def positive_rows(clusters: list[int], status: str = "verified",
                  family: str = "", target: str = "AsyncRAT.db",
                  prefix: str = "p") -> list[tuple]:
    rows = []
    index = 0
    for cluster_index, size in enumerate(clusters):
        for _ in range(size):
            sha = f"{prefix}{index:04d}"
            rows.append((sha, status, family, target, f"c{cluster_index}", 0))
            index += 1
    return rows


def benign_rows(clusters: list[int], source: str = "dike",
                origin: str = "github", prefix: str = "b") -> list[tuple]:
    rows = []
    index = 0
    for cluster_index, size in enumerate(clusters):
        for _ in range(size):
            sha = f"{prefix}{index:04d}"
            rows.append((sha, "benign", "Benign", "Benign.db",
                         f"bc{cluster_index}", 0))
            index += 1
    return rows


class GateTests(unittest.TestCase):
    def test_asyncrat_three_clusters_fails(self):
        root = make_root()
        add_rows(root, positive_rows([11, 5, 3], prefix="a"))
        gate = evaluate_gate(root)
        stats = gate["stage1"]["asyncrat"]
        self.assertEqual(stats["clusters"], 3)
        self.assertAlmostEqual(stats["share"], 57.9, places=1)
        self.assertFalse(stats["ok"])

    def test_asyncrat_ten_clusters_passes(self):
        root = make_root()
        add_rows(root, positive_rows([10, 3, 3, 3, 1, 1, 1, 1, 1, 1],
                                     prefix="a"))
        stats = evaluate_gate(root)["stage1"]["asyncrat"]
        self.assertEqual(stats["clusters"], 10)
        self.assertAlmostEqual(stats["share"], 40.0, places=1)
        self.assertTrue(stats["ok"])

    def test_xworm_two_clusters_fails_stage2(self):
        root = make_root()
        add_rows(root, positive_rows([10, 3, 3, 3, 1, 1, 1, 1, 1, 1],
                                     prefix="a"))
        add_rows(root, positive_rows([7, 2], status="verified_other",
                                     family="XWorm", target="OtherMalwares.db",
                                     prefix="x"))
        gate = evaluate_gate(root)
        self.assertTrue(gate["stage2"]["families"]["XWorm"]["clusters"] == 2)
        self.assertFalse(gate["stage2"]["families"]["XWorm"]["ok"])
        self.assertFalse(gate["stage2"]["ok"])

    def test_benign_uses_active_only_and_ignores_holdout(self):
        root = make_root()
        # 139 active rows, 20 clusters, largest 19 (13.7%).
        active = [19] + [7] * 6 + [6] * 13
        holdout = [565]
        rows = benign_rows(active)
        rows += benign_rows(holdout, source="clrheader2023", origin="github",
                            prefix="h")
        rows += benign_rows([10], source="fixture", origin="fixture",
                            prefix="f")
        add_rows(root, rows)
        for row in rows:
            sha = row[0]
            if sha.startswith("h"):
                add_label(root, sha, "benign", source="clrheader2023")
            elif sha.startswith("f"):
                add_label(root, sha, "benign", source="fixture")
            else:
                add_label(root, sha, "benign")
        stats = evaluate_gate(root)["stage1"]["benign"]
        self.assertEqual(stats["rows"], 139)
        self.assertEqual(stats["clusters"], 20)
        self.assertAlmostEqual(stats["share"], 13.7, places=1)
        self.assertTrue(stats["ok"])

    def test_missing_family_fails_without_crash(self):
        root = make_root()
        add_rows(root, positive_rows([10, 3, 3, 3, 1, 1, 1, 1, 1, 1],
                                     prefix="a"))
        gate = evaluate_gate(root)
        self.assertFalse(gate["stage2"]["ok"])
        self.assertNotIn("XWorm", gate["stage2"]["families"])

    def test_gold_rows_do_not_count(self):
        root = make_root()
        rows = positive_rows([10, 3, 3, 3, 1, 1, 1, 1, 1, 1], prefix="a")
        rows[0] = (rows[0][0], rows[0][1], rows[0][2], rows[0][3],
                   rows[0][4], 1)
        add_rows(root, rows)
        stats = evaluate_gate(root)["stage1"]["asyncrat"]
        self.assertEqual(stats["rows"], 24)


if __name__ == "__main__":
    unittest.main()

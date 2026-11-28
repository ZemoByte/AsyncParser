#!/usr/bin/env python3
"""Synthetic test: the report warns when cluster JSONs disagree with the DB."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class ClusterCountWarningTests(unittest.TestCase):
    def test_stale_cluster_json_warns(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Data"
            root.mkdir()
            conn = sqlite3.connect(root / "DataSet.db")
            conn.execute(
                "CREATE TABLE dataset (sha256 TEXT PRIMARY KEY, lbl_sts TEXT, "
                "sug_fam TEXT, target_class_db TEXT, cluster_id TEXT, "
                "is_dotnet INTEGER, lbl_src TEXT, is_gold INTEGER)")
            conn.execute(
                "INSERT INTO dataset VALUES ('a' * 64, 'verified', '', "
                "'AsyncRAT.db', 'c1', 1, 'auto_aggregator', 0)")
            conn.commit()
            conn.close()
            clusters = root / "Clusters"
            clusters.mkdir()
            for sha, cluster_id in (("a" * 64, "c1"), ("b" * 64, "c2")):
                (clusters / f"{sha}.json").write_text(json.dumps({
                    "schema_version": 1, "sha256": sha, "kind": "cluster",
                    "fields": {"cluster_id": cluster_id, "tlsh": ""}}))
                labels = root / "Labels"
                labels.mkdir(exist_ok=True)
                (labels / f"{sha}.json").write_text(json.dumps({
                    "schema_version": 1, "sha256": sha, "kind": "label",
                    "fields": {"sha256": sha, "lbl_sts": "verified",
                               "sug_fam": ""}}))
            samples = Path(directory) / "Samples"
            samples.mkdir()
            proc = subprocess.run(
                [sys.executable, "Tools/Report/dataset_report.py",
                 "--data-root", str(root), "--samples-root", str(samples),
                 "--out", str(Path(directory) / "Reports" / "report.md")],
                cwd=REPO, capture_output=True, text=True, check=False)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("WARNING: cluster JSON count 2 != dataset rows 1",
                          proc.stderr)
            self.assertTrue((Path(directory) / "Reports" / "report.md").is_file())


if __name__ == "__main__":
    unittest.main()

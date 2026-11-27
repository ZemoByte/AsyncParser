#!/usr/bin/env python3
"""Synthetic tests for labeler --benign-only. No ledger, no parser, no samples."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from pe_fixtures import make_pe  # noqa: E402
from Tools.Labeling import labeler  # noqa: E402


class BenignOnlyTests(unittest.TestCase):
    def test_benign_only_labels_and_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            benign_root = root / "Benign"
            benign_root.mkdir()
            net_bytes = make_pe(True)
            native_bytes = make_pe(False)
            (benign_root / "net.exe").write_bytes(net_bytes)
            (benign_root / "native.exe").write_bytes(native_bytes)
            out = root / "Data"
            labeler.benign_only(argparse.Namespace(benign_root=benign_root, out=out))

            net_sha = hashlib.sha256(net_bytes).hexdigest()
            native_sha = hashlib.sha256(native_bytes).hexdigest()
            net_label = json.loads(
                (out / "Labels" / f"{net_sha}.json").read_text())["fields"]
            native_label = json.loads(
                (out / "Labels" / f"{native_sha}.json").read_text())["fields"]
            self.assertEqual((net_label["lbl_sts"], net_label["sug_fam"]),
                             ("benign", "Benign"))
            self.assertEqual(native_label["lbl_sts"], "rejected_non_dotnet")

            net_ev = json.loads(
                (out / "Evidence" / net_sha / "rat_king_parser.json").read_text())
            native_ev = json.loads(
                (out / "Evidence" / native_sha / "rat_king_parser.json").read_text())
            self.assertEqual(net_ev["fields"]["raw"]["reason"], "benign_not_parsed")
            self.assertEqual(native_ev["fields"]["raw"]["reason"], "not_dotnet")
            marker = json.loads((out / "Labels" / ".labeler.done").read_text())
            self.assertEqual(marker["count"], 2)

            before = {path: path.read_bytes() for path in out.rglob("*") if path.is_file()}
            labeler.benign_only(argparse.Namespace(benign_root=benign_root, out=out))
            after = {path: path.read_bytes() for path in out.rglob("*") if path.is_file()}
            for path, data in before.items():
                if path.name != ".labeler.done" and path.name != ".rat_king_parser.done":
                    self.assertEqual(after[path], data)


if __name__ == "__main__":
    unittest.main()

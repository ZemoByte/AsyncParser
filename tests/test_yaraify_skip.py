#!/usr/bin/env python3
"""Synthetic tests for YARAify trivial-skip and reuse (no network)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Voters.YARAify import yaraify_voter as voter  # noqa: E402


def label(root: Path, sha: str, status: str) -> None:
    path = root / "Labels" / f"{sha}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "schema_version": 1, "sha256": sha, "kind": "label",
        "fields": {"sha256": sha, "lbl_sts": status},
    }))


def sample(root: Path, name: str) -> str:
    import hashlib
    data = b"MZ" + name.encode()
    path = root / "Samples" / "AsyncRAT" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


class SkipTrivialTests(unittest.TestCase):
    def run_voter(self, root: Path, extra: list[str], lookup):
        argv = ["yaraify_voter.py", "--samples-root", str(root / "Samples"),
                "--out", str(root / "Data"), "--delay", "0"] + extra
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.object(voter, "resolve_auth_key", return_value="x"), \
                mock.patch.object(voter, "lookup", side_effect=lookup):
            return voter.main()

    def test_benign_and_non_dotnet_do_not_call_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            benign = sample(root, "benign.exe")
            native = sample(root, "native.exe")
            label(root / "Data", benign, "benign")
            label(root / "Data", native, "rejected_non_dotnet")
            self.run_voter(root, ["--skip-trivial"], AssertionError("called"))
            for sha, reason in ((benign, "skipped_benign"),
                                (native, "skipped_non_dotnet")):
                payload = json.loads((root / "Data" / "Evidence" / sha
                                      / "yaraify.json").read_text())
                fields = payload["fields"]
                self.assertEqual(fields["verdict"], "no_match")
                self.assertEqual(fields["raw"]["reason"], reason)
                self.assertEqual(fields["raw"]["query_status"], "skipped")

    def test_verified_still_calls_api(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = sample(root, "verified.exe")
            label(root / "Data", sha, "verified")
            calls = []

            def lookup(*args, **kwargs):
                calls.append(args)
                return "no_match", {"strength": "weak",
                                    "raw": {"reason": "no_family"}}

            self.run_voter(root, ["--skip-trivial"], lookup)
            self.assertEqual(len(calls), 1)

    def test_no_skip_trivial_forces_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = sample(root, "benign.exe")
            label(root / "Data", sha, "benign")
            calls = []

            def lookup(*args, **kwargs):
                calls.append(args)
                return "no_match", {"strength": "weak",
                                    "raw": {"reason": "no_family"}}

            self.run_voter(root, ["--no-skip-trivial"], lookup)
            self.assertEqual(len(calls), 1)

    def test_existing_hit_is_preserved_on_skip(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sha = sample(root, "benign.exe")
            label(root / "Data", sha, "benign")
            evidence = root / "Data" / "Evidence" / sha / "yaraify.json"
            evidence.parent.mkdir(parents=True)
            evidence.write_text(json.dumps({
                "sha256": sha, "fields": {"verdict": "AsyncRAT"}}))
            self.run_voter(root, ["--skip-trivial"], AssertionError("called"))
            fields = json.loads(evidence.read_text())["fields"]
            self.assertEqual(fields["verdict"], "AsyncRAT")


if __name__ == "__main__":
    unittest.main()

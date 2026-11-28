#!/usr/bin/env python3
"""Synthetic tests for the family queue and shared-key loader."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path

import sys

REPO = Path(__file__).resolve().parents[1]
for path in (REPO, REPO / "Tools" / "Voters"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import tlsh  # noqa: E402

from Tools.MBDownloader import mb_downloader as mb  # noqa: E402
from Tools.Voters.YARAify import yaraify_voter  # noqa: E402

HEADER = ('# "first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter",'
          '"file_name","file_type_guess","mime_type","signature","clamav",'
          '"vtpercent","imphash","ssdeep","tlsh"')


def tlsh_of(seed: str) -> str:
    data = b"".join(hashlib.sha256(f"{seed}:{i}".encode()).digest()
                    for i in range(200))
    return tlsh.hash(data)


def row(first_seen: str, sha: str, name: str, kind: str, signature: str,
        tlsh_value: str) -> str:
    return (f'"{first_seen}", "{sha}", "md5", "sha1", "abuse_ch", "{name}", '
            f'"{kind}", "mime", "{signature}", "n/a", "n/a", "imp", "ss", '
            f'"{tlsh_value}"')


def families() -> list[dict]:
    return [
        {"name": "DcRat", "parent": "AsyncRAT", "aliases": ["DcRat"],
         "availability": "mb", "mb_count": 100},
        {"name": "HotRAT", "parent": "AsyncRAT", "aliases": ["HotRAT"],
         "availability": "mb", "mb_count": 3},
        {"name": "RiMAWI", "parent": "AsyncRAT", "aliases": ["RiMAWI"],
         "availability": "unavailable_mb", "mb_count": 0},
    ]


class FamilySelectionTests(unittest.TestCase):
    def test_caps_and_tlsh(self):
        same = tlsh_of("same")
        rows = {
            "DcRat": [
                {"family": "DcRat", "sha256": "a" * 64,
                 "first_seen": "2021-01-01", "tlsh": same, "source": "signature"},
                {"family": "DcRat", "sha256": "b" * 64,
                 "first_seen": "2021-01-02", "tlsh": same, "source": "signature"},
            ],
            "HotRAT": [
                {"family": "HotRAT", "sha256": "c" * 64,
                 "first_seen": "2021-01-03", "tlsh": tlsh_of("c"), "source": "tag"},
            ],
        }
        result = mb.select_family_batch(rows, {}, {"DcRat": 50, "HotRAT": 3},
                                        100, 0)
        self.assertEqual(result["per_family"], {"DcRat": 1, "HotRAT": 1})
        self.assertEqual(result["rejected"], [("b" * 64, "DcRat", "tlsh_reject")])

    def test_signature_and_filename_match(self):
        signature_map, filename_map = mb.family_maps(families())
        self.assertEqual(signature_map.get("dcrat"), "DcRat")
        self.assertEqual(mb.match_filename_family("HotRAT_client.exe", filename_map),
                         "HotRAT")
        self.assertIsNone(mb.match_filename_family("x.exe", filename_map))

    def test_export_candidates_skip_asyncrat_and_ledger(self):
        good = tlsh_of("good")
        directory = tempfile.mkdtemp()
        path = Path(directory) / "full.zip"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("full.csv", "\r\n".join([
                "####", HEADER,
                row("2021-01-01 00:00:00", "1" * 64, "x.exe", "exe", "DcRat", good),
                row("2021-01-02 00:00:00", "2" * 64, "y.exe", "exe", "AsyncRAT", good),
                row("2021-01-03 00:00:00", "3" * 64, "HotRAT.exe", "exe", "", good),
                row("2021-01-04 00:00:00", "4" * 64, "z.dll", "dll", "DcRat", good),
            ]) + "\r\n")
        scan = mb.family_candidates(path, families(), {"2" * 64}, set())
        self.assertEqual([item["sha256"] for item in scan["by_family"]["DcRat"]],
                         ["1" * 64])
        self.assertEqual([item["sha256"] for item in scan["by_family"]["HotRAT"]],
                         ["3" * 64])
        self.assertEqual(scan["by_family"]["HotRAT"][0]["source"], "filename")


class KeyLoaderTests(unittest.TestCase):
    def test_yaraify_key_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("MB_AUTH_KEY=mb\nYARAIFY_AUTH_KEY=ya\n")
            self.assertEqual(yaraify_voter.resolve_auth_key("", env), "ya")

    def test_falls_back_to_mb_key(self):
        with tempfile.TemporaryDirectory() as directory:
            env = Path(directory) / ".env"
            env.write_text("MB_AUTH_KEY=mb\n")
            self.assertEqual(yaraify_voter.resolve_auth_key("", env), "mb")

    def test_cli_key_wins(self):
        self.assertEqual(yaraify_voter.resolve_auth_key("cli", Path("/nope")),
                         "cli")

    def test_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                yaraify_voter.resolve_auth_key("", Path(directory) / ".env"), "")


if __name__ == "__main__":
    unittest.main()

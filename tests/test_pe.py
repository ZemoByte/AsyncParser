#!/usr/bin/env python3
"""Synthetic tests for the single PE/CLR parser."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from pe_fixtures import make_pe  # noqa: E402
from Tools import _carver_common  # noqa: E402
from Tools.Labeling import labeler  # noqa: E402
from Tools._pe import is_dotnet, is_dotnet_bytes  # noqa: E402


class PeParserTests(unittest.TestCase):
    def test_dotnet_pe(self):
        data = make_pe(dotnet=True)
        self.assertTrue(is_dotnet_bytes(data))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "dotnet.exe"
            path.write_bytes(data)
            self.assertTrue(is_dotnet(path))

    def test_native_pe(self):
        data = make_pe(dotnet=False)
        self.assertFalse(is_dotnet_bytes(data))
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "native.exe"
            path.write_bytes(data)
            self.assertFalse(is_dotnet(path))

    def test_truncated_and_non_mz(self):
        self.assertFalse(is_dotnet_bytes(b"MZ"))
        self.assertFalse(is_dotnet_bytes(b"not a PE"))

    def test_one_shared_implementation(self):
        self.assertIs(labeler.is_dotnet, is_dotnet)
        self.assertIs(_carver_common.is_dotnet, is_dotnet)


if __name__ == "__main__":
    unittest.main()

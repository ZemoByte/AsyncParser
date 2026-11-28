#!/usr/bin/env python3
"""Synthetic tests: carvers warn on parse failures instead of hiding them."""

from __future__ import annotations

import contextlib
import hashlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.AssemblyRef import assembly_ref  # noqa: E402
from Tools.ImplMap import impl_map  # noqa: E402
from Tools.ImportTable import import_table  # noqa: E402
from Tools.MemberRef import member_ref  # noqa: E402
from Tools.TypeRef import type_ref  # noqa: E402

DNFILE_MODULES = (type_ref, member_ref, assembly_ref, impl_map)


class CarverWarningTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "corrupt.exe"
        self.path.write_bytes(b"MZ" + b"\x00" * 64)
        self.sha = hashlib.sha256(self.path.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def test_dnfile_carvers_warn(self):
        for module in DNFILE_MODULES:
            with self.subTest(module=module.KIND):
                fake = SimpleNamespace(
                    dnPE=mock.Mock(side_effect=ValueError("bad metadata")))
                buffer = io.StringIO()
                with mock.patch.object(module, "is_dotnet", return_value=True), \
                        mock.patch.object(module, "dnfile", fake), \
                        contextlib.redirect_stderr(buffer):
                    values = module.carve(self.path)
                self.assertEqual(values, [])
                warning = buffer.getvalue()
                self.assertIn(f"WARNING: {module.KIND} parse failed", warning)
                self.assertIn(str(self.path), warning)
                self.assertIn(self.sha, warning)
                self.assertIn("bad metadata", warning)

    def test_import_table_warns(self):
        fake = SimpleNamespace(
            PE=mock.Mock(side_effect=ValueError("bad PE header")))
        buffer = io.StringIO()
        with mock.patch.object(import_table, "is_dotnet", return_value=True), \
                mock.patch.object(import_table, "pefile", fake), \
                contextlib.redirect_stderr(buffer):
            values = import_table.carve(self.path)
        self.assertEqual(values, [])
        warning = buffer.getvalue()
        self.assertIn("WARNING: ImportTable PE parse failed", warning)
        self.assertIn(self.sha, warning)
        self.assertIn("bad PE header", warning)


if __name__ == "__main__":
    unittest.main()

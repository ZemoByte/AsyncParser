#!/usr/bin/env python3
"""Synthetic tests for DIE workers (fake diec, no malware)."""

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

from Tools.Voters.DIE import die_voter  # noqa: E402


class DieWorkerTests(unittest.TestCase):
    def test_workers_write_evidence_and_survive_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake_diec"
            fake.write_text("""#!/bin/bash
if [ "$1" = "--version" ]; then echo "die 4.1.0"; exit 0; fi
for arg in "$@"; do
  case "$arg" in
    *bad.exe) echo "synthetic failure" >&2; exit 1 ;;
  esac
done
echo '{"detects":[{"values":[{"type":"compiler","name":"VB.NET"}]}]}'
""")
            fake.chmod(0o755)
            samples = root / "Samples" / "AsyncRAT"
            samples.mkdir(parents=True)
            import hashlib
            shas = {}
            for name in ("a.exe", "b.exe", "bad.exe"):
                data = b"MZ" + name.encode()
                (samples / name).write_bytes(data)
                shas[hashlib.sha256(data).hexdigest()] = name
            out = root / "Data"
            argv = ["die_voter.py", "--samples-root", str(root / "Samples"),
                    "--out", str(out), "--diec", str(fake), "--workers", "2"]
            with mock.patch.object(sys, "argv", argv):
                self.assertEqual(die_voter.main(), 0)
            evidence = list((out / "Evidence").glob("*/detect_it_easy.json"))
            self.assertEqual(len(evidence), 3)
            levels = {}
            for path in evidence:
                fields = json.loads(path.read_text())["fields"]
                levels[shas[path.parent.name]] = fields["raw"]["obf_lvl"]
            self.assertEqual(levels["a.exe"], "plain")
            self.assertEqual(levels["b.exe"], "plain")
            self.assertEqual(levels["bad.exe"], "unknown")
            self.assertTrue((out / "Evidence" / ".detect_it_easy.done").is_file())

    def test_workers_are_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = root / "fake_diec"
            fake.write_text('#!/bin/bash\nif [ "$1" = "--version" ]; then echo "die 4.1.0"; fi\n')
            fake.chmod(0o755)
            (root / "Samples" / "AsyncRAT").mkdir(parents=True)
            (root / "Samples" / "AsyncRAT" / "a.exe").write_bytes(b"MZ")
            argv = ["die_voter.py", "--samples-root", str(root / "Samples"),
                    "--out", str(root / "Data"), "--diec", str(fake),
                    "--workers", "99"]
            with mock.patch.object(sys, "argv", argv):
                self.assertEqual(die_voter.main(), 0)


if __name__ == "__main__":
    unittest.main()

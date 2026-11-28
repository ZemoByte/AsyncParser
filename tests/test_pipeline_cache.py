#!/usr/bin/env python3
"""Synthetic tests for pipeline fingerprints, reuse and skip rules."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Pipeline import run, state
from Tools.Pipeline.reuse import can_reuse, output_version, schema_shift_message
from Tools._versions import LABEL_SCHEMA_VERSION


class StateTests(unittest.TestCase):
    def test_fingerprint_is_stable_and_version_sensitive(self):
        code = [Path(__file__)]
        inputs = {"samples": "abc", "ledger": "def"}
        first = state.stage_fingerprint("labeler", {"v": 2}, code, inputs, {})
        second = state.stage_fingerprint("labeler", {"v": 2}, code, inputs, {})
        changed = state.stage_fingerprint("labeler", {"v": 3}, code, inputs, {})
        upstream = state.stage_fingerprint("labeler", {"v": 2}, code, inputs,
                                           {"labeler": "x"})
        self.assertEqual(first, second)
        self.assertNotEqual(first, changed)
        self.assertNotEqual(first, upstream)

    def test_fresh_requires_outputs_and_status(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out.json"
            output.write_text("{}")
            entry = {"status": "ok", "fingerprint": "fp", "schema_version": 2}
            ok, reason = state.stage_fresh(entry, "fp", [output])
            self.assertTrue(ok)
            output.unlink()
            ok, reason = state.stage_fresh(entry, "fp", [output])
            self.assertFalse(ok)
            self.assertIn("missing outputs", reason)

    def test_state_roundtrip_is_atomic(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            state.save_state({"schema_version": 2, "stages": {"a": {}}}, path)
            self.assertEqual(state.load_state(path)["stages"], {"a": {}})
            self.assertFalse(list(path.parent.glob("*.tmp")))


class ReuseTests(unittest.TestCase):
    def test_ten_old_plus_one_new(self):
        old = [{"sha256": f"s{i}", "fields": {"producer_version": 1}}
               for i in range(10)]
        new = None
        versions = Counter(output_version(payload) for payload in old)
        message = schema_shift_message(versions, 2, "carver_typeref", 11)
        self.assertIn("schema changed 1->2", message)
        self.assertIn("11 samples", message)
        self.assertFalse(any(can_reuse(payload, f"s{i}", 2)[0]
                             for i, payload in enumerate(old)))
        self.assertFalse(can_reuse(new, "new", 2)[0])
        self.assertTrue(all(can_reuse(payload, f"s{i}", 1)[0]
                            for i, payload in enumerate(old)))

    def test_missing_version_is_not_reused(self):
        ok, reason = can_reuse({"sha256": "a", "fields": {}}, "a",
                               LABEL_SCHEMA_VERSION)
        self.assertFalse(ok)
        self.assertIn("legacy", reason)

    def test_sha_mismatch_is_not_reused(self):
        payload = {"sha256": "b", "fields": {"producer_version": 2}}
        self.assertFalse(can_reuse(payload, "a", 2)[0])


class StageExecutionTests(unittest.TestCase):
    def run_stage(self, root: Path, stage: dict, entries=None):
        entries = {} if entries is None else entries
        with mock.patch.object(run, "LOG_DIR", root / "logs"), \
                mock.patch.object(run, "LOCK_DIR", root / "locks"):
            return run._run_stage(stage, None, entries, {"fake": "fp"}, 1), entries

    def test_wall_seconds_and_state_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out.txt"
            code = ("import time; time.sleep(0.3); "
                    f"open({str(output)!r}, 'w').write('x')")
            stage = {"name": "fake", "cmd": [sys.executable, "-c", code],
                     "outputs": [output]}
            seconds, entries = self.run_stage(root, stage)
            self.assertGreaterEqual(seconds, 0.25)
            record = entries["fake"]
            self.assertEqual(record["status"], "ok")
            self.assertGreaterEqual(record["wall_seconds"], 0.25)
            self.assertEqual(record["returncode"], 0)
            self.assertEqual(record["output_count"], 1)
            self.assertTrue(record["started_at"])
            self.assertFalse(list((root / "locks").glob("*.lock")))

    def test_existing_lock_blocks_second_start(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "locks").mkdir()
            lock = root / "locks" / "fake.lock"
            lock.write_text(json.dumps({"pid": os.getpid()}))
            stage = {"name": "fake", "cmd": [sys.executable, "-c", "pass"],
                     "outputs": [root / "out"]}
            with self.assertRaises(RuntimeError) as caught:
                self.run_stage(root, stage)
            self.assertIn("already running", str(caught.exception))

    def test_stale_output_fails_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "out.txt"
            output.write_text("old")
            os.utime(output, (1, 1))
            stage = {"name": "fake", "cmd": [sys.executable, "-c", "pass"],
                     "outputs": [output]}
            entries = {}
            with self.assertRaises(RuntimeError) as caught:
                self.run_stage(root, stage, entries)
            self.assertIn("did not refresh", str(caught.exception))
            self.assertEqual(entries["fake"]["status"], "failed:stale_output")


class RunnerPlanTests(unittest.TestCase):
    def test_each_carver_once_and_single_carver_pass(self):
        stages = run.stages()
        names = [stage["name"] for stage in stages]
        for kind in ("typeref", "memberref", "assemblyref", "implmap",
                     "importtable"):
            self.assertEqual(names.count(f"carver_{kind}"), 1)
        self.assertEqual(names.count("importer"), 1)
        self.assertEqual(names.count("importer2"), 1)
        self.assertEqual(names.count("split"), 1)

    def test_dry_run_prints_each_stage_once(self):
        proc = subprocess.run(
            [sys.executable, "Tools/Pipeline/run.py", "--dry-run"],
            cwd=REPO, capture_output=True, text=True, check=False)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for stage in run.stages():
            pattern = rf"(?m)^\s*\d+\s+{re.escape(stage['name'])}\s+"
            self.assertEqual(len(re.findall(pattern, proc.stdout)), 1,
                             stage["name"])

    def test_yaraify_rate_is_unchanged(self):
        stages = run.stages()
        yaraify = next(stage for stage in stages
                       if stage["name"] == "yaraify")
        self.assertIn("--delay", yaraify["cmd"])
        self.assertEqual(yaraify["cmd"][yaraify["cmd"].index("--delay") + 1],
                         "1.0")
        self.assertNotIn("--workers", yaraify["cmd"])

    def test_waves_keep_writers_serial(self):
        stages = run.stages()
        waves = {stage["name"]: stage["wave"] for stage in stages}
        writers = ["aggregator", "audit", "clusterer", "split", "matrix",
                   "baseline"]
        for name in writers:
            self.assertGreater(waves[name], 2, name)
        self.assertLess(waves["importer"], waves["split"])
        self.assertLess(waves["split"], waves["importer2"])


if __name__ == "__main__":
    unittest.main()

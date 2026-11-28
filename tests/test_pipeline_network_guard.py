#!/usr/bin/env python3
"""Synthetic tests for the pipeline network/write guards."""

from __future__ import annotations

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools.Pipeline import run  # noqa: E402


def stage(name: str, wave: int = 2, cmd=None) -> dict:
    return {"name": name, "wave": wave, "cmd": cmd or ["true"],
            "outputs": [], "versions": [], "code": [], "inputs": [],
            "upstream": []}


def item(name: str, action: str = "run") -> dict:
    return {"stage": stage(name), "action": action, "reason": "test"}


class NetworkGuardTests(unittest.TestCase):
    def test_network_stage_is_only_yaraify(self):
        self.assertEqual(run.NETWORK_STAGES, ("yaraify",))

    def test_plain_plan_blocks_network_and_keeps_local(self):
        plan = [item("labeler"), item("yaraify"), item("baseline")]
        blocked = run.block_network_plan(plan, allow_network=False)
        self.assertEqual(blocked, ["yaraify"])
        self.assertEqual([entry["action"] for entry in plan],
                         ["run", "blocked", "run"])
        self.assertIn("--allow-network", plan[1]["reason"])

    def test_allow_network_permits_stage(self):
        plan = [item("yaraify")]
        blocked = run.block_network_plan(plan, allow_network=True)
        self.assertEqual(blocked, [])
        self.assertEqual(plan[0]["action"], "run")

    def _main(self, argv: list[str], stages=None, extra_patches=None):
        fake = stages or [stage("labeler", 1), stage("yaraify", 2),
                          stage("baseline", 3)]
        patches = [
            mock.patch.object(run, "stages", return_value=fake),
            mock.patch.object(run.state, "samples_digest", return_value="s"),
            mock.patch.object(run.state, "file_digest", return_value="f"),
            mock.patch.object(run, "build_fingerprints",
                              return_value={entry["name"]: "fp"
                                            for entry in fake}),
            mock.patch.object(run.state, "load_state",
                              return_value={"stages": {}}),
            mock.patch.object(run.state, "stage_fresh",
                              return_value=(False, "changed")),
            mock.patch.object(run.state, "save_state"),
            mock.patch.object(run, "_run_stage", return_value=0.0),
            mock.patch.object(run.subprocess, "run"),
            mock.patch.object(sys, "argv", ["run.py", *argv]),
        ]
        if extra_patches:
            patches.extend(extra_patches)
        started = [patch.start() for patch in patches]
        runner = started[7]
        proc = started[8]
        try:
            output = io.StringIO()
            with redirect_stdout(output):
                code = run.main()
        finally:
            for patch in reversed(patches):
                patch.stop()
        return code, output.getvalue(), runner, proc

    def test_plain_run_is_plan_only_and_never_executes(self):
        code, output, runner, proc = self._main([])
        self.assertEqual(code, 0)
        self.assertIn("plan-only; pass --apply", output)
        self.assertIn("network stages blocked: yaraify", output)
        runner.assert_not_called()
        proc.assert_not_called()

    def test_dry_run_is_plan_only(self):
        code, output, runner, proc = self._main(["--dry-run"])
        self.assertEqual(code, 0)
        self.assertIn("blocked", output)
        self.assertIn("plan-only; pass --apply", output)
        runner.assert_not_called()
        proc.assert_not_called()

    def test_apply_runs_local_and_blocks_yaraify(self):
        code, output, runner, proc = self._main(["--apply"])
        self.assertEqual(code, 2)
        self.assertIn("network stages blocked: yaraify", output)
        self.assertEqual(runner.call_count, 2)
        called = [call.args[0]["name"] for call in runner.call_args_list]
        self.assertEqual(called, ["labeler", "baseline"])
        proc.assert_not_called()

    def test_apply_allow_network_runs_all(self):
        code, output, runner, proc = self._main(["--apply",
                                                "--allow-network"])
        self.assertEqual(code, 0)
        self.assertEqual(runner.call_count, 3)
        called = [call.args[0]["name"] for call in runner.call_args_list]
        self.assertEqual(called, ["labeler", "yaraify", "baseline"])
        proc.assert_not_called()

    def test_freeze_runs_no_stages(self):
        code, output, runner, proc = self._main(["--freeze"])
        self.assertEqual(code, 0)
        self.assertIn("freeze check: ok", output)
        runner.assert_not_called()
        proc.assert_not_called()

    def test_plain_run_does_not_create_a_stage_output(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = Path(directory) / "written"
            command = [sys.executable, "-c",
                       f"open({str(sentinel)!r}, 'w').write('x')"]
            fake = [stage("labeler", 1, command)]
            code, _output, runner, _proc = self._main([], stages=fake)
            self.assertEqual(code, 0)
            self.assertFalse(sentinel.exists())
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()

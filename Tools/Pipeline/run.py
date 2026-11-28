#!/usr/bin/env python3
"""Fingerprint-aware pipeline orchestrator.

Runs independent stages concurrently, skips unchanged stages, and keeps
YARAify strictly sequential (1 req/s). The importer runs on every activation
because it is idempotent.

Dry-run first:
    python3 Tools/Pipeline/run.py --dry-run
"""

from __future__ import annotations

import argparse
import csv
import datetime
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._versions import (  # noqa: E402
    CARVER_SCHEMA_VERSION, EVIDENCE_SCHEMA_VERSION, FEATURE_SCHEMA_VERSION,
    LABEL_SCHEMA_VERSION, PIPELINE_SCHEMA_VERSION, SPLIT_SCHEMA_VERSION,
    STRUCTURE_SCHEMA_VERSION,
)
from Tools.Pipeline import state  # noqa: E402

DATA = ROOT / "Data"
SAMPLES = ROOT / "Samples"
LEDGER = ROOT / "Tools" / "MBDownloader" / "samples.db"
DIE_WRAPPER = Path.home() / ".local" / "opt" / "asyncparser-die" / "diec"
LOG_DIR = DATA / "Pipeline" / "logs"
LOCK_DIR = DATA / "Pipeline" / "locks"
CARVERS = ("TypeRef", "MemberRef", "AssemblyRef", "ImplMap", "ImportTable")
VOTERS = ("own_yara", "elastic", "malpedia", "malwarebazaar", "yaraify",
          "detect_it_easy")
# Only the YARAify voter performs an outbound HTTP request. The other voters
# are local (YARA rules, ledger, DIE binary). Keep this list authoritative.
NETWORK_STAGES = ("yaraify",)
FROZEN_DB_SHA256 = "e2db6434824f4f7952c68cda5d31ef538bfcceb122bdaac1cdf64eff1e3d1a75"
FROZEN_SPLIT_COUNT = 341
FROZEN_GOLD_ROWS = 30
FREEZE_REQUIRED = (
    DATA / "DataSet.db",
    DATA / "Splits" / ".done",
    DATA / "Features" / "train.npz",
    DATA / "Features" / "val.npz",
    DATA / "Features" / "test.npz",
    DATA / "Features" / "metadata.json",
    DATA / "Features" / "baseline_results.json",
    DATA / "Features" / "fixup_results.json",
    DATA / "Reports" / "dataset_report.md",
    DATA / "Gold" / "review" / "gold_review_sheet.csv",
    DATA / "Gold" / "gold.csv",
)
_CACHE_HELPERS = [ROOT / "Tools" / "_versions.py",
                  ROOT / "Tools" / "Pipeline" / "reuse.py"]
CODE = {
    "labeler": [ROOT / "Tools" / "Labeling" / "labeler.py",
                ROOT / "Tools" / "_label_common.py", *_CACHE_HELPERS],
    "carver": [ROOT / "Tools" / "_carver_common.py", *_CACHE_HELPERS],
    "structure": [ROOT / "Tools" / "Structure" / "structure.py",
                  ROOT / "Tools" / "_carver_common.py", *_CACHE_HELPERS],
    "voter": [ROOT / "Tools" / "_voter_common.py",
              ROOT / "Tools" / "_label_common.py", *_CACHE_HELPERS],
    "aggregator": [ROOT / "Tools" / "Aggregator" / "aggregator.py",
                   ROOT / "Tools" / "_label_common.py"],
    "audit": [ROOT / "Tools" / "Audit" / "reference_only.py",
              ROOT / "Tools" / "_label_common.py"],
    "clusterer": [ROOT / "Tools" / "Clustering" / "clusterer.py",
                  ROOT / "Tools" / "_label_common.py"],
    "importer": [ROOT / "Tools" / "Importer" / "importer.py",
                 ROOT / "Tools" / "_label_common.py"],
    "split": [ROOT / "Tools" / "Splits" / "split.py",
              ROOT / "Tools" / "_label_common.py"],
    "matrix": [ROOT / "Tools" / "Features" / "build_matrix.py",
               ROOT / "Tools" / "_label_common.py"],
    "baseline": [ROOT / "Tools" / "Models" / "baseline.py",
                 ROOT / "Tools" / "_gate.py"],
    "report": [ROOT / "Tools" / "Report" / "dataset_report.py",
               ROOT / "Tools" / "_gate.py"],
}
VOTER_FILES = {
    "own_yara": ROOT / "Tools" / "Voters" / "OwnYara" / "own_yara.py",
    "elastic": ROOT / "Tools" / "Voters" / "Elastic" / "elastic_voter.py",
    "malpedia": ROOT / "Tools" / "Voters" / "Malpedia" / "malpedia_voter.py",
    "malwarebazaar": ROOT / "Tools" / "Voters" / "MalwareBazaar" / "mb_voter.py",
    "yaraify": ROOT / "Tools" / "Voters" / "YARAify" / "yaraify_voter.py",
    "detect_it_easy": ROOT / "Tools" / "Voters" / "DIE" / "die_voter.py",
}
RULES = {
    "own_yara": [ROOT / "Tools" / "Voters" / "OwnYara" / "asyncrat_own.yar"],
    "elastic": [ROOT / "Tools" / "Voters" / "Elastic" / "rules"],
    "malpedia": [ROOT / "Tools" / "Voters" / "Malpedia" / "rules"],
}


def _rules_files(kind: str) -> list[Path]:
    files = []
    for path in RULES.get(kind, []):
        if path.is_dir():
            files.extend(item for item in path.rglob("*") if item.is_file())
        elif path.is_file():
            files.append(path)
    return files


def _voter_stage(kind: str) -> dict:
    marker = f".{kind}.done" if kind != "detect_it_easy" else ".detect_it_easy.done"
    command = ["python3", str(VOTER_FILES[kind])]
    if kind in ("own_yara", "elastic", "malpedia"):
        command.append("--reuse")
    if kind == "yaraify":
        command += ["--delay", "1.0", "--reuse", "--skip-trivial"]
    if kind == "detect_it_easy":
        command += ["--reuse", "--workers", "4", "--diec", str(DIE_WRAPPER)]
    return {"name": kind, "wave": 2, "cmd": command,
            "outputs": [DATA / "Evidence" / marker],
            "versions": [EVIDENCE_SCHEMA_VERSION],
            "code": CODE["voter"] + [VOTER_FILES[kind]] + _rules_files(kind),
            "inputs": [kind], "upstream": ["labeler"]}


def stages() -> list[dict]:
    result = [{
        "name": "labeler", "wave": 1,
        "cmd": ["python3", str(ROOT / "Tools" / "Labeling" / "labeler.py"),
                "--reuse"],
        "outputs": [DATA / "Labels" / ".labeler.done"],
        "versions": [LABEL_SCHEMA_VERSION], "inputs": ["samples", "sources"],
        "code": CODE["labeler"], "upstream": [],
    }]
    for kind in CARVERS:
        result.append({
            "name": f"carver_{kind.lower()}", "wave": 1,
            "cmd": ["python3", str(ROOT / "Tools" / kind / f"{_snake(kind)}.py"),
                    "--reuse"],
            "outputs": [DATA / cls / kind / ".done"
                        for cls in ("AsyncRAT", "OtherMalwares", "Benign")],
            "versions": [CARVER_SCHEMA_VERSION], "inputs": ["samples"],
            "code": CODE["carver"] + [ROOT / "Tools" / kind / f"{_snake(kind)}.py"],
            "upstream": [],
        })
    result.append({
        "name": "structure", "wave": 1,
        "cmd": ["python3", str(ROOT / "Tools" / "Structure" / "structure.py"),
                "--reuse"],
        "outputs": [DATA / "Structure" / ".done"],
        "versions": [STRUCTURE_SCHEMA_VERSION], "inputs": ["samples"],
        "code": CODE["structure"], "upstream": [],
    })
    result.extend(_voter_stage(kind) for kind in VOTERS)
    result += [
        {"name": "aggregator", "wave": 3,
         "cmd": ["python3", str(ROOT / "Tools" / "Aggregator" / "aggregator.py")],
         "outputs": [DATA / "Aggregated" / ".aggregator.done"],
         "versions": [], "inputs": scheduled_inputs(VOTERS),
         "code": CODE["aggregator"], "upstream": ["labeler", *VOTERS]},
        {"name": "audit", "wave": 4,
         "cmd": ["python3", str(ROOT / "Tools" / "Audit" / "reference_only.py")],
         "outputs": [DATA / "Audit" / "reference_only.json"],
         "versions": [], "inputs": [], "code": CODE["audit"],
         "upstream": ["aggregator"]},
        {"name": "clusterer", "wave": 5,
         "cmd": ["python3", str(ROOT / "Tools" / "Clustering" / "clusterer.py")],
         "outputs": [DATA / "Clusters" / ".done"],
         "versions": [], "inputs": ["samples"], "code": CODE["clusterer"],
         "upstream": ["audit"]},
        {"name": "importer", "wave": 6,
         "cmd": ["python3", str(ROOT / "Tools" / "Importer" / "importer.py")],
         "outputs": [DATA / "DataSet.db"],
         "versions": [], "inputs": [],
         "code": CODE["importer"], "always_run": True,
         "upstream": ["clusterer", "carver_typeref", "carver_memberref",
                      "carver_assemblyref", "carver_implmap",
                      "carver_importtable", "structure", "aggregator"]},
        {"name": "split", "wave": 7,
         "cmd": ["python3", str(ROOT / "Tools" / "Splits" / "split.py")],
         "outputs": [DATA / "Splits" / ".done"],
         "versions": [SPLIT_SCHEMA_VERSION], "inputs": [],
         "code": CODE["split"], "upstream": ["importer"]},
        {"name": "importer2", "wave": 8,
         "cmd": ["python3", str(ROOT / "Tools" / "Importer" / "importer.py")],
         "outputs": [DATA / "DataSet.db"],
         "versions": [], "inputs": [], "code": CODE["importer"],
         "always_run": True, "upstream": ["split"]},
        {"name": "matrix", "wave": 9,
         "cmd": ["python3", str(ROOT / "Tools" / "Features" / "build_matrix.py")],
         "outputs": [DATA / "Features" / "metadata.json"],
         "versions": [FEATURE_SCHEMA_VERSION], "inputs": [],
         "code": CODE["matrix"], "upstream": ["split", "structure",
                                              "carver_typeref", "carver_memberref",
                                              "carver_assemblyref",
                                              "carver_implmap",
                                              "carver_importtable"]},
        {"name": "baseline", "wave": 10,
         "cmd": ["python3", str(ROOT / "Tools" / "Models" / "baseline.py")],
         "outputs": [DATA / "Features" / "baseline_results.json"],
         "versions": [], "inputs": [], "code": CODE["baseline"],
         "upstream": ["matrix"]},
        {"name": "report", "wave": 11,
         "cmd": ["python3", str(ROOT / "Tools" / "Report" / "dataset_report.py"),
                 "--out", str(DATA / "Reports" / "dataset_report.md")],
         "outputs": [DATA / "Reports" / "dataset_report.md"],
         "versions": [], "inputs": [], "code": CODE["report"],
         "upstream": ["baseline"]},
    ]
    return result


def scheduled_inputs(kinds: list[str]) -> list[str]:
    return list(kinds)


def _snake(name: str) -> str:
    return {"TypeRef": "type_ref", "MemberRef": "member_ref",
            "AssemblyRef": "assembly_ref", "ImplMap": "impl_map",
            "ImportTable": "import_table"}[name]


def build_fingerprints(all_stages: list[dict], args, samples_digest: str,
                       ledger_digest: str, sources_digest: str) -> dict:
    versions = {
        "label": LABEL_SCHEMA_VERSION, "evidence": EVIDENCE_SCHEMA_VERSION,
        "carver": CARVER_SCHEMA_VERSION,
        "structure": STRUCTURE_SCHEMA_VERSION,
        "feature": FEATURE_SCHEMA_VERSION, "split": SPLIT_SCHEMA_VERSION,
    }
    fps = {}
    by_name = {stage["name"]: stage for stage in all_stages}
    for stage in all_stages:
        inputs = {"samples": samples_digest, "ledger": ledger_digest,
                  "sources": sources_digest}
        for kind in stage["inputs"]:
            if kind == "samples":
                continue
            if kind in RULES:
                inputs[f"rules:{kind}"] = state.digest_paths(_rules_files(kind))
            if kind == "malwarebazaar":
                inputs["ledger"] = ledger_digest
            if kind == "detect_it_easy":
                inputs["die"] = die_digest_cached(args.die)
        chosen = {f"v{version}": version for version in stage["versions"]}
        upstream = {name: fps[name] for name in stage["upstream"]
                    if name in fps}
        fps[stage["name"]] = state.stage_fingerprint(
            stage["name"], chosen, stage["code"], inputs, upstream)
    return fps


_die_cache = {}


def die_digest_cached(wrapper: str) -> str:
    if wrapper not in _die_cache:
        _die_cache[wrapper] = state.die_digest(wrapper)
    return _die_cache[wrapper]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the pipeline")
    parser.add_argument("--data-root", type=Path, default=DATA)
    parser.add_argument("--samples-root", type=Path, default=SAMPLES)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--changed-only", action="store_true", default=True)
    parser.add_argument("--refresh", action="append", default=[])
    parser.add_argument("--refresh-all", action="store_true")
    parser.add_argument("--from", dest="start", default=None)
    parser.add_argument("--to", dest="end", default=None)
    parser.add_argument("--apply", action="store_true",
                        help="execute the plan; without this, plan only")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-network", action="store_true",
                        help="permit network stages (YARAify)")
    parser.add_argument("--freeze", action="store_true",
                        help="verify the frozen package and exit")
    parser.add_argument("--verify-only", action="store_true",
                        help="alias for --freeze")
    parser.add_argument("--die", default=str(DIE_WRAPPER))
    args = parser.parse_args()
    if args.freeze or args.verify_only:
        return freeze_check()

    all_stages = stages()
    names = [stage["name"] for stage in all_stages]
    if args.start and args.start not in names:
        parser.error(f"unknown stage {args.start}")
    if args.end and args.end not in names:
        parser.error(f"unknown stage {args.end}")
    jobs = max(1, min(args.jobs, max(1, os.cpu_count() or 1)))

    samples_digest = state.samples_digest(args.samples_root.resolve(), LEDGER)
    ledger_digest = state.file_digest(LEDGER)
    sources_digest = state.file_digest(ROOT / "Data" / "BenignSources.csv")
    fps = build_fingerprints(all_stages, args, samples_digest, ledger_digest,
                             sources_digest)
    payload = state.load_state()
    entries = payload.setdefault("stages", {})

    plan = []
    for stage in all_stages:
        fresh, reason = state.stage_fresh(entries.get(stage["name"]),
                                          fps[stage["name"]], stage["outputs"])
        forced = args.refresh_all or stage["name"] in args.refresh
        if not _in_range(stage["name"], names, args.start, args.end):
            action, why = "skip", "outside --from/--to"
        elif forced:
            action, why = "run", "forced refresh"
        elif stage.get("always_run"):
            action, why = "run", "always"
        elif fresh:
            action, why = "skip", reason
        else:
            action, why = "run", reason
        plan.append({"stage": stage, "action": action, "reason": why})

    blocked = block_network_plan(plan, args.allow_network)
    if args.dry_run or not args.apply:
        for item in plan:
            print(f"{item['stage']['wave']:>2} {item['stage']['name']:<22} "
                  f"{item['action']:<7} {item['reason']}")
        print(f"plan: run={sum(1 for p in plan if p['action']=='run')} "
              f"skip={sum(1 for p in plan if p['action']=='skip')} "
              f"blocked={sum(1 for p in plan if p['action']=='blocked')} "
              f"jobs={jobs}")
        if blocked:
            print("network stages blocked: " + ", ".join(blocked))
        print("plan-only; pass --apply to execute")
        return 0
    if blocked:
        print("network stages blocked: " + ", ".join(blocked))
        print("continuing with local stages; pass --allow-network for a full run")

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    state.save_state(payload)
    timings = []
    for wave in sorted({stage["wave"] for stage in all_stages}):
        group = [item for item in plan if item["stage"]["wave"] == wave
                 and item["action"] == "run"]
        skipped = [item["stage"]["name"] for item in plan
                   if item["stage"]["wave"] == wave and item["action"] == "skip"]
        for name in skipped:
            timings.append((name, 0.0, "skipped"))
        if not group:
            continue
        try:
            if len(group) == 1:
                item = group[0]
                seconds = _run_stage(item["stage"], args, entries, fps, jobs)
                timings.append((item["stage"]["name"], seconds, "ok"))
            else:
                with ThreadPoolExecutor(max_workers=jobs) as pool:
                    futures = {pool.submit(_run_stage, item["stage"], args,
                                           entries, fps, jobs):
                               item["stage"]["name"] for item in group}
                    for future in as_completed(futures):
                        name = futures[future]
                        seconds = future.result()
                        timings.append((name, seconds, "ok"))
        finally:
            state.save_state(payload)

    print("\nstage timings")
    for name, seconds, status in sorted(timings, key=lambda row: row[0]):
        print(f"  {name:<22} {status:<8} {seconds:.1f}s")
    if blocked:
        print("network stages blocked: " + ", ".join(blocked))
        return 2
    return 0


def block_network_plan(plan: list[dict], allow_network: bool) -> list[str]:
    """Mark selected network stages blocked; return their names."""
    blocked = []
    if allow_network:
        return blocked
    for item in plan:
        if item["stage"]["name"] in NETWORK_STAGES and item["action"] == "run":
            item["action"] = "blocked"
            item["reason"] = "network stage blocked; use --allow-network"
            blocked.append(item["stage"]["name"])
    return blocked


def freeze_check() -> int:
    problems = []
    missing = [str(path) for path in FREEZE_REQUIRED if not path.exists()]
    if missing:
        problems.extend(f"missing: {path}" for path in missing)
    db_path = DATA / "DataSet.db"
    if db_path.is_file():
        digest = hashlib.sha256(db_path.read_bytes()).hexdigest()
        print(f"  DataSet.db sha256: {digest[:8]}…")
        if digest != FROZEN_DB_SHA256:
            problems.append("DataSet.db sha256 changed")
    else:
        print("  DataSet.db sha256: missing")
    split_count = len(list((DATA / "Splits").glob("*.json")))
    print(f"  split JSONs: {split_count}")
    if split_count != FROZEN_SPLIT_COUNT:
        problems.append(f"split count {split_count} != {FROZEN_SPLIT_COUNT}")
    from Tools._gate import evaluate_gate
    gate = evaluate_gate(DATA)
    print(f"  gate: {'PASS' if gate['overall'] else 'FAIL'}")
    if gate["overall"]:
        problems.append("gate is PASS; expected FAIL")
    gold_rows = []
    gold_path = DATA / "Gold" / "gold.csv"
    if gold_path.is_file():
        with gold_path.open(newline="", encoding="utf-8") as handle:
            gold_rows = list(csv.DictReader(handle))
    filled = sum(1 for row in gold_rows
                 if (row.get("gold_status") or "").strip())
    print(f"  gold: {len(gold_rows)} rows / {filled} filled")
    if len(gold_rows) != FROZEN_GOLD_ROWS or filled:
        problems.append("gold sheet is not 30 rows / 0 filled")
    locks = list(LOCK_DIR.glob("*")) if LOCK_DIR.is_dir() else []
    print(f"  locks: {len(locks)}")
    if locks:
        problems.append(f"locks present: {len(locks)}")
    if problems:
        for problem in problems:
            print(f"  FAIL: {problem}")
        print("freeze check: FAILED")
        return 1
    print("freeze check: ok")
    return 0


def _in_range(name: str, names: list[str], start: str | None,
              end: str | None) -> bool:
    low = names.index(start) if start else 0
    high = names.index(end) if end else len(names) - 1
    return low <= names.index(name) <= high


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _acquire_lock(name: str) -> Path:
    LOCK_DIR.mkdir(parents=True, exist_ok=True)
    path = LOCK_DIR / f"{name}.lock"
    payload = json.dumps({"pid": os.getpid(),
                          "started_at": datetime.datetime.now(
                              datetime.timezone.utc).isoformat(
                                  timespec="seconds")}).encode()
    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
            os.write(fd, payload)
            os.close(fd)
            return path
        except FileExistsError:
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = {}
            pid = int(existing.get("pid") or 0)
            if pid and _pid_alive(pid):
                raise RuntimeError(
                    f"stage {name} is already running (pid {pid}, lock {path})")
            try:
                path.unlink()
            except FileNotFoundError:
                pass
    raise RuntimeError(f"could not acquire lock for stage {name}: {path}")


def _release_lock(path: Path) -> None:
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def _fresh_outputs(outputs: list[Path], started_ns: int) -> tuple[bool, float | None]:
    mtimes = [path.stat().st_mtime for path in outputs if path.exists()]
    if len(mtimes) != len(outputs):
        return False, None
    newest = max(mtimes)
    # Filesystems with coarse timestamps may round down; 2 s is far below
    # the age of a stale marker from a previous run.
    return newest >= (started_ns / 1e9) - 2.0, newest


def _run_stage(stage: dict, args, entries: dict, fps: dict, jobs: int) -> float:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_path = LOG_DIR / f"{stage['name']}.log"
    started_at = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")
    started_ns = time.time_ns()
    started = time.monotonic()
    print(f"[run] {stage['name']}")
    lock_path = _acquire_lock(stage["name"])
    try:
        with log_path.open("w", encoding="utf-8") as log:
            proc = subprocess.run(stage["cmd"], cwd=ROOT, stdout=log,
                                  stderr=subprocess.STDOUT, text=True)
    finally:
        _release_lock(lock_path)
    seconds = time.monotonic() - started
    finished_at = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")
    if proc.returncode != 0:
        entries[stage["name"]] = state.stage_record(
            stage["name"], fps[stage["name"]], stage["outputs"], seconds,
            status=f"failed:{proc.returncode}", started_at=started_at,
            finished_at=finished_at, returncode=proc.returncode)
        raise RuntimeError(f"stage {stage['name']} failed; see {log_path}")
    fresh, marker_mtime = _fresh_outputs(stage["outputs"], started_ns)
    if not fresh:
        entries[stage["name"]] = state.stage_record(
            stage["name"], fps[stage["name"]], stage["outputs"], seconds,
            status="failed:stale_output", started_at=started_at,
            finished_at=finished_at, returncode=proc.returncode,
            marker_mtime=marker_mtime)
        raise RuntimeError(
            f"stage {stage['name']} did not refresh its outputs; "
            f"see {log_path}")
    entries[stage["name"]] = state.stage_record(
        stage["name"], fps[stage["name"]], stage["outputs"], seconds,
        started_at=started_at, finished_at=finished_at,
        returncode=proc.returncode, marker_mtime=marker_mtime)
    print(f"[ok]  {stage['name']} ({seconds:.1f}s)")
    return seconds


if __name__ == "__main__":
    raise SystemExit(main())

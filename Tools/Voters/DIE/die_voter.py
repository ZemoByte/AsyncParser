#!/usr/bin/env python3
"""Detect It Easy attribute voter for `obf_lvl`.

This is not a family voter: verdict is always `no_match`; the useful value is
`raw.obf_lvl`. If `diec` is not installed, it writes an honest no_match with
`raw.reason=diec_not_installed` so the evidence marker still exists.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file  # noqa: E402
from Tools._versions import EVIDENCE_SCHEMA_VERSION  # noqa: E402
from Tools._voter_common import (  # noqa: E402
    evidence_current, write_evidence, write_marker)  # noqa: E402

DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
SOURCE = "detect_it_easy"
GROUP = "attribute:die"
OBFUSCATOR_TYPES = {
    ".net obfuscator", "protector", "packer", ".net compressor",
    "obfuscator", "crypter", "cryptor",
}


def diec_version(diec: str) -> str:
    try:
        proc = subprocess.run([diec, "--version"], capture_output=True,
                              text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    text = (proc.stdout or proc.stderr).strip()
    return text.splitlines()[0] if text else "unknown"


def parse_diec_output(text: str) -> tuple[str, dict]:
    """Parse DIE 4.x JSON (`detects[].values[]`) and the older records list."""
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        return "unknown", {"reason": f"diec_json_error: {exc}"}
    if not isinstance(payload, dict):
        return "unknown", {"reason": "diec_no_records"}
    records = payload.get("records")
    if not isinstance(records, list):
        records = []
        for detect in payload.get("detects") or []:
            if isinstance(detect, dict) and isinstance(detect.get("values"), list):
                records.extend(detect["values"])
    if not records:
        return "unknown", {"reason": "diec_no_records"}
    relevant = []
    for record in records:
        if not isinstance(record, dict):
            continue
        record_type = str(record.get("type") or "").strip().lower()
        if record_type in OBFUSCATOR_TYPES:
            relevant.append({
                "type": record.get("type"),
                "name": record.get("name"),
                "version": record.get("version"),
                "info": str(record.get("info") or "")[:200],
            })
    raw = {"record_count": len(records), "obfuscator_records": relevant}
    if relevant:
        names = [str(item.get("name") or "unknown") for item in relevant]
        return f"obfuscated:{names[0]}", raw
    return "plain", raw


def run_diec(diec: str, path: Path, timeout: int) -> tuple[str, dict]:
    try:
        proc = subprocess.run(
            [diec, "-j", "-d", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return "unknown", {"reason": "diec_timeout"}
    except OSError as exc:
        return "unknown", {"reason": f"diec_error: {exc}"}
    if proc.returncode != 0:
        return "unknown", {"reason": f"diec_returncode:{proc.returncode}",
                           "stderr": (proc.stderr or "")[:500]}
    return parse_diec_output(proc.stdout)


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect It Easy obf-level voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--diec", default=shutil.which("diec") or "diec")
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--reuse", action="store_true")
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    diec = args.diec
    installed = shutil.which(diec) is not None
    version = diec_version(diec) if installed else "not-installed"
    source_version = f"diec@{version}"

    counts: Counter = Counter()
    total = 0
    reused = 0
    workers = max(1, min(args.workers, 4))
    pending = []
    for _class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        if args.reuse and evidence_current(out_root, sha256, SOURCE,
                                           source_version):
            reused += 1
            total += 1
            continue
        pending.append((sha256, path))

    def work(item):
        sha256, path = item
        level, detail = run_diec(diec, path, args.timeout)
        return sha256, level, detail

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(work, item) for item in pending]
        for future in as_completed(futures):
            sha256, obf_lvl, detail = future.result()
            strength = "strong" if obf_lvl.startswith("obfuscated:") else "medium"
            raw = {"scope": "attribute", "obf_lvl": obf_lvl, "detail": detail}
            write_evidence(out_root, sha256, SOURCE, source_version, GROUP,
                           "no_match", strength, raw)
            counts[obf_lvl] += 1
            total += 1

    if reused:
        counts["reused"] += reused
    write_marker(out_root / "Evidence", SOURCE, source_version, total)
    print(f"detect_it_easy: {total} samples (reused {reused}), "
          f"workers {workers}, obf_lvl {dict(sorted(counts.items()))}")
    print(f"diec_installed: {installed}, version: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

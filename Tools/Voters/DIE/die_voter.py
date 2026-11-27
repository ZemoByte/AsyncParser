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
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file  # noqa: E402
from Tools._voter_common import write_evidence, write_marker  # noqa: E402

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


def run_diec(diec: str, path: Path, timeout: int) -> tuple[str, dict]:
    try:
        proc = subprocess.run(
            [diec, "-j", "-d", "-e", str(path)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except subprocess.TimeoutExpired:
        return "unknown", {"reason": "diec_timeout"}
    except OSError as exc:
        return "unknown", {"reason": f"diec_error: {exc}"}
    if proc.returncode != 0:
        return "unknown", {"reason": f"diec_returncode:{proc.returncode}",
                           "stderr": (proc.stderr or "")[:500]}
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        return "unknown", {"reason": f"diec_json_error: {exc}"}
    records = payload.get("records") if isinstance(payload, dict) else None
    if not isinstance(records, list):
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Detect It Easy obf-level voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--diec", default=shutil.which("diec") or "diec")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    diec = args.diec
    installed = shutil.which(diec) is not None
    version = diec_version(diec) if installed else "not-installed"
    source_version = f"diec@{version}"

    counts: Counter = Counter()
    total = 0
    for _class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        if installed:
            obf_lvl, detail = run_diec(diec, path, args.timeout)
            strength = "strong" if obf_lvl.startswith("obfuscated:") else "medium"
            raw = {"scope": "attribute", "obf_lvl": obf_lvl, "detail": detail}
        else:
            obf_lvl = "unknown"
            strength = "weak"
            raw = {"scope": "attribute", "obf_lvl": obf_lvl,
                   "reason": "diec_not_installed"}
        write_evidence(out_root, sha256, SOURCE, source_version, GROUP,
                       "no_match", strength, raw)
        counts[obf_lvl] += 1
        total += 1

    write_marker(out_root / "Evidence", SOURCE, source_version, total)
    print(f"detect_it_easy: {total} samples, obf_lvl {dict(sorted(counts.items()))}")
    print(f"diec_installed: {installed}, version: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

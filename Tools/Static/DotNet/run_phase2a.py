#!/usr/bin/env python3
"""Phase 2A orchestrator: clean one .NET sample (or a directory of them).

Runs de4dot → decompile → IL → resources → strings → carve → stego.
Child tools write Cleaned/<original_sha>/… and their own provenance entries.
This orchestrator only prints status and appends one summary step per sample.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/run_phase2a.py <sample|dir>
"""

import argparse
import hashlib
import subprocess
import sys
from pathlib import Path

from dotnet_common import CLEANED, record

SCRIPT_DIR = Path(__file__).resolve().parent
VENV_PYTHON = SCRIPT_DIR.parents[1] / ".venv" / "bin" / "python"

# exit 0 = ok, 2 = skipped (missing tool / soft skip), else = failed
PIPELINE = [
    ("deobfuscate", "deobfuscate.py", False),
    ("decompile", "decompile.py", True),
    ("il_dump", "il_dump.py", True),
    ("resources", "extract_resources.py", True),
    ("decrypt_strings", "decrypt_strings.py", True),
    ("carve", "carve_payloads.py", True),
    ("steganography", "extract_steganography.py", True),
]


def python_bin():
    return str(VENV_PYTHON) if VENV_PYTHON.is_file() else sys.executable


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def run_step(script, sample, sha, pass_sha):
    cmd = [python_bin(), str(SCRIPT_DIR / script), str(sample)]
    if pass_sha:
        cmd.extend(["--sha", sha])
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=600,
                            errors="replace")
    except subprocess.TimeoutExpired:
        return "failed", "timeout after 600s"
    except OSError as e:
        return "failed", str(e)

    out = ((cp.stdout or "") + (cp.stderr or "")).strip()
    snippet = out[-500:] if out else f"rc={cp.returncode}"
    if cp.returncode == 0:
        return "ok", snippet
    if cp.returncode == 2:
        return "skipped", snippet
    return "failed", snippet


def collect_samples(target):
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(
            p for p in target.rglob("*")
            if p.is_file() and p.suffix.lower() in {".exe", ".dll"}
        )
    return []


def main():
    ap = argparse.ArgumentParser(description="Phase 2A .NET cleaning orchestrator")
    ap.add_argument("sample", help="Path to .NET assembly/exe, or directory")
    args = ap.parse_args()

    samples = collect_samples(Path(args.sample))
    if not samples:
        print(f"ERROR: no .exe/.dll under {args.sample}", file=sys.stderr)
        sys.exit(1)

    print(f"Processing {len(samples)} sample(s) with Phase 2A pipeline\n")
    any_failed = False

    for src in samples:
        sha = sha256_of_file(src)
        print("=" * 60)
        print(f"Sample: {src.name}")
        print(f"SHA256: {sha}\n")

        deobf = CLEANED / sha / "deobf" / f"{src.stem}_cleaned.exe"
        work = src
        statuses = []

        for step_name, script, pass_sha in PIPELINE:
            print(f"--- {step_name}")
            status, reason = run_step(script, work, sha, pass_sha)
            statuses.append(status)
            tag = status.upper()
            print(f"  {tag}: {reason.splitlines()[-1] if reason else ''}")

            if step_name == "deobfuscate" and status == "ok" and deobf.is_file():
                work = deobf  # later steps analyze cleaned binary, write under --sha

            if status == "failed":
                any_failed = True

        overall = "failed" if "failed" in statuses else (
            "ok" if "ok" in statuses else "skipped"
        )
        record(sha, "phase2a", overall, tool="run_phase2a",
               reason=f"steps={statuses}; input={src.name}")
        print(f"\nSample {src.name} pipeline complete ({overall})\n")

    print("=" * 60)
    print("Phase 2A pipeline completed")
    sys.exit(1 if any_failed else 0)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Phase 2A: IL dump via monodis (fallback ikdasm). Writes Cleaned/<sha256>/il/.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/il_dump.py <path_to_exe>
"""

import argparse
import sys
from pathlib import Path

from dotnet_common import (artifacts_dir, record, resolve_sha, run_tool,
                           tool_path)


def main():
    ap = argparse.ArgumentParser(description="Dump IL from one .NET sample")
    ap.add_argument("sample")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    out_dir = artifacts_dir(sha, "il")
    out_file = out_dir / f"{sha[:16]}.il"

    monodis = tool_path("monodis")
    ikdasm = tool_path("ikdasm")
    if not monodis and not ikdasm:
        record(sha, "il_dump", "skipped", tool="monodis/ikdasm",
               reason="neither tool installed (needs mono-complete)")
        print("SKIP: monodis and ikdasm not found.")
        sys.exit(2)

    if monodis:
        tool = monodis
        rc, stdout, stderr, error = run_tool([tool, f"--output={out_file}", str(src)])
    else:
        tool = ikdasm
        rc, stdout, stderr, error = run_tool([tool, str(src)])
        if rc == 0 and stdout:
            out_file.write_text(stdout, errors="replace")

    ok = rc == 0 and out_file.is_file() and out_file.stat().st_size > 0
    reason = (error or stderr.strip() or stdout.strip())[:500]
    record(sha, "il_dump", "ok" if ok else "failed", tool=Path(tool).name,
           artifacts=[out_file] if ok else [],
           reason=f"rc={rc}; {reason}")
    print(f"{'OK' if ok else 'FAILED'} IL dump -> {out_file if ok else reason}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

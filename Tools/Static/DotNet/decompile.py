#!/usr/bin/env python3
"""Phase 2A: ilspycmd wrapper. Writes Cleaned/<sha256>/decompiled/.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/decompile.py <path_to_exe>
  [--ilspycmd /path/to/ilspycmd]
"""

import argparse
import sys
from pathlib import Path

from dotnet_common import (artifacts_dir, record, resolve_sha, run_tool,
                           tool_path)


def main():
    ap = argparse.ArgumentParser(description="Decompile one .NET sample with ilspycmd")
    ap.add_argument("sample")
    ap.add_argument("--ilspycmd", default=None, help="Path to ilspycmd (default: search PATH)")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    out_dir = artifacts_dir(sha, "decompiled")
    tool = args.ilspycmd or tool_path("ilspycmd")
    if not tool:
        record(sha, "decompile", "skipped", tool="ilspycmd",
               reason="ilspycmd not installed (needs dotnet-sdk)")
        print("SKIP: ilspycmd not found. Install it before running this step.")
        sys.exit(2)

    rc, stdout, stderr, error = run_tool([tool, "-o", str(out_dir), str(src)])
    produced = [p for p in out_dir.rglob("*") if p.is_file()]
    ok = rc == 0 and bool(produced)
    reason = (error or stderr.strip() or stdout.strip())[:500]
    record(sha, "decompile", "ok" if ok else "failed", tool="ilspycmd",
           artifacts=produced if ok else [],
           reason=f"rc={rc}; {reason}")
    print(f"{'OK' if ok else 'FAILED'} ilspycmd -> {len(produced)} file(s)")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

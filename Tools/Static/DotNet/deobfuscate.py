#!/usr/bin/env python3
"""Phase 2A: deobfuscation wrapper.

Runs de4dot on a .NET sample and writes Cleaned/<sha256>/deobf/.

de4dot-cex v4.0.0 is a .NET Framework 4.0 app, so on Linux it needs Mono
(Fedora: `sudo dnf install mono`). If de4dot cannot run, the step is recorded
as skipped with no artifacts.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/deobfuscate.py <path_to_exe>
  [--de4dot /path/to/de4dot]
"""

import argparse
import sys
from pathlib import Path

import dnfile

from dotnet_common import artifacts_dir, BASE, record, run_tool, sha256_of_file


def parse_dotnet_with_dnfile(path):
    """Verify a PE re-parses as a valid .NET assembly.

    Returns (success: bool, message: str).
    """
    try:
        pe = dnfile.dnPE(str(path))
        try:
            has_clr = pe.net is not None
            parse_ok = (has_clr and
                        pe.net.mdtables is not None and
                        pe.net.mdtables.Assembly is not None)
            return parse_ok, f"CLR metadata present={has_clr}, " \
                           f"assembly tables={len(pe.net.mdtables.Assembly) if pe.net.mdtables else 0}"
        finally:
            pe.close()
    except Exception as e:
        return False, f"dnfile parse failed: {e}"


def run_de4dot(de4dot_path, src, out_path):
    """Run de4dot (via mono for Windows .exe builds). Returns (success, message)."""
    if Path(de4dot_path).suffix.lower() == ".exe":
        cmd = ["mono", de4dot_path, str(src), "-o", str(out_path)]
        via = "via mono"
    else:
        cmd = [de4dot_path, str(src), "-o", str(out_path)]
        via = "direct"
    rc, stdout, stderr, error = run_tool(cmd, timeout=300)
    if rc == 0 and out_path.is_file() and out_path.stat().st_size > 0:
        # Re-parse with dnfile per Phase 2A verification
        ok, msg = parse_dotnet_with_dnfile(out_path)
        if ok:
            return True, f"de4dot OK (rc=0, {via}), re-parse OK: {msg}"
        return False, f"de4dot ran but re-parse failed: {msg}"
    return False, (error or stderr.strip() or stdout.strip())[:500]


def main():
    ap = argparse.ArgumentParser(
        description="Deobfuscate one .NET sample with de4dot"
    )
    ap.add_argument("sample")
    ap.add_argument(
        "--de4dot",
        default=None,
        help="Path to de4dot (default: Tools/de4dot/de4dot.exe)",
    )
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = sha256_of_file(src)
    out_dir = artifacts_dir(sha, "deobf")
    out_path = out_dir / f"{src.stem}_cleaned.exe"

    # --- Attempt 1: de4dot (preferred) ---
    de4dot_path = None
    reason = "de4dot binary not found"
    if args.de4dot:
        de4dot_path = args.de4dot
    else:
        # Try finding de4dot in our Tools/de4dot/ directory using BASE
        de4dot_dir = BASE / "Tools" / "de4dot"
        for candidate in [de4dot_dir / "de4dot.exe", de4dot_dir / "de4dot-x64.exe"]:
            if candidate.is_file():
                de4dot_path = str(candidate)
                break

    if de4dot_path:
        ok, reason = run_de4dot(de4dot_path, src, out_path)
        if ok:
            record(sha, "deobfuscate", "ok", tool="de4dot", artifacts=[out_path],
                   reason=reason)
            print(f"OK de4dot -> {out_path}")
            sys.exit(0)

        record(sha, "deobfuscate", "failed", tool="de4dot",
               reason=f"de4dot failed: {reason}")
        print(f"DE4DOT FAILED: {reason}")
        sys.exit(1)

    # --- Attempt 2: de4dot not available ---
    # No copy to deobf/ (violates LOCKED DECISION #2: raw binary never sent
    # to the LLM as a "cleaned" artifact). Record skipped with zero artifacts.
    record(sha, "deobfuscate", "skipped", tool="none",
           reason=f"de4dot not runnable: {reason}")
    print("SKIP de4dot: cannot execute de4dot in this environment")
    sys.exit(2)


if __name__ == "__main__":
    main()



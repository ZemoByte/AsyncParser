#!/usr/bin/env python3
"""Phase 2A/2B: extract appended/overlay data and PNG trailing data.

Writes candidates to Cleaned/<sha256>/stego/ and records findings.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/extract_steganography.py <path_to_exe>
"""

import argparse
import sys
from pathlib import Path

import pefile

from dotnet_common import artifacts_dir, record, resolve_sha

PNG_SIG = b"\x89PNG\r\n\x1a\n"
IEND = b"IEND\xaeB`\x82"


def main():
    ap = argparse.ArgumentParser(description="Extract steganography artifacts")
    ap.add_argument("sample")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    out_dir = artifacts_dir(sha, "stego")
    data = src.read_bytes()
    artifacts = []
    dropped = []

    pe = pefile.PE(str(src))
    try:
        end = max((s.PointerToRawData + s.SizeOfRawData for s in pe.sections),
                  default=0)
        overlay = data[end:]
        if overlay:
            path = out_dir / "overlay.bin"
            path.write_bytes(overlay)
            artifacts.append(path)
        else:
            dropped.append("no PE overlay data")
    finally:
        pe.close()

    start = 0
    while True:
        png = data.find(PNG_SIG, start)
        if png < 0:
            break
        iend = data.find(IEND, png)
        if iend < 0:
            dropped.append(f"PNG at 0x{png:x}: no IEND marker")
            break
        trailing = data[iend + len(IEND):]
        if trailing:
            path = out_dir / f"png_trailing_{png:x}.bin"
            path.write_bytes(trailing)
            artifacts.append(path)
        else:
            dropped.append(f"PNG at 0x{png:x}: no trailing data")
        start = iend + len(IEND)

    record(sha, "steganography", "ok", tool="pure-python",
           artifacts=artifacts, dropped=dropped,
           reason=f"{len(artifacts)} candidate blob(s)")
    print(f"OK: {len(artifacts)} stego candidate(s), {len(dropped)} dropped")


if __name__ == "__main__":
    main()

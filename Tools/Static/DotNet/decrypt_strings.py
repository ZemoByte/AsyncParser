#!/usr/bin/env python3
"""Phase 2A: heuristic string recovery (base64 / XOR) into Cleaned/<sha>/strings/.

This is a static approximation, not full .NET emulation: it scans raw bytes for
printable strings, then tries base64 and single-byte XOR. Candidates that decode
to readable text or a PE/ZIP marker are kept; the rest are recorded as dropped.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/decrypt_strings.py <path_to_exe>
"""

import argparse
import base64
import binascii
import re
import sys
from pathlib import Path

from dotnet_common import artifacts_dir, record, resolve_sha

PRINTABLE = re.compile(rb"[ -~]{8,}")
B64 = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")


def readable(text):
    return sum(c.isprintable() for c in text) / max(len(text), 1) > 0.85


def main():
    ap = argparse.ArgumentParser(description="Recover obfuscated strings heuristically")
    ap.add_argument("sample")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    out_dir = artifacts_dir(sha, "strings")
    data = src.read_bytes()

    decoded = []
    dropped = []

    for m in B64.finditer(data):
        raw = m.group()
        if len(raw) % 4:
            continue
        try:
            out = base64.b64decode(raw, validate=True)
        except (binascii.Error, ValueError):
            continue
        text = out.decode("utf-8", errors="replace")
        if readable(text) or out[:2] in (b"MZ", b"PK"):
            decoded.append((raw.decode("ascii"), text[:500]))
        else:
            dropped.append(f"base64 at 0x{m.start():x}: no readable result")

    for m in PRINTABLE.finditer(data):
        raw = m.group()
        for key in range(1, 256):
            out = bytes(b ^ key for b in raw)
            text = out.decode("utf-8", errors="replace")
            if readable(text) and any(w in text.lower() for w in
                                      ("host", "port", "password", "http", "mutex")):
                decoded.append((f"xor-{key:02x}", text[:500]))
                break

    lines = [f"{blob}\t=>\t{text}\n" for blob, text in decoded]
    out_file = out_dir / "decoded.txt"
    out_file.write_text("".join(lines))
    if not decoded:
        dropped.append("no base64/XOR candidates decoded")

    record(sha, "decrypt_strings", "ok" if decoded else "skipped",
           tool="heuristic", artifacts=[out_file] if decoded else [],
           dropped=dropped,
           reason=f"{len(decoded)} candidate string(s); static approximation only")
    print(f"OK: {len(decoded)} candidate string(s) -> {out_file}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Phase 2A/2B: carve embedded PE payloads and base64-loaded assemblies.

Writes candidates to Cleaned/<sha256>/carved/ and records every finding.
Heuristic: an embedded PE starts with MZ and has a PE signature at e_lfanew.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/carve_payloads.py <path_to_exe> [--sha HASH]
"""

import argparse
import base64
import binascii
import re
import struct
import sys
from pathlib import Path

from dotnet_common import artifacts_dir, record, resolve_sha

B64 = re.compile(rb"[A-Za-z0-9+/]{80,}={0,2}")
PE_SIG = b"PE\x00\x00"
# PE32 = 0x10b, PE32+ = 0x20b (little-endian)
OPT_MAGIC_OK = {0x10B, 0x20B}


def is_pe_at(data, offset, sample_offset=0):
    """Validate a real PE at offset (not just MZ). Skips sample_offset (usually 0)."""
    if offset == sample_offset:
        return False
    if offset + 0x40 > len(data) or data[offset:offset + 2] != b"MZ":
        return False
    try:
        lfanew = struct.unpack_from("<I", data, offset + 0x3C)[0]
    except struct.error:
        return False
    pe_off = offset + lfanew
    if lfanew < 0x40 or pe_off + 26 > len(data):
        return False
    if data[pe_off:pe_off + 4] != PE_SIG:
        return False
    num_sections = struct.unpack_from("<H", data, pe_off + 6)[0]
    if num_sections < 1 or num_sections > 96:
        return False
    opt_magic = struct.unpack_from("<H", data, pe_off + 24)[0]
    return opt_magic in OPT_MAGIC_OK


def main():
    ap = argparse.ArgumentParser(description="Carve embedded payloads from a PE")
    ap.add_argument("sample")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    out_dir = artifacts_dir(sha, "carved")
    data = src.read_bytes()
    artifacts = []
    dropped = []

    offsets = [i for i in range(1, len(data) - 1) if data[i:i + 2] == b"MZ"]
    for off in offsets:
        if not is_pe_at(data, off):
            continue
        end = min([x for x in offsets if x > off] or [len(data)])
        blob = data[off:end]
        if len(blob) < 512:
            dropped.append(f"embedded PE at 0x{off:x}: too small ({len(blob)} bytes)")
            continue
        path = out_dir / f"embedded_pe_{off:x}.bin"
        path.write_bytes(blob)
        artifacts.append(path)

    for m in B64.finditer(data):
        try:
            decoded = base64.b64decode(m.group(), validate=True)
        except (binascii.Error, ValueError):
            continue
        if decoded[:2] == b"PK":
            path = out_dir / f"b64_zip_{m.start():x}.bin"
            path.write_bytes(decoded)
            artifacts.append(path)
        elif decoded[:2] == b"MZ" and is_pe_at(decoded, 0, sample_offset=-1):
            path = out_dir / f"b64_pe_{m.start():x}.bin"
            path.write_bytes(decoded)
            artifacts.append(path)
        else:
            dropped.append(f"base64 at 0x{m.start():x}: decoded but not PE/ZIP")

    record(sha, "carve_payloads", "ok", tool="pure-python",
           artifacts=artifacts, dropped=dropped,
           reason=f"{len(offsets)} MZ candidate(s), {len(artifacts)} carved")
    print(f"OK: {len(artifacts)} carved payload(s), {len(dropped)} dropped")


if __name__ == "__main__":
    main()

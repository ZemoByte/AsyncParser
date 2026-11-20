#!/usr/bin/env python3
"""Phase 2A: extract .NET managed resources with dnfile."""

import argparse
import json
import sys
import struct
import re
from pathlib import Path

import dnfile

from dotnet_common import artifacts_dir, record, resolve_sha, safe_name


def _decode_serialized_data(data):
    """Try to decode a .NET serialized blob.

    Returns decoded string if it looks like real text (readable char ratio > 85%,
    not full of replacement chars), else None.
    """
    if not data:
        return None
    try:
        if len(data) >= 8:
            length = struct.unpack_from("<I", data, 0)[0]
            if 0 < length < len(data) - 4 and length * 2 + 4 <= len(data):
                text = data[4 : 4 + length * 2].decode("utf-16-le", errors="replace")
                if _is_meaningful_text(text):
                    return text.strip()
                text = data[4 : 4 + length].decode("utf-8", errors="replace")
                if _is_meaningful_text(text):
                    return text.strip()
    except (struct.error, UnicodeDecodeError, IndexError):
        pass
    try:
        matches = re.findall(rb"[ -~]{4,}", data)
        if matches:
            best = max(matches, key=len)
            decoded = best.decode("ascii", errors="replace")
            if _is_meaningful_text(decoded):
                return decoded
    except Exception:
        pass
    return None


def _is_meaningful_text(text, printable_ratio=0.85):
    """Check if text is meaningful readable content, not garbage decoded bytes."""
    if not text:
        return False
    stripped = text.strip()
    if not stripped:
        return False
    printable = sum(1 for c in stripped if c.isprintable() or (32 <= ord(c) <= 126))
    ratio = printable / len(stripped)
    if ratio < printable_ratio:
        return False
    REPLACEMENT_CHAR = "\ufffd"
    ff_count = stripped.count(REPLACEMENT_CHAR)
    if ff_count > len(stripped) * 0.15:
        return False
    return True


def _parse_resource_entry(entry, out_dir, res_name, sha256, manifest, artifacts):
    """Parse a single resource entry, attempting to decode serialized data."""
    dropped = []
    entry_name = str(getattr(entry, "name", "") or "entry")
    data = getattr(entry, "data", None) or getattr(entry, "value", None)

    if data is None:
        dropped.append(f"{res_name}/{entry_name}: no data")
        return dropped
    if not isinstance(data, (bytes, bytearray)) or not data:
        dropped.append(f"{res_name}/{entry_name}: non-byte data")
        return dropped

    decoded = _decode_serialized_data(data)

    if decoded is not None:
        txt_path = out_dir / f"{safe_name(res_name)}__{safe_name(entry_name)}.txt"
        txt_path.write_text(decoded, encoding="utf-8")
        artifacts.append(txt_path)
        manifest.append(
            {"name": f"{res_name}/{entry_name}", "file": txt_path.name, "size": len(decoded), "decoded": True}
        )
        bin_path = out_dir / f"{safe_name(res_name)}__{safe_name(entry_name)}.bin"
        bin_path.write_bytes(data)
        artifacts.append(bin_path)
        manifest.append(
            {"name": f"{res_name}/{entry_name}", "file": bin_path.name, "size": len(data), "decoded": False}
        )
        return dropped

    bin_path = out_dir / f"{safe_name(res_name)}__{safe_name(entry_name)}.bin"
    bin_path.write_bytes(data)
    artifacts.append(bin_path)
    manifest.append({"name": f"{res_name}/{entry_name}", "file": bin_path.name, "size": len(data), "decoded": False})

    return dropped


def main():
    ap = argparse.ArgumentParser(description="Extract .NET managed resources")
    ap.add_argument("sample", help="Path to .NET assembly/exe")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    out_dir = artifacts_dir(sha, "resources")

    pe = dnfile.dnPE(str(src))
    try:
        if pe.net is None:
            record(sha, "resources", "skipped", tool="dnfile",
                   reason="no CLR metadata (not a .NET assembly)")
            print("SKIP: not a .NET assembly")
            sys.exit(2)

        artifacts = []
        dropped = []
        manifest = []

        for i, res in enumerate(pe.net.resources):
            res_name = str(res.name) or f"resource_{i}"
            res_data = getattr(res, "data", None)
            if res_data is not None:
                entries = getattr(res_data, "entries", []) or []
            else:
                entries = []

            if not entries:
                dropped.append(f"{res_name}: no entries")
                continue

            for entry in entries:
                entry_dropped = _parse_resource_entry(entry, out_dir, res_name, sha, manifest, artifacts)
                dropped.extend(entry_dropped)

        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        record(sha, "resources", "ok", tool="dnfile",
               artifacts=artifacts,
               dropped=dropped,
               reason=f"{len(pe.net.resources)} resource set(s)")
        print(f"OK: {len(artifacts)} resource file(s), {len(dropped)} dropped")
    finally:
        pe.close()


if __name__ == "__main__":
    main()

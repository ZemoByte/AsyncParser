#!/usr/bin/env python3
"""Dump the .NET #US (user-string) heap via dnfile.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/user_strings.py <assembly>
      [--sha HASH] [--output FILE]
"""

import argparse
import json
import sys
from pathlib import Path

import dnfile

from dotnet_common import artifacts_dir, record, resolve_sha


def _printable_ratio(text):
    if not text:
        return 0.0
    return sum(c.isprintable() for c in text) / len(text)


def extract_user_strings(pe_path):
    """Return readable strings from pe.net.user_strings."""
    pe = dnfile.dnPE(str(pe_path))
    try:
        if pe.net is None or pe.net.user_strings is None:
            return []

        us = pe.net.user_strings
        strings = []
        seen = set()
        offset = 1
        heap_size = us.sizeof()

        while offset < heap_size:
            try:
                item = us.get(offset)
            except Exception:
                offset += 1
                continue
            if item is None:
                offset += 1
                continue

            value = item.value if getattr(item, "value", None) is not None else ""
            if (
                isinstance(value, str)
                and len(value) >= 2
                and _printable_ratio(value) > 0.8
                and value not in seen
            ):
                seen.add(value)
                strings.append(value)

            step = getattr(item, "raw_size", 0) or 1
            offset += step if step > 0 else 1

        return strings
    finally:
        pe.close()


def main():
    ap = argparse.ArgumentParser(description="Extract .NET #US user strings")
    ap.add_argument("sample", help="Path to .NET assembly/exe")
    ap.add_argument("--sha", default=None, help="Original sample SHA256 for Cleaned/<sha>/")
    ap.add_argument("--output", "-o", help="Optional JSON output path")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    sha = resolve_sha(src, args.sha)
    strings = extract_user_strings(src)
    result = {"raw_strings": strings, "count": len(strings)}

    out_dir = artifacts_dir(sha, "strings")
    out_path = Path(args.output) if args.output else out_dir / "user_strings.json"
    out_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")

    record(sha, "user_strings", "ok" if strings else "skipped", tool="dnfile",
           artifacts=[out_path] if strings else [],
           reason=f"{len(strings)} user string(s)")

    print(f"Extracted {len(strings)} user string(s) from {src}")
    for s in strings[:10]:
        print(f"  - {s}")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()

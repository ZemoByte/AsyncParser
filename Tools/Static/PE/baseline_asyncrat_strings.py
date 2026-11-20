#!/usr/bin/env python3
"""Trivial baseline: does the raw binary contain readable "AsyncRAT" text?

This is a deterministic string search over raw bytes. It is intentionally dumb:
no deobfuscation, no parsing, no IL. If the literal string "AsyncRAT" appears
in printable form, predict `asyncrat`; otherwise predict `uncertain`.

Purpose: an honest floor the LLM must beat. If the LLM cannot outperform this
rule on the held-out set, that is a finding to record — not a success.

Usage:
  Tools/.venv/bin/python Tools/Static/PE/baseline_asyncrat_strings.py <sample>
  Tools/.venv/bin/python Tools/Static/PE/baseline_asyncrat_strings.py --dir Samples/AsyncRAT
"""

import argparse
import csv
import os
import sys
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TARGET = b"AsyncRAT"


def baseline_label(data: bytes) -> str:
    """Return 'asyncrat' if raw bytes contain readable 'AsyncRAT', else 'uncertain'."""
    return "asyncrat" if TARGET in data else "uncertain"


def scan_one(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "sha256": path.name.removesuffix(".exe"),
        "filename": path.name,
        "baseline_label": baseline_label(data),
        "has_asyncrat_string": TARGET in data,
    }


def main():
    ap = argparse.ArgumentParser(description="Baseline: raw 'AsyncRAT' string presence")
    ap.add_argument("sample", nargs="?", help="Path to a single sample (or use --dir)")
    ap.add_argument("--dir", help="Directory of samples to scan")
    ap.add_argument("--out", help="Write CSV results to this path")
    args = ap.parse_args()

    results = []

    if args.dir:
        d = Path(args.dir)
        if not d.is_dir():
            print(f"ERROR: not a directory: {d}", file=sys.stderr)
            sys.exit(1)
        for p in sorted(d.iterdir()):
            if p.is_file():
                results.append(scan_one(p))
    elif args.sample:
        results.append(scan_one(Path(args.sample)))
    else:
        ap.print_help()
        sys.exit(1)

    hits = sum(1 for r in results if r["has_asyncrat_string"])
    total = len(results)
    print(f"Baseline scan: {total} samples, {hits} with readable 'AsyncRAT' string "
          f"({hits / total * 100:.1f}%)")

    if args.out:
        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["sha256", "filename", "baseline_label",
                                              "has_asyncrat_string"])
            w.writeheader()
            w.writerows(results)
        print(f"Wrote {total} rows to {args.out}")

    for r in results:
        print(f"  {r['filename']}: {r['baseline_label']} "
              f"(string={'yes' if r['has_asyncrat_string'] else 'no'})")


if __name__ == "__main__":
    main()

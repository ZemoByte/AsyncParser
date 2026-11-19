#!/usr/bin/env python3
"""Enrich Data/manifest.csv with PE format and fingerprint features.

Connects:
  - Tools/Static/PE/dotnet_analyzer.py (format_gate) -> is_dotnet
  - Tools/Static/PE/native_analyze.py (analyze_native_pe) -> upx_detected,
    avg_section_entropy, max_section_entropy, imported_function_count

For each manifest row, finds the matching .exe under Samples/, runs the analyzers,
and updates the manifest columns:
  - is_dotnet: yes | no | unknown
  - upx_detected: yes | no | unknown
  - avg_section_entropy: float (0.00 - 8.00)
  - max_section_entropy: float (0.00 - 8.00)
  - imported_function_count: int count of imported functions

Usage:
  Tools/.venv/bin/python Tools/Manifestor/manifest_updater.py \
      [--manifest Data/manifest.csv] [--samples Samples] [--dry-run]
"""

import argparse
import csv
import os
import sys

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Add Tools/Static/PE to path so we can import dotnet_analyzer and native_analyze directly
sys.path.insert(0, os.path.join(BASE, "Tools", "Static", "PE"))
from dotnet_analyzer import format_gate  # noqa: E402
from native_analyze import analyze_native_pe  # noqa: E402


def sha256_of_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_sample(samples_dir, filename, expected_sha=None):
    """Find a sample file by name under samples_dir (any subfolder), matching SHA256 if provided."""
    matches = []
    for root, _, files in os.walk(samples_dir):
        if filename in files:
            path = os.path.join(root, filename)
            if expected_sha:
                if sha256_of_file(path).lower() == expected_sha.lower():
                    return path
            matches.append(path)
    return matches[0] if matches else None


def format_to_is_dotnet(fmt):
    """Map format_gate verdict to is_dotnet enum value."""
    if fmt == "dotnet" or fmt == "dotnet_parse_failed":
        return "yes"
    if fmt == "native":
        return "no"
    return "unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Add is_dotnet and PE fingerprint columns to manifest"
    )
    parser.add_argument(
        "--manifest", default=os.path.join(BASE, "Data", "manifest.csv"),
        help="Path to manifest CSV"
    )
    parser.add_argument(
        "--samples", default=os.path.join(BASE, "Samples"),
        help="Path to Samples directory"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print what would change without writing"
    )
    args = parser.parse_args()

    if not os.path.isfile(args.manifest):
        print(f"ERROR: manifest not found: {args.manifest}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.samples):
        print(f"ERROR: samples dir not found: {args.samples}", file=sys.stderr)
        sys.exit(1)

    # Read existing manifest
    with open(args.manifest, newline="") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        rows = list(reader)

    updated = 0
    skipped = 0
    format_counts = {}

    for i, row in enumerate(rows, start=1):
        filename = (row.get("filename") or "").strip()
        sha = (row.get("sha256") or "").strip()
        sample_path = find_sample(args.samples, filename, expected_sha=sha) if filename else None
        if not filename or not sample_path:
            if not filename:
                print(f"  SKIP (no filename at row {i})")
            else:
                print(f"  SKIP (not on disk or hash mismatch): {filename}")
            row["is_dotnet"] = "unknown"
            row["upx_detected"] = "unknown"
            row["avg_section_entropy"] = ""
            row["max_section_entropy"] = ""
            row["imported_function_count"] = ""
            skipped += 1
            continue

        # Run format gate
        try:
            gate_report = format_gate(sample_path)
            fmt = gate_report["format"]
            is_dotnet = format_to_is_dotnet(fmt)
        except Exception as e:
            print(f"  ERROR analyzing {filename} (format_gate): {e}")
            is_dotnet = "unknown"
            fmt = "error"

        format_counts[fmt] = format_counts.get(fmt, 0) + 1
        row["is_dotnet"] = is_dotnet

        # Run native/PE fingerprint analysis
        if fmt != "invalid" and fmt != "error":
            try:
                native_report = analyze_native_pe(sample_path)
                if "error" in native_report:
                    row["upx_detected"] = "unknown"
                    row["avg_section_entropy"] = ""
                    row["max_section_entropy"] = ""
                    row["imported_function_count"] = ""
                else:
                    row["upx_detected"] = "yes" if native_report.get("upx_detected") else "no"
                    row["avg_section_entropy"] = f"{native_report.get('avg_section_entropy', 0.0):.2f}"
                    row["max_section_entropy"] = f"{native_report.get('max_section_entropy', 0.0):.2f}"
                    row["imported_function_count"] = str(native_report.get("imported_function_count", 0))
            except Exception as e:
                print(f"  ERROR analyzing {filename} (native_analyze): {e}")
                row["upx_detected"] = "unknown"
                row["avg_section_entropy"] = ""
                row["max_section_entropy"] = ""
                row["imported_function_count"] = ""
        else:
            row["upx_detected"] = "unknown"
            row["avg_section_entropy"] = ""
            row["max_section_entropy"] = ""
            row["imported_function_count"] = ""

        updated += 1

        if i % 10 == 0 or i == len(rows):
            print(f"  Progress: {i}/{len(rows)} (dotnet={format_counts.get('dotnet',0)}, native={format_counts.get('native',0)}, invalid={format_counts.get('invalid',0)}, failed={format_counts.get('dotnet_parse_failed',0)})")

    # Build new column order: is_dotnet, upx_detected, avg_section_entropy,
    # max_section_entropy, imported_function_count placed after filetype (or existing is_dotnet)
    target_fields = [
        "is_dotnet",
        "upx_detected",
        "avg_section_entropy",
        "max_section_entropy",
        "imported_function_count",
    ]
    base_columns = [c for c in columns if c not in target_fields]
    idx = base_columns.index("filetype") + 1 if "filetype" in base_columns else len(base_columns)
    new_columns = base_columns[:idx] + target_fields + base_columns[idx:]

    # Reorder all rows to new columns
    new_rows = []
    for row in rows:
        new_row = {col: row.get(col, "") for col in new_columns}
        new_rows.append(new_row)

    if args.dry_run:
        print(f"DRY RUN: would update {updated} rows, skip {skipped}")
        print(f"Format counts: {format_counts}")
        print(f"New columns: {new_columns}")
        # Show a few samples
        for row in new_rows[:3]:
            print(f"  {row['filename']} -> is_dotnet={row['is_dotnet']}, upx={row['upx_detected']}, avg_ent={row['avg_section_entropy']}, max_ent={row['max_section_entropy']}, imports={row['imported_function_count']}")
        return

    # Write updated manifest
    tmp_path = args.manifest + ".tmp"
    with open(tmp_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=new_columns)
        writer.writeheader()
        writer.writerows(new_rows)

    os.replace(tmp_path, args.manifest)
    print(f"Updated {updated} rows, skipped {skipped}")
    print(f"Format counts: {format_counts}")
    print(f"Manifest: {args.manifest}")
    print(f"Columns: {new_columns}")


if __name__ == "__main__":
    main()

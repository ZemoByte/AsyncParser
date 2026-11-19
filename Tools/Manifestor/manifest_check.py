#!/usr/bin/env python3
"""Manifest integrity check.

Always-checked invariants:
  - unique sha256 per row
  - every listed file exists under Samples/ and its SHA256 matches
  - AsyncRAT rows reference .exe files (not .zip)
  - no "DO NOT EXTRACT" in notes

Columns that do not exist yet in the CSV are skipped, so the same check works
before and after the schema grows. When present, these are validated:
  - is_dotnet               yes | no | unknown
  - upx_detected            yes | no | unknown
  - avg_section_entropy     0.0 - 8.0
  - max_section_entropy     0.0 - 8.0
  - imported_function_count non-negative integer
  - verdict                 confirmed | malicious_unconfirmed | loader | reject | benign
  - llm_label               asyncrat | other | benign | uncertain
  - llm_confidence          0.0 - 1.0
  - cleaned_core            empty, or a path to an existing file

Usage:
  python Tools/Manifestor/manifest_check.py [--manifest PATH] [--samples PATH]
                                            [--expect FAMILY=COUNT ...]
"""

import argparse
import csv
import hashlib
import os
import sys
from collections import Counter, defaultdict

BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ENUMS = {
    "is_dotnet": {"yes", "no", "unknown"},
    "upx_detected": {"yes", "no", "unknown"},
    "verdict": {"confirmed", "malicious_unconfirmed", "loader", "reject", "benign"},
    "llm_label": {"asyncrat", "other", "benign", "uncertain"},
}


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def index_samples(samples_dir):
    """Map filename -> all paths with that name found under samples_dir."""
    index = defaultdict(list)
    for root, _, files in os.walk(samples_dir):
        for name in files:
            index[name].append(os.path.join(root, name))
    return index


def parse_expect(raw):
    expects = {}
    for item in raw or []:
        if "=" not in item:
            raise ValueError(f"expected FAMILY=COUNT, got {item!r}")
        family, count = item.rsplit("=", 1)
        expects[family] = int(count)
    return expects


def main():
    parser = argparse.ArgumentParser(description="Check manifest integrity")
    parser.add_argument("--manifest", default=os.path.join(BASE, "Data", "manifest.csv"),
                        help="Path to manifest CSV (default: <repo>/Data/manifest.csv)")
    parser.add_argument("--samples", default=os.path.join(BASE, "Samples"),
                        help="Path to Samples directory (default: <repo>/Samples)")
    parser.add_argument("--expect", action="append", metavar="FAMILY=COUNT",
                        help="Optional expected row count per family (repeatable)")
    args = parser.parse_args()

    if not os.path.isfile(args.manifest):
        print(f"ERROR: manifest not found: {args.manifest}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isdir(args.samples):
        print(f"ERROR: samples dir not found: {args.samples}", file=sys.stderr)
        sys.exit(1)
    try:
        expects = parse_expect(args.expect)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    with open(args.manifest, newline="") as f:
        reader = csv.DictReader(f)
        columns = reader.fieldnames or []
        rows = list(reader)

    errors = []
    checked = 0
    family_counts = Counter()
    seen_hashes = {}
    sample_index = index_samples(args.samples)

    for i, row in enumerate(rows, start=2):  # row 1 is the header
        sha = (row.get("sha256") or "").strip()
        filename = (row.get("filename") or "").strip()
        family = (row.get("family") or "").strip()
        notes = (row.get("notes") or "").strip()

        family_counts[family] += 1

        # 1. No duplicate hashes.
        if sha:
            key = sha.lower()
            if key in seen_hashes:
                errors.append(f"L{i}: duplicate sha256 (first seen L{seen_hashes[key]}): {filename}")
            else:
                seen_hashes[key] = i

        # 2. AsyncRAT rows must reference .exe, not .zip.
        if family == "AsyncRAT" and filename.endswith(".zip"):
            errors.append(f"L{i}: AsyncRAT row references a .zip file ({filename}), expected .exe")

        # 3. No "DO NOT EXTRACT" in notes.
        if "DO NOT EXTRACT" in notes.upper():
            errors.append(f"L{i}: notes contain 'DO NOT EXTRACT' ({filename})")

        # 4. File must exist on disk (search all subfolders, no family->folder map).
        matches = sample_index.get(filename, [])
        if not matches:
            errors.append(f"L{i}: file not found under {args.samples}: {filename}")
            continue
        if len(matches) > 1:
            errors.append(f"L{i}: ambiguous filename {filename}: {len(matches)} locations")
        disk_path = matches[0]

        # 5. SHA256 must match.
        actual = sha256_of_file(disk_path)
        if sha and actual.lower() != sha.lower():
            errors.append(f"L{i}: SHA256 mismatch for {filename} "
                          f"(manifest={sha[:12]}... disk={actual[:12]}...)")
        checked += 1

        # 6. Enum columns, validated only when the schema actually has them.
        for col, allowed in ENUMS.items():
            if col not in columns:
                continue
            value = (row.get(col) or "").strip()
            if value and value not in allowed:
                errors.append(f"L{i}: {col}={value!r} not in {sorted(allowed)}")

        # 7. Confidence range.
        if "llm_confidence" in columns:
            value = (row.get("llm_confidence") or "").strip()
            if value:
                try:
                    confidence = float(value)
                    if not 0.0 <= confidence <= 1.0:
                        errors.append(f"L{i}: llm_confidence out of range: {value}")
                except ValueError:
                    errors.append(f"L{i}: llm_confidence is not a number: {value}")

        # 8. cleaned_core path, when present and non-empty.
        if "cleaned_core" in columns:
            value = (row.get("cleaned_core") or "").strip()
            if value:
                path = value if os.path.isabs(value) else os.path.join(BASE, value)
                if not os.path.isfile(path):
                    errors.append(f"L{i}: cleaned_core path missing: {value}")

        # 9. PE fingerprint metrics
        for col in ("avg_section_entropy", "max_section_entropy"):
            if col in columns:
                val = (row.get(col) or "").strip()
                if val:
                    try:
                        ent = float(val)
                        if not 0.0 <= ent <= 8.0:
                            errors.append(f"L{i}: {col} out of range (0-8): {val}")
                    except ValueError:
                        errors.append(f"L{i}: {col} is not a valid float: {val}")

        if "imported_function_count" in columns:
            val = (row.get("imported_function_count") or "").strip()
            if val:
                try:
                    cnt = int(val)
                    if cnt < 0:
                        errors.append(f"L{i}: imported_function_count is negative: {val}")
                except ValueError:
                    errors.append(f"L{i}: imported_function_count is not an integer: {val}")

    # 10. Optional, explicitly requested family counts.
    for family, expected in expects.items():
        actual = family_counts.get(family, 0)
        if actual != expected:
            errors.append(f"Family {family!r}: expected {expected} rows, found {actual}")

    print(f"Manifest: {args.manifest}")
    print(f"Rows checked: {checked} / {len(rows)}")
    print(f"Columns: {len(columns)}")
    print(f"Family counts: {dict(sorted(family_counts.items()))}")
    if errors:
        print(f"\n{len(errors)} ISSUE(S) FOUND:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print("\nAll checks passed. Manifest is consistent.")


if __name__ == "__main__":
    main()

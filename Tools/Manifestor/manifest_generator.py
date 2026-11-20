#!/usr/bin/env python3
"""Generate manifest CSV rows for samples in a directory.

Output columns (matches Data/manifest.csv):
  sha256,filename,family,source,bazaar_signature,bazaar_tags,os,arch,filetype,
  is_dotnet,upx_detected,avg_section_entropy,max_section_entropy,
  imported_function_count,notes

Bootstrap tool for NEW sample batches only. Without --append it overwrites --out
with the full 15-column schema, so never point it at Data/manifest.csv -- that
would erase every enriched column (verdict, llm_label, cleaned_core, cluster_id, ...).

With --append it reads an existing manifest, adds new rows for files not already
present (deduped by sha256), and writes back. Safe to point at Data/manifest.csv.

The PE fingerprint columns default to "unknown"/empty so manifest_check.py
skips them; manifest_updater.py fills them in later.

Usage examples:
  python Tools/Manifestor/manifest_generator.py --dir Samples/AsyncRAT --family AsyncRAT \
      --source MalwareBazaar --out manifest_asyncrat.csv
  python Tools/Manifestor/manifest_generator.py --dir Samples/Benign_DotNet --family benign \
      --source GitHub --out manifest_benign_dotnet.csv
  # Append a new family into the live manifest:
  python Tools/Manifestor/manifest_generator.py --dir Samples/Other_Malwares \
      --family QuasarRAT --source MalwareBazaar --out Data/manifest.csv --append
"""

import argparse
import csv
import hashlib
import os
import sys

HEADER_COLUMNS = ["sha256", "filename", "family", "source", "bazaar_signature",
                  "bazaar_tags", "os", "arch", "filetype", "is_dotnet",
                  "upx_detected", "avg_section_entropy", "max_section_entropy",
                  "imported_function_count", "notes"]


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def scan_files(directory):
    """Return sorted list of (filename, full_path) for regular files in directory."""
    if not os.path.isdir(directory):
        print(f"ERROR: not a directory: {directory}", file=sys.stderr)
        sys.exit(1)
    files = []
    for name in sorted(os.listdir(directory)):
        full = os.path.join(directory, name)
        if os.path.isfile(full):
            files.append((name, full))
    return files


def build_row(sha256, filename, family, source, signature, tags, os_, arch,
              filetype, is_dotnet, upx_detected, avg_entropy, max_entropy,
              import_count, notes):
    return [sha256, filename, family, source, signature, tags, os_, arch,
            filetype, is_dotnet, upx_detected, avg_entropy, max_entropy,
            import_count, notes]


def main():
    parser = argparse.ArgumentParser(description="Generate manifest CSV rows for a sample directory")
    parser.add_argument("--dir", required=True, help="Directory containing the samples")
    parser.add_argument("--family", required=True, help="Family label (e.g. AsyncRAT, benign)")
    parser.add_argument("--source", required=True, help="Source label (e.g. MalwareBazaar, Sysinternals)")
    parser.add_argument("--signature", default="", help="Bazaar signature (default: empty)")
    parser.add_argument("--tags", default="", help="Bazaar tags (default: empty)")
    parser.add_argument("--os", default="Windows", dest="os_", help="OS (default: Windows)")
    parser.add_argument("--arch", default="unknown", help="Arch (default: unknown)")
    parser.add_argument("--filetype", default="exe (PE)", help="Filetype (default: exe (PE))")
    parser.add_argument("--is-dotnet", default="unknown", help="is_dotnet (default: unknown)")
    parser.add_argument("--upx-detected", default="unknown", help="upx_detected (default: unknown)")
    parser.add_argument("--avg-entropy", default="", help="avg_section_entropy (default: empty)")
    parser.add_argument("--max-entropy", default="", help="max_section_entropy (default: empty)")
    parser.add_argument("--import-count", default="", help="imported_function_count (default: empty)")
    parser.add_argument("--notes", default="", help="Notes (default: empty)")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--header", action="store_true",
                        help="Write the manifest header row as well")
    parser.add_argument("--append", action="store_true",
                        help="Append new rows to an existing manifest (deduped by sha256). "
                             "Safe to point at Data/manifest.csv.")
    args = parser.parse_args()

    files = scan_files(args.dir)
    if not files:
        print(f"No files found in {args.dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    # Build new rows from the sample directory
    new_rows = []
    for filename, full in files:
        digest = sha256_of_file(full)
        new_rows.append(build_row(digest, filename, args.family, args.source,
                                  args.signature, args.tags, args.os_, args.arch,
                                  args.filetype, args.is_dotnet, args.upx_detected,
                                  args.avg_entropy, args.max_entropy,
                                  args.import_count, args.notes))

    if args.append:
        # Read existing manifest, dedupe new rows against existing sha256s, append.
        if not os.path.isfile(args.out):
            print(f"ERROR: --append requires an existing manifest at {args.out}",
                  file=sys.stderr)
            sys.exit(1)
        existing_rows = []
        existing_shas = set()
        with open(args.out, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_rows.append(row)
                sha = (row.get("sha256") or "").strip().lower()
                if sha:
                    existing_shas.add(sha)

        appended = 0
        for row_vals in new_rows:
            sha = row_vals[0].lower()
            if sha in existing_shas:
                continue
            row_dict = dict(zip(HEADER_COLUMNS, row_vals))
            existing_rows.append(row_dict)
            existing_shas.add(sha)
            appended += 1

        with open(args.out, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=HEADER_COLUMNS)
            w.writeheader()
            w.writerows(existing_rows)

        print(f"Appended {appended} new rows to {args.out} "
              f"({len(existing_rows)} total rows)")
    else:
        with open(args.out, "w", newline="") as f:
            w = csv.writer(f)
            if args.header:
                w.writerow(HEADER_COLUMNS)
            for row_vals in new_rows:
                w.writerow(row_vals)

        print(f"Wrote {len(new_rows)} rows to {args.out}")


if __name__ == "__main__":
    main()

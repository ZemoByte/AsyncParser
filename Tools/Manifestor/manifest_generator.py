#!/usr/bin/env python3
"""Generate manifest CSV rows for samples in a directory.

Output columns (matches Data/manifest.csv):
  sha256,filename,family,source,bazaar_signature,bazaar_tags,os,arch,filetype,notes

Bootstrap tool for NEW sample batches only. It overwrites --out with these 10
columns, so never point it at Data/manifest.csv -- that would erase every
enriched column (is_dotnet, verdict, llm_label, cleaned_core, cluster_id, ...).

Usage examples:
  python Manifest_generator.py --dir Samples/AsyncRAT --family AsyncRAT \
      --source MalwareBazaar --out manifest_asyncrat.csv
  python Manifest_generator.py --dir Samples/Regular_executables --family benign \
      --source Sysinternals --out manifest_benign.csv
"""

import argparse
import csv
import hashlib
import os
import sys


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
              filetype, notes):
    return [sha256, filename, family, source, signature, tags, os_, arch,
            filetype, notes]


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
    parser.add_argument("--notes", default="", help="Notes (default: empty)")
    parser.add_argument("--out", required=True, help="Output CSV path")
    parser.add_argument("--header", action="store_true",
                        help="Write the manifest header row as well")
    args = parser.parse_args()

    files = scan_files(args.dir)
    if not files:
        print(f"No files found in {args.dir}", file=sys.stderr)
        sys.exit(1)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)) or ".", exist_ok=True)

    with open(args.out, "w", newline="") as f:
        w = csv.writer(f)
        if args.header:
            w.writerow(["sha256", "filename", "family", "source", "bazaar_signature",
                        "bazaar_tags", "os", "arch", "filetype", "notes"])
        for filename, full in files:
            digest = sha256_of_file(full)
            w.writerow(build_row(digest, filename, args.family, args.source,
                                 args.signature, args.tags, args.os_, args.arch,
                                 args.filetype, args.notes))

    print(f"Wrote {len(files)} rows to {args.out}")


if __name__ == "__main__":
    main()

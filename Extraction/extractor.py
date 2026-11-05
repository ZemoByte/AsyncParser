#!/usr/bin/env python3
"""Extract MalwareBazaar AsyncRAT samples from password-protected zips."""

import argparse
import csv
import os
import shutil
import pyzipper

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(BASE, "Samples", "AsyncRAT")
ZIP_ARCHIVE_DIR = os.path.join(BASE, "Samples", "Sample_Zip_Files")
PASSWORD = b"infected"


def main():
    parser = argparse.ArgumentParser(description="Extractor for AsyncRAT sample zips")
    parser.add_argument("--execute", action="store_true",
                        help="Actually perform extraction and moves (default is dry run)")
    args = parser.parse_args()

    os.makedirs(ZIP_ARCHIVE_DIR, exist_ok=True)

    zips = sorted(f for f in os.listdir(SAMPLE_DIR) if f.endswith(".zip"))
    if not zips:
        print("No .zip files found in", SAMPLE_DIR)
        return

    print(f"Found {len(zips)} zip files in {SAMPLE_DIR}")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN (use --execute to apply)'}\n")

    log = []
    failed = 0
    total_extracted = 0

    for zip_name in zips:
        zip_path = os.path.join(SAMPLE_DIR, zip_name)
        stem = zip_name[:-4]
        try:
            with pyzipper.AESZipFile(zip_path) as zf:
                zf.setpassword(PASSWORD)
                members = zf.namelist()
                file_members = [m for m in members if not m.endswith("/")]

                if not file_members:
                    print(f"  SKIP  (no files): {zip_name}")
                    log.append((zip_name, "skip_empty", "", ""))
                    continue

                if args.execute:
                    zf.extractall(SAMPLE_DIR, pwd=PASSWORD)

                    extracted_files = []
                    for m in file_members:
                        full = os.path.join(SAMPLE_DIR, m)
                        if os.path.isfile(full):
                            extracted_files.append(m)

                    if len(extracted_files) > 1:
                        target_folder = os.path.join(SAMPLE_DIR, stem)
                        os.makedirs(target_folder, exist_ok=True)
                        for rel in extracted_files:
                            src = os.path.join(SAMPLE_DIR, rel)
                            dst = os.path.join(target_folder, os.path.basename(rel))
                            if os.path.exists(src):
                                shutil.move(src, dst)
                        for rel in extracted_files:
                            parent = os.path.dirname(os.path.join(SAMPLE_DIR, rel))
                            if parent != SAMPLE_DIR and os.path.isdir(parent) and not os.listdir(parent):
                                os.rmdir(parent)

                    shutil.move(zip_path, os.path.join(ZIP_ARCHIVE_DIR, zip_name))

                total_extracted += len(file_members)
                detail = f"{len(file_members)} file(s)"
                if len(file_members) > 1:
                    detail += f" -> folder '{stem}/'"
                print(f"  OK  {zip_name}: {detail}")
                log.append((zip_name, "ok", detail, ""))

        except RuntimeError as e:
            failed += 1
            print(f"  FAIL {zip_name}: {e}")
            log.append((zip_name, "password_error", "", str(e)))
        except Exception as e:
            failed += 1
            print(f"  ERR  {zip_name}: {e}")
            log.append((zip_name, "error", "", str(e)))

    if args.execute:
        log_path = os.path.join(BASE, "Extraction", "extraction_log.csv")
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        with open(log_path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["zip_file", "status", "detail", "error"])
            w.writerows(log)
        print(f"\nLog written to {log_path}")

    print(f"\nSummary: {len(zips)} zips processed, {failed} failed, "
          f"{total_extracted} files extracted")
    if not args.execute:
        print("This was a DRY RUN. Re-run with --execute to apply changes.")


if __name__ == "__main__":
    main()
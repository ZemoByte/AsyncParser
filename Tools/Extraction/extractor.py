#!/usr/bin/env python3
"""Extract samples dropped in Samples/Basket into the right Samples folder.

Categories (MalwareBazaar zips use password "infected"):
  1) AsyncRAT      -> exes to Samples/AsyncRAT,     leftover zips to Samples/AsyncRAT_Zip_Files
  2) Other Malware -> exes to Samples/Other_Malwares, leftover zips to Samples/Other_Malwares_Zip_Files
  3) Regular executables (plain .exe, no zip) -> moved to Samples/Regular_executables

Also appends 15-column manifest rows to Data/manifest.csv for each moved file,
so the dataset stays consistent with the manifest schema.
"""

import argparse
import csv
import hashlib
import os
import shutil
import pyzipper

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(os.path.dirname(SCRIPT_DIR))
SAMPLES_DIR = os.path.join(BASE, "Samples")
BASKET_DIR = os.path.join(SAMPLES_DIR, "Basket")
ASYNRAT_DIR = os.path.join(SAMPLES_DIR, "AsyncRAT")
ASYNRAT_ZIP_DIR = os.path.join(SAMPLES_DIR, "AsyncRAT_Zip_Files")
OTHER_DIR = os.path.join(SAMPLES_DIR, "Other_Malwares")
OTHER_ZIP_DIR = os.path.join(SAMPLES_DIR, "Other_Malwares_Zip_Files")
REGULAR_DIR = os.path.join(SAMPLES_DIR, "Regular_executables")
PASSWORD = b"infected"

CATEGORIES = {
    "1": ("AsyncRAT", ASYNRAT_DIR, ASYNRAT_ZIP_DIR, True),
    "2": ("Other Malware", OTHER_DIR, OTHER_ZIP_DIR, True),
    "3": ("Regular executables", REGULAR_DIR, None, False),
}


def sha256_of_file(path):
    """Compute SHA256 of a file, matching manifest_check.py style."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def append_manifest_row(path, family, source="MalwareBazaar"):
    """Append a 15-column manifest row for a moved file.

    The row is deduped against existing sha256s in Data/manifest.csv.
    Uses the --append pattern from manifest_generator.py so it is safe to
    point at Data/manifest.csv.

    Fields filled from basket extraction:
      - sha256: hash of the moved file
      - filename: the file's basename
      - family: the category name (AsyncRAT / Other_Malware / benign)
      - source: "MalwareBazaar"
      - bazaar_signature: "" (unknown at extract time)
      - bazaar_tags: "" (unknown at extract time)
      - os: "Windows"
      - arch: "unknown"
      - filetype: "exe (PE)"
      - is_dotnet: "unknown" (filled later by manifest_updater.py)
      - upx_detected: "unknown"
      - avg_section_entropy: ""
      - max_section_entropy: ""
      - imported_function_count: ""
      - notes: e.g. "basket-extracted"
    """
    import sys
    sys.path.insert(0, os.path.join(BASE, "Tools", "Manifestor"))
    from manifest_generator import load_manifest, sha256_of_file as mg_sha256

    # Actually, use our own sha256 function
    sha = sha256_of_file(path)

    # Load existing manifest and dedupe
    MANIFEST_PATH = os.path.join(BASE, "Data", "manifest.csv")
    existing_shas = set()
    if os.path.isfile(MANIFEST_PATH):
        with open(MANIFEST_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                s = (row.get("sha256") or "").strip().lower()
                if s:
                    existing_shas.add(s)

    if sha.lower() in existing_shas:
        return  # already in manifest

    filename = os.path.basename(path)
    row = {
        "sha256": sha,
        "filename": filename,
        "family": family,
        "source": source,
        "bazaar_signature": "",
        "bazaar_tags": "",
        "os": "Windows",
        "arch": "unknown",
        "filetype": "exe (PE)",
        "is_dotnet": "unknown",
        "upx_detected": "unknown",
        "avg_section_entropy": "",
        "max_section_entropy": "",
        "imported_function_count": "",
        "notes": "basket-extracted",
    }

    # Read existing manifest
    existing_rows = []
    if os.path.isfile(MANIFEST_PATH):
        with open(MANIFEST_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_rows.append(row)

    # Append new row
    existing_rows.append(row)

    # Write back using the 15-column schema from manifest_generator.py
    HEADER_COLUMNS = [
        "sha256", "filename", "family", "source", "bazaar_signature",
        "bazaar_tags", "os", "arch", "filetype", "is_dotnet",
        "upx_detected", "avg_section_entropy", "max_section_entropy",
        "imported_function_count", "notes",
    ]

    tmp = MANIFEST_PATH + ".tmp"
    with open(tmp, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER_COLUMNS)
        writer.writeheader()
        writer.writerows(existing_rows)

    os.replace(tmp, MANIFEST_PATH)


def ask_category():
    print("What kind of samples are in the Basket?")
    print("  1) AsyncRAT      (MalwareBazaar password-protected zips)")
    print("  2) Other Malware (MalwareBazaar password-protected zips)")
    print("  3) Regular executables (plain .exe, no extraction)")
    choice = input("Select 1/2/3: ").strip()
    return CATEGORIES.get(choice)


def extract_malware_zip(zip_path, dest_dir, zip_name):
    """Extract one password-protected zip into dest_dir. Return list of extracted file paths."""
    with pyzipper.AESZipFile(zip_path) as zf:
        zf.setpassword(PASSWORD)
        members = zf.namelist()
        file_members = [m for m in members if not m.endswith("/")]
        if not file_members:
            return []
        zf.extractall(dest_dir, pwd=PASSWORD)
        extracted = []
        for m in file_members:
            full = os.path.join(dest_dir, m)
            if os.path.isfile(full):
                extracted.append(full)
        return extracted


def organize_extracted(dest_dir, extracted_files, stem):
    """If more than one file was extracted, move them into a subfolder named after the zip stem."""
    if len(extracted_files) <= 1:
        return
    target_folder = os.path.join(dest_dir, stem)
    os.makedirs(target_folder, exist_ok=True)
    for src in extracted_files:
        if os.path.exists(src):
            shutil.move(src, os.path.join(target_folder, os.path.basename(src)))
    for src in extracted_files:
        parent = os.path.dirname(src)
        if parent != dest_dir and os.path.isdir(parent) and not os.listdir(parent):
            os.rmdir(parent)


def process_malware(category_name, dest_dir, zip_dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    os.makedirs(zip_dest_dir, exist_ok=True)

    zips = sorted(f for f in os.listdir(BASKET_DIR) if f.endswith(".zip"))
    if not zips:
        print(f"No .zip files found in {BASKET_DIR}")
        return

    log = []
    failed = 0
    total_extracted = 0

    for zip_name in zips:
        zip_path = os.path.join(BASKET_DIR, zip_name)
        stem = zip_name[:-4]
        try:
            extracted_files = extract_malware_zip(zip_path, dest_dir, zip_name)
            if not extracted_files:
                print(f"  SKIP  (no files): {zip_name}")
                log.append((zip_name, "skip_empty", "", ""))
                continue

            organize_extracted(dest_dir, extracted_files, stem)
            shutil.move(zip_path, os.path.join(zip_dest_dir, zip_name))

            total_extracted += len(extracted_files)
            detail = f"{len(extracted_files)} file(s)"
            if len(extracted_files) > 1:
                detail += f" -> folder '{stem}/'"
            print(f"  OK  {zip_name}: {detail}")

            # Append manifest row for each extracted file
            for extracted_file in extracted_files:
                if os.path.isfile(extracted_file):
                    append_manifest_row(extracted_file, category_name)

            log.append((zip_name, "ok", detail, ""))

        except RuntimeError as e:
            failed += 1
            print(f"  FAIL {zip_name}: {e}")
            log.append((zip_name, "password_error", "", str(e)))
        except Exception as e:
            failed += 1
            print(f"  ERR {zip_name}: {e}")
            log.append((zip_name, "error", "", str(e)))

    log_path = os.path.join(SCRIPT_DIR, "extraction_log.csv")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    with open(log_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["zip_file", "status", "detail", "error"])
        w.writerows(log)
    print(f"\nLog written to {log_path}")
    print(f"Summary: {len(zips)} zips processed, {failed} failed, {total_extracted} files extracted")


def process_regular():
    os.makedirs(REGULAR_DIR, exist_ok=True)
    exes = sorted(f for f in os.listdir(BASKET_DIR) if f.endswith(".exe"))
    if not exes:
        print(f"No .exe files found in {BASKET_DIR}")
        return

    moved = 0
    for exe_name in exes:
        src = os.path.join(BASKET_DIR, exe_name)
        dst = os.path.join(REGULAR_DIR, exe_name)
        if os.path.exists(dst):
            print(f"  SKIP  (already exists): {exe_name}")
            continue
        shutil.move(src, dst)
        print(f"  OK  {exe_name}")

        # Append manifest row for each moved exe
        append_manifest_row(dst, "benign")

        moved += 1

    print(f"\nSummary: {moved} exe(s) moved to {REGULAR_DIR}")


def dry_run_list(category_name, dest_dir, zip_dest_dir, is_zip):
    if is_zip:
        zips = sorted(f for f in os.listdir(BASKET_DIR) if f.endswith(".zip"))
        print(f"Would process {len(zips)} zip(s) from Basket as '{category_name}'")
        for z in zips:
            print(f"  {z} -> extract to {dest_dir}, zip -> {zip_dest_dir}")
    else:
        exes = sorted(f for f in os.listdir(BASKET_DIR) if f.endswith(".exe"))
        print(f"Would move {len(exes)} exe(s) from Basket to {dest_dir}")
        for e in exes:
            print(f"  {e} -> {dest_dir}")


def main():
    parser = argparse.ArgumentParser(description="Extractor for samples dropped in Samples/Basket")
    parser.add_argument("--execute", action="store_true",
                        help="Actually perform extraction/moves (default is dry run)")
    args = parser.parse_args()

    os.makedirs(BASKET_DIR, exist_ok=True)

    if not os.listdir(BASKET_DIR):
        print(f"Basket directory {BASKET_DIR} is empty. Drop files there first.")
        return

    selection = ask_category()
    if not selection:
        print("Invalid selection.")
        return

    category_name, dest_dir, zip_dest_dir, is_zip = selection

    print(f"\nCategory: {category_name}")
    print(f"Destination: {dest_dir}")
    if zip_dest_dir:
        print(f"Leftover zips: {zip_dest_dir}")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN (use --execute to apply)'}\n")

    if not is_zip:
        if args.execute:
            process_regular()
        else:
            dry_run_list(category_name, dest_dir, zip_dest_dir, is_zip)
    else:
        if args.execute:
            process_malware(category_name, dest_dir, zip_dest_dir)
        else:
            dry_run_list(category_name, dest_dir, zip_dest_dir, is_zip)

    if not args.execute:
        print("\nThis was a DRY RUN. Re-run with --execute to apply changes.")


if __name__ == "__main__":
    main()
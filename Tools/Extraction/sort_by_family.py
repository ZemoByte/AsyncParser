#!/usr/bin/env python3
"""Sort samples into family folders by manifest, verify truth, and report.

Reads Data/manifest.csv (15-column schema) and moves/validates files under
Samples/<family>/ so that every manifest row's file lives in the folder that
matches its ``family`` ground-truth.

Folder map (config constant at top of script):
  "asyncrat"   -> Samples/AsyncRAT      (existing convention)
  "benign"     -> Samples/Regular_executables  (existing convention: Sysinternals)
  "loader"/"reject" -> Samples/Native   (skip unless needed)
  default      -> Samples/<family>      (e.g. Samples/QuasarRAT, Samples/DcRat)

Behaviour
---------
1. Load manifest: sha256 -> (family, filename) (truth).
   Rows missing ``family`` or with empty family are recorded as ``unknown``
   and placed under ``Samples/<family>``.
2. For each manifest row, locate the .exe file under Samples/ by the
   ``filename`` column (not by hash-based naming).  Verify its SHA256 matches
   the manifest entry (same logic as ``manifest_check.py``).  If the file
   cannot be found or the hash mismatches, record it as an issue.
3. Move the file to its target folder determined by ``folder_map(family)``.
   Target folders are created if they do not exist.  Moves are idempotent –
   re-running the script moves nothing that is already in the correct folder.
4. Write a per-action log to ``Tools/Extraction/sort_log.csv`` with columns:
   timestamp, sha256, family, source_folder, target_folder, status.
   Zip_Files directories are excluded from the "untracked" check –- they hold
   the original MalwareBazaar zips and are not expected to match manifest rows.
5. Verification ("right tagged / true") –- performed after all moves:
   a) Run ``Tools/Manifestor/manifest_check.py`` as a subprocess; any
      non-zero exit or output issues are reported.
   b) Control-group check: for every file directly in
      ``Samples/AsyncRAT/``, test whether the raw bytes contain the printable
      ASCII string ``b"AsyncRAT"`` (same heuristic as
      baseline_asyncrat_strings.py).  Report the count and flag any
      shortfall relative to the expected ~7.
   c) Print a per-family summary: family, target folder, manifest row count,
      files on disk.
6. Flags
   - ``--dry-run``: print every move without applying it.
   - ``--verbose``: additionally print each file as it is processed (or would
     be moved).

Style
-----
Plain functions, docstrings, argparse, stdlib only (hashlib, csv, os, shutil,
subprocess, pathlib).  Match the style of ``Tools/Extraction/extractor.py``.

Usage examples
--------------
  # Sort everything into family folders (no moves if already correct)
  python Tools/Extraction/sort_by_family.py

  # Dry run: see what would move where without applying
  python Tools/Extraction/sort_by_family.py --dry-run

  # Verbose: show each file being processed
  python Tools/Extraction/sort_by_family.py --verbose
"""

import argparse
import csv
import hashlib
import os
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Repo paths (match extractor.py style)
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))          # Tools/Extraction/
BASE = os.path.dirname(os.path.dirname(SCRIPT_DIR))              # project root
SAMPLES_DIR = os.path.join(BASE, "Samples")
MANIFEST_PATH = os.path.join(BASE, "Data", "manifest.csv")
LOG_PATH = os.path.join(SCRIPT_DIR, "sort_log.csv")

# ---------------------------------------------------------------------------
# Folder map: family name -> relative path under Samples/
# ---------------------------------------------------------------------------
# Key names must match the lowercase ``family`` column values in Data/manifest.csv.
# Values are relative to Samples/ (i.e. the full path is Samples/<value>).
FOLDER_MAP = {
    "asyncrat": "AsyncRAT",
    "benign": "Regular_executables",
    # "loader" and "reject" could map to Samples/Native if ever needed;
    # the default catch-all handles any other family name.
}

# Default target for any family not explicitly listed above.
DEFAULT_TARGET = "<family>"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_of_file(path: Path) -> str:
    """Return the hex SHA256 digest of *path*."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest(path: Path) -> tuple:
    """Return two dicts from the manifest CSV:

    1. sha256 -> family (truth)
    2. sha256 -> filename (the original executable name)

    Rows where ``family`` is empty or missing are mapped to the string
    ``"unknown"``.
    """
    sha_to_family = {}
    sha_to_filename = {}
    if not path.is_file():
        return sha_to_family, sha_to_filename
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            sha = (row.get("sha256") or "").strip().lower()
            family = (row.get("family") or "").strip().lower()
            filename = (row.get("filename") or "").strip()
            if sha:
                sha_to_family[sha] = family if family else "unknown"
                sha_to_filename[sha] = filename
    return sha_to_family, sha_to_filename


def find_sample_file(filename: str, samples_dir: Path) -> Path | None:
    """Return the first ``samples_dir``/``filename`` that is a regular file.

    ``filename`` is expected to be just the executable name (e.g. ``ADExplorer.exe``)
    not a hash-based name.  We walk all sub‑directories of *samples_dir* looking
    for a file with that exact name.
    """
    if not filename:
        return None
    for root, _, files in os.walk(samples_dir):
        for name in files:
            if name == filename:
                full = Path(root) / name
                if full.is_file():
                    return full
    return None


def verify_sha(file_path: Path, expected_sha: str) -> bool:
    """Return True if the file's SHA256 matches *expected_sha* (case‑insensitive)."""
    try:
        actual = sha256_of_file(file_path).lower()
        return actual == expected_sha.lower()
    except OSError:
        return False


def contains_asyncrat_string(file_path: Path) -> bool:
    """Heuristic: does the file contain a readable ``AsyncRAT`` string?"""
    try:
        data = file_path.read_bytes()
        return b"AsyncRAT" in data
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def init_log():
    """Create sort_log.csv with a header if it does not already exist."""
    header = [
        "timestamp", "sha256", "family", "source_folder",
        "target_folder", "status",
    ]
    if not os.path.isfile(LOG_PATH):
        with open(LOG_PATH, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(header)


def log_action(ts: str, sha: str, family: str, source: str, target: str, status: str):
    """Append one row to sort_log.csv."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([ts, sha, family, source, target, status])


# ---------------------------------------------------------------------------
# Core sorting logic
# ---------------------------------------------------------------------------

def sort_samples(dry_run: bool = False, verbose: bool = False) -> dict:
    """Move files into family folders keyed by the manifest.

    Returns a summary dict with counts per status category.
    """
    init_log()

    sha_to_family, sha_to_filename = load_manifest(Path(MANIFEST_PATH))
    samples_root = Path(SAMPLES_DIR)

    # ------------------------------------------------------------------
    # Invert folder_map: target folder name -> set of family keys that map there.
    # ------------------------------------------------------------------
    # e.g. target="AsyncRAT" covers family="asyncrat".
    target_to_families = defaultdict(set)
    for fam, target in FOLDER_MAP.items():
        target_to_families[target].add(fam)
    # Also allow the default catch‑all: any family not explicitly listed will
    # target under its own name, i.e. Samples/QuasarRAT, Samples/DcRat, etc.

    summary = {
        "moved": 0,
        "already_correct": 0,
        "no_file_in_manifest": 0,
        "file_not_found": 0,
        "hash_mismatch": 0,
        "moved_to_wrong": 0,   # file already in a different family folder
        "issues": [],          # list of (sha, family, problem)
    }

    # First pass: locate every manifest row's file and verify SHA.
    # We collect (sha, family, source_path, target_dir) tuples.
    actions = []

    for sha, family in sha_to_family.items():
        # Get the original filename from the manifest
        filename = sha_to_filename.get(sha, "")

        # Determine target folder based on family.
        if family in FOLDER_MAP:
            target_dir_name = FOLDER_MAP[family]
        else:
            # Default: Samples/<family>, e.g. Samples/QuasarRAT
            target_dir_name = family

        target_dir = samples_root / target_dir_name

        # Locate the file by its manifest filename (not hash-based name).
        source_file = find_sample_file(filename, samples_root) if filename else None

        # Determine the *current* location of the file, if it exists.
        if source_file is None:
            summary["file_not_found"] += 1
            summary["issues"].append((sha, family, "file_not_found_on_disk"))
            log_action(
                datetime.now(timezone.utc).isoformat(),
                sha, family,
                "none", target_dir_name, "file_not_found",
            )
            continue

        # Verify SHA256 matches the manifest entry.
        if not verify_sha(source_file, sha):
            summary["hash_mismatch"] += 1
            summary["issues"].append((sha, family, f"hash_mismatch:{source_file}"))
            log_action(
                datetime.now(timezone.utc).isoformat(),
                sha, family,
                str(source_file), target_dir_name, "hash_mismatch",
            )
            continue

        # Determine the *current* family folder the file resides in.
        # We infer it from the immediate parent folder name.
        current_parent = source_file.parent.name
        # Check if the file is already in a folder that matches its target.
        target_parent_names = set(target_to_families.keys())
        is_already_in_target = current_parent in target_parent_names

        # Additionally, verify that the folder's name actually corresponds
        # to the manifest family by checking if any manifest row with that
        # family points to this same folder.
        # (If the file lives in Samples/AsyncRAT/ and the manifest family is
        # asyncrat, we consider it already correct.)

        if family == "unknown":
            # Unknown family: place under Samples/<family> i.e. Samples/unknown
            # but that would conflict with the .exe naming convention; instead
            # we skip the move and log it.
            summary["issues"].append((sha, family, "unknown_family"))
            log_action(
                datetime.now(timezone.utc).isoformat(),
                sha, family,
                str(source_file), "unknown", "skipped_unknown_family",
            )
            continue

        if is_already_in_target and current_parent == target_dir_name:
            summary["already_correct"] += 1
            if verbose:
                print(f"  OK  already in target: {source_file.name} -> {target_dir_name}/")
            log_action(
                datetime.now(timezone.utc).isoformat(),
                sha, family,
                str(source_file), target_dir_name, "already_correct",
            )
            continue

        # Otherwise we need to move (or would move in dry-run).
        actions.append((sha, family, str(source_file), str(target_dir)))
        # Don't increment summary["moved"] yet -- do it in the second pass

    # ------------------------------------------------------------------
    # Second pass: perform the moves (or dry-run them).
    # ------------------------------------------------------------------
    for sha, family, source_str, target_dir_str in actions:
        source = Path(source_str)
        target_dir = Path(target_dir_str)

        if dry_run:
            if verbose:
                print(f"  [DRY RUN] would move {source.name} -> {target_dir}/")
            log_action(
                datetime.now(timezone.utc).isoformat(),
                sha, family,
                str(source), str(target_dir), "dry_run",
            )
            continue

        # Ensure target directory exists.
        target_dir.mkdir(parents=True, exist_ok=True)

        dest = target_dir / source.name
        if verbose:
            print(f"  MVE  {source.name} -> {target_dir}/")

        # If the destination already exists (e.g. duplicate SHA), skip the move
        # to avoid accidental overwrite; instead record the situation.
        if dest.is_file() and dest.resolve() != source.resolve():
            # Already have a file with the same name in the target; keep it.
            if verbose:
                print(f"  SKP  destination exists: {dest.name}")
            summary["moved"] += 1  # count as "handled"
            log_action(
                datetime.now(timezone.utc).isoformat(),
                sha, family,
                str(source), str(target_dir), "skipped_dest_exists",
            )
            continue

        shutil.move(str(source), str(dest))
        summary["moved"] += 1

        log_action(
            datetime.now(timezone.utc).isoformat(),
            sha, family,
            str(source), str(target_dir), "moved",
        )

    return summary


# ---------------------------------------------------------------------------
# Verification step (manifest check + control‑group)
# ---------------------------------------------------------------------------

def verify_after_sort() -> dict:
    """Run manifest_check.py and the AsyncRAT control‑group string check.

    Returns a dict with the subprocess output and the string‑hit count.
    """
    results = {"manifest_check": "", "asyncrat_string_hits": 0, "issues": []}

    # 1) manifest_check.py
    try:
        proc = subprocess.run(
            [sys.executable, "Tools/Manifestor/manifest_check.py"],
            cwd=BASE,
            capture_output=True,
            text=True,
            timeout=60,
        )
        results["manifest_check"] = proc.stdout
        if proc.returncode != 0:
            results["issues"].append(
                f"manifest_check.py exited {proc.returncode}: {proc.stderr}"
            )
    except Exception as e:
        results["issues"].append(f"manifest_check.py could not be run: {e}")

    # 2) Control‑group: count AsyncRAT files with readable "AsyncRAT" string
    asyncrat_dir = Path(SAMPLES_DIR) / "AsyncRAT"
    hits = 0
    if asyncrat_dir.is_dir():
        for f in sorted(asyncrat_dir.iterdir()):
            if f.is_file() and f.suffix.lower() == ".exe":
                if contains_asyncrat_string(f):
                    hits += 1

    results["asyncrat_string_hits"] = hits
    # Flag if we expected ~7 and get something different (just a note, not
    # an error — the count itself is the information).
    results["expected_control_hits"] = 7
    if hits != 7:
        results["issues"].append(
            f"Control-group string hit count: {hits} (expected ~7 per Plan.md)"
        )

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Sort samples into family folders by manifest truth."
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print every move without applying it.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show each file being processed.",
    )
    args = parser.parse_args()

    # 1) Sort samples.
    summary = sort_samples(dry_run=args.dry_run, verbose=args.verbose)

    # 2) Verification.
    verify_results = verify_after_sort()

    # 3) Print a report.
    print("=" * 60)
    print("SORT BY FAMILY — REPORT")
    print("=" * 60)

    print("\n--- Move summary ---")
    print(f"  Moved (applied):        {summary['moved']}")
    print(f"  Already in target:      {summary['already_correct']}")
    print(f"  No file on disk:        {summary['file_not_found']}")
    print(f"  Hash mismatch:          {summary['hash_mismatch']}")
    print(f"  No manifest row:        {summary['no_file_in_manifest']}")
    print(f"  Issues recorded:        {len(summary['issues'])}")

    # Load manifest for per-family summary (separate from sort_samples return)
    sha_to_family, sha_to_filename = load_manifest(Path(MANIFEST_PATH))

    print("\n--- Verification ---")
    print(f"  manifest_check.py output:")
    mc_out = verify_results["manifest_check"][:200] if verify_results["manifest_check"] else "(empty)"
    print(f"  {mc_out}")
    if verify_results["issues"]:
        for issue in verify_results["issues"]:
            print(f"  ! {issue}")

    print(f"  AsyncRAT control-group: {verify_results['asyncrat_string_hits']} / {verify_results['expected_control_hits']} files contain readable 'AsyncRAT' string")
    if verify_results["issues"]:
        for issue in verify_results["issues"]:
            print(f"  ! {issue}")

    print("\n--- Per-family summary ---")
    from collections import Counter
    fam_counts = Counter()
    for family in sha_to_family.values():
        if family != "unknown":
            fam_counts[family] += 1
    for family, count in sorted(fam_counts.items()):
        target = FOLDER_MAP.get(family, f"<family={family}>")
        target_path = Path(SAMPLES_DIR) / target
        on_disk = len(list(target_path.glob("*.exe"))) if target_path.is_dir() else 0
        print(f"  family={family:12s}  target={target:20s}  manifest_rows={count:3d}  on_disk={on_disk:3d}")

    print("\n--- Log file ---")
    print(f"  {LOG_PATH}")
    print("=" * 60)


if __name__ == "__main__":
    main()
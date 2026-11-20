#!/usr/bin/env python3
"""Download malware samples from MalwareBazaar and add them to the dataset.

Pulls non-AsyncRAT malware (QuasarRAT, DcRat, VenomRAT, njRat, Remcos, etc.)
into Samples/Other_Malwares/ and appends 15-column manifest rows so Phase 9's
3-class design has real `other` samples to train on.

API: https://mb-api.abuse.ch/api/v1/  (free key from abuse.ch).
Never hardcode or print the key — take it via --auth-key or the
MB_AUTH_KEY environment variable.  If MB_AUTH_KEY is set in a repo-root .env
file it will be loaded automatically; otherwise pass --auth-key on the command
line or set the env var in your shell.

Usage examples:
  # Download 10 samples by signature (QuasarRAT)
  python Tools/Extraction/mb_downloader.py \
      --auth-key "$MB_AUTH_KEY" --limit 10 --signature QuasarRAT

  # Download by repeatable tags (each tag needs its own --tag flag)
  python Tools/Extraction/mb_downloader.py \
      --auth-key "$MB_AUTH_KEY" --limit 20 --tag RAT --tag .NET

  # Dry run first, then execute
  python Tools/Extraction/mb_downloader.py --auth-key "$MB_AUTH_KEY" --limit 5 --signature QuasarRAT --dry-run
  python Tools/Extraction/mb_downloader.py --auth-key "$MB_AUTH_KEY" --limit 5 --signature QuasarRAT

  # Using .env (no --auth-key needed if key is in .env)
  python Tools/Extraction/mb_downloader.py --limit 10 --signature QuasarRAT
"""
import argparse
import csv
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pyzipper

# ---------------------------------------------------------------------------
# Repo paths (match the style of extractor.py)
# ---------------------------------------------------------------------------
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))          # Tools/Extraction/
BASE = os.path.dirname(os.path.dirname(SCRIPT_DIR))              # project root
SAMPLES_DIR = os.path.join(BASE, "Samples")
MANIFEST_PATH = os.path.join(BASE, "Data", "manifest.csv")
OTHER_DIR = os.path.join(SAMPLES_DIR, "Other_Malwares")
LOG_PATH = os.path.join(SCRIPT_DIR, "mb_download_log.csv")

# API config
API_URL = "https://mb-api.abuse.ch/api/v1/"
DEFAULT_RATE_SEC = 0.4        # ~0.3–0.5 s between downloads
DAILY_CAP = 1800              # stop at ~1800 of the 2000/IP/day hard cap

# ---------------------------------------------------------------------------
# Optional .env loader — first-class way to supply MB_AUTH_KEY
# Reads repo-root .env as KEY=VALUE lines; ignores comments (lines starting with #)
# and blank lines. Does NOT override MB_AUTH_KEY if already set in the environment.
# ---------------------------------------------------------------------------
def _load_env():
    """Load MB_AUTH_KEY from .env if not already in the environment."""
    env_path = Path(BASE) / ".env"
    if not env_path.is_file():
        return
    if os.environ.get("MB_AUTH_KEY"):
        # Already set — respect the existing value; do not override
        return
    try:
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" in line:
                    key, _, value = line.partition("=")
                    key = key.strip()
                    value = value.strip()
                    if key == "MB_AUTH_KEY":
                        os.environ["MB_AUTH_KEY"] = value
                        break
    except Exception:
        pass  # best-effort only


_load_env()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sha256_of_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_existing_shas() -> set:
    """Return set of sha256 strings already in manifest.csv + on disk."""
    shas = set()

    # From manifest
    if os.path.isfile(MANIFEST_PATH):
        with open(MANIFEST_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                s = (row.get("sha256") or "").strip().lower()
                if s:
                    shas.add(s)

    # From Samples/Other_Malwares/ (files already extracted)
    if os.path.isdir(OTHER_DIR):
        for p in Path(OTHER_DIR).rglob("*.exe"):
            try:
                shas.add(sha256_of_file(p))
            except OSError:
                pass

    return shas


def append_manifest_rows(rows: list) -> None:
    """Append 15-column schema rows to Data/manifest.csv.

    Each row is a list matching HEADER_COLUMNS from manifest_generator.py.
    Uses the --append pattern from that script (safe to point at Data/manifest.csv).
    """
    HEADER_COLUMNS = [
        "sha256", "filename", "family", "source", "bazaar_signature",
        "bazaar_tags", "os", "arch", "filetype", "is_dotnet",
        "upx_detected", "avg_section_entropy", "max_section_entropy",
        "imported_function_count", "notes",
    ]

    # Read existing
    existing_rows = []
    existing_shas = set()
    if os.path.isfile(MANIFEST_PATH):
        with open(MANIFEST_PATH, newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                existing_rows.append(row)
                s = (row.get("sha256") or "").strip().lower()
                if s:
                    existing_shas.add(s)

    # Add new, deduped
    new_rows_count = 0
    for row_dict in rows:
        sha = row_dict.get("sha256", "").strip().lower()
        if sha and sha in existing_shas:
            continue
        existing_rows.append(row_dict)
        existing_shas.add(sha)
        new_rows_count += 1

    if new_rows_count == 0:
        return

    # Write back
    tmp = MANIFEST_PATH + ".tmp"
    with open(tmp, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=HEADER_COLUMNS)
        writer.writeheader()
        writer.writerows(existing_rows)

    os.replace(tmp, MANIFEST_PATH)
    print(f"  Appended {new_rows_count} row(s) to {MANIFEST_PATH}")


def log_action(ts_iso: str, sha: str, family: str, path: str, status: str = "ok", detail: str = "") -> None:
    """Append one action to the download log CSV."""
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    file_exists = os.path.isfile(LOG_PATH)
    with open(LOG_PATH, "a", newline="") as f:
        w = csv.writer(f)
        if not file_exists:
            w.writerow(["timestamp", "sha256", "family", "path", "status", "detail"])
        w.writerow([ts_iso, sha, family, path, status, detail])


def rate_limit(last_ts: float) -> float:
    """Sleep if needed to respect the ~0.3–0.5 s rate. Returns the actual sleep time."""
    elapsed = time.monotonic() - last_ts
    if elapsed < DEFAULT_RATE_SEC:
        time.sleep(DEFAULT_RATE_SEC - elapsed)
    return time.monotonic()
# ---------------------------------------------------------------------------
# API conversation
# ---------------------------------------------------------------------------

def api_post(query: str, auth_key: str) -> dict | bytes:
    """POST to the MalwareBazaar API.
    
    Returns parsed JSON dict if the response is JSON, or raw bytes if binary.
    Returns dict with "errors" key on failure.
    """
    import urllib.request
    import json
    
    data = f"query={query}".encode("utf-8")
    req = urllib.request.Request(
        API_URL,
        data=data,
        method="POST",
        headers={"Auth-Key": auth_key, "Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            # Try to decode as JSON first
            try:
                text = raw.decode("utf-8")
                return json.loads(text)
            except (json.JSONDecodeError, UnicodeDecodeError):
                # Not JSON — return raw bytes (e.g. ZIP from get_file)
                return raw
    except Exception as e:
        print(f"  API error: {e}", file=sys.stderr)
        return {"errors": [str(e)]}


def discover_signatures(auth_key: str, signatures: list) -> list:
    """Query get_siginfo for each signature name; return list of siginfo dicts."""
    results = []
    for sig in signatures:
        print(f"  Discovering signature: {sig}")
        resp = api_post(f"get_siginfo&signature={sig}&limit=1000", auth_key)
        if resp.get("errors"):
            print(f"    SKIP (no info for signature '{sig}': {resp['errors']})", file=sys.stderr)
            continue
        # resp may contain a list under 'data' or just siginfo fields
        data = resp.get("data", [])
        if isinstance(data, list):
            results.extend(data)
        results.append(resp)  # keep the siginfo too
        time.sleep(DEFAULT_RATE_SEC)
    return results


def discover_tags(auth_key: str, tags: list) -> list:
    """Query get_taginfo for each tag name; return list of taginfo dicts."""
    results = []
    for tag in tags:
        print(f"  Discovering tag: {tag}")
        resp = api_post(f"get_taginfo&tag={tag}&limit=1000", auth_key)
        if resp.get("errors"):
            print(f"    SKIP (no info for tag '{tag}': {resp['errors']})", file=sys.stderr)
            continue
        data = resp.get("data", [])
        if isinstance(data, list):
            results.extend(data)
        results.append(resp)
        time.sleep(DEFAULT_RATE_SEC)
    return results


def download_file(auth_key: str, sha256_hash: str) -> bytes | None:
    """Download a sample ZIP via get_file query. Returns raw ZIP bytes, or None."""
    result = api_post(f"get_file&sha256_hash={sha256_hash}&limit=1", auth_key)
    
    # api_post may return a dict (JSON error response) or bytes (binary ZIP)
    if isinstance(result, dict):
        # JSON response — check for errors
        if result.get("errors"):
            print(f"    SKIP (download failed: {result['errors']})", file=sys.stderr)
            return None
        # Unexpected JSON response — treat as failure
        print(f"    SKIP (unexpected JSON response from get_file)", file=sys.stderr)
        return None
    
    # Binary response — raw ZIP bytes
    zip_bytes = result
    if not zip_bytes:
        print(f"    SKIP (empty ZIP data)", file=sys.stderr)
        return None
    
    return zip_bytes
# ---------------------------------------------------------------------------
# Sample processing (unzip + save + manifest)
# ---------------------------------------------------------------------------

def unzip_and_save(zip_bytes: bytes, dest_dir: Path, filename: str) -> Path | None:
    """Unzip MalwareBazaar ZIP (password "infected") and save the .exe.

    Returns the path to the saved .exe, or None on failure.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)

    # Write ZIP to a temp file so pyzipper can read it
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as zf:
        zf.write(zip_bytes)
        zip_path = zf.name

    try:
        with pyzipper.AESZipFile(zip_path) as zf:
            zf.setpassword(b"infected")
            # Extract all members
            zf.extractall(dest_dir, pwd=b"infected")
        # Find the .exe file(s) just extracted
        extracted_exes = list(dest_dir.rglob("*.exe"))
        if not extracted_exes:
            # Maybe the zip just has top-level files without .exe extension mask
            extracted_exes = [f for f in dest_dir.iterdir() if f.suffix.lower() == ".exe"]
        if not extracted_exes:
            print(f"    WARN  no .exe found in zip for {filename}", file=sys.stderr)
            # Clean up the zip temp file already handled; return None
            return None

        # If multiple files, move the first one using the stem folder pattern
        # (matching extractor.py's organize_extracted style)
        target = extracted_exes[0]
        # If there are multiple, create a subfolder named after the stem
        if len(extracted_exes) > 1:
            stem = Path(filename).stem
            subfolder = dest_dir / stem
            subfolder.mkdir(parents=True, exist_ok=True)
            for exe in extracted_exes:
                if exe.name != target.name:  # don't move the first one twice
                    exe.rename(subfolder / exe.name)
            # re-scan for the primary target
            extracted_exes = list(dest_dir.rglob("*.exe"))

        # Dedupe by sha256 against what's already on disk
        target_sha = sha256_of_file(target)
        # We'll check dedup in the caller; just return the path
        os.unlink(zip_path)  # clean up temp
        return target
    except RuntimeError as e:
        print(f"    FAIL  password error for {filename}: {e}", file=sys.stderr)
        os.unlink(zip_path)
        return None
    except Exception as e:
        print(f"    FAIL  extraction error for {filename}: {e}", file=sys.stderr)
        os.unlink(zip_path)
        return None


def build_manifest_row(sha256: str, filename: str, signature: str, tags: list, family: str) -> dict:
    """Build a 15-column manifest row dict for a new sample."""
    import re

    # Parse os/arch from filename heuristics, or default
    os_val = "Windows"   # MalwareBazaar .exes are typically Windows
    arch_val = "unknown"
    filetype_val = "exe (PE)"

    # Build notes from available info
    note_parts = []
    if signature:
        note_parts.append(f"signature={signature}")
    if tags:
        note_parts.append(f"tags={','.join(tags)}")
    notes_val = " | ".join(note_parts) if note_parts else ""

    return {
        "sha256": sha256,
        "filename": filename,
        "family": family,
        "source": "MalwareBazaar",
        "bazaar_signature": signature or "",
        "bazaar_tags": ",".join(tags) if tags else "",
        "os": os_val,
        "arch": arch_val,
        "filetype": filetype_val,
        "is_dotnet": "unknown",
        "upx_detected": "unknown",
        "avg_section_entropy": "",
        "max_section_entropy": "",
        "imported_function_count": "",
        "notes": notes_val,
    }
# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="MalwareBazaar sample downloader for AsyncParser")
    parser.add_argument("--auth-key", required=not os.environ.get("MB_AUTH_KEY"),
                        help="MalwareBazaar API key (or set MB_AUTH_KEY env var)")
    parser.add_argument("--limit", type=int, default=20,
                        help="Max total samples to download (default: 20)")
    parser.add_argument("--tag", action="append", default=[],
                        help="Tag to search (repeatable; e.g. RAT .NET). Overridden by --signature if both given.")
    parser.add_argument("--signature", action="append", default=[],
                        help="Signature name to search (repeatable; e.g. QuasarRAT DcRat).")
    parser.add_argument("--dry-run", action="store_true",
                        help="Discover signatures/tags and preview rows; do not download or write files")
    args = parser.parse_args()

    # Auth key: prefer env var, then CLI
    auth_key = os.environ.get("MB_AUTH_KEY", "").strip()
    if not auth_key:
        if args.auth_key:
            auth_key = args.auth_key.strip()
        else:
            parser.error("--auth-key is required. Get a free key at https://mb-api.abuse.ch/")

    # If tags given but no signatures, we discover by tag first; if signatures given,
    # we discover by signature. Allow both.
    signatures = args.signature if args.signature else []
    tags = args.tag if args.tag else []

    # Load existing sha256s for dedup
    existing_shas = load_existing_shas()
    print(f"Existing samples (manifest + disk): {len(existing_shas)}")

    # Discover samples from MalwareBazaar
    to_download = []  # list of (sha256, filename, signature, family)
    seen_in_api = set()

    # --- Discover by signature ---
    if signatures:
        print(f"\nDiscovering by signature(s): {signatures}")
        sig_info = discover_signatures(auth_key, signatures)
        for info in sig_info:
            # The siginfo response typically has: sha256_hash, file_name, signature, threat_name, etc.
            sha = info.get("sha256_hash") or info.get("sha256") or ""
            fname = info.get("file_name") or info.get("filename") or ""
            sig_name = info.get("signature") or ""
            threat = info.get("threat_name") or ""
            if not sha or not fname:
                continue
            sha = sha.lower()
            if sha in seen_in_api or sha in existing_shas:
                continue
            seen_in_api.add(sha)
            # family = threat name or we map it; default to Other_Malware family
            family = sig_name or "Other_Malware"
            # Use a sensible filename; MalwareBazaar filenames may include path, take just the stem
            if fname:
                # normalize: just the executable name
                target_name = Path(fname).name
                if not target_name.lower().endswith(".exe"):
                    target_name += ".exe"
            else:
                target_name = f"{sha[:12]}.exe"
            to_download.append((sha, target_name, sig_name, family))
            print(f"  Queued: {target_name} ({sig_name})")

    # --- Discover by tag ---
    if tags:
        print(f"\nDiscovering by tag(s): {tags}")
        tag_info = discover_tags(auth_key, tags)
        for info in tag_info:
            sha = info.get("sha256_hash") or info.get("sha256") or ""
            fname = info.get("file_name") or info.get("filename") or ""
            tag_name = info.get("tag") or ""
            if not sha or not fname:
                continue
            sha = sha.lower()
            if sha in seen_in_api or sha in existing_shas:
                continue
            seen_in_api.add(sha)
            family = "Other_Malware"
            # Note: tag-based downloads default family to Other_Malware since
            # get_taginfo doesn't return a specific signature. Use --signature
            # instead if you need real family names (QuasarRAT, DcRat, etc.).
            target_name = Path(fname).name
            if not target_name.lower().endswith(".exe"):
                target_name += ".exe"
            to_download.append((sha, target_name, tag_name, family))
            print(f"  Queued: {target_name} ({tag_name})")

    if not to_download:
        print("No new samples to download. Exiting.")
        return

    # Cap at --limit total
    to_download = to_download[:args.limit]
    print(f"\nWill attempt to download {len(to_download)} sample(s) (capped by --limit {args.limit})")

    # --- Dry run: just preview rows ---
    if args.dry_run:
        print("\n--- DRY RUN: preview of manifest rows that would be appended ---")
        for sha, fname, sig, family in to_download:
            row = build_manifest_row(sha, fname, sig, [], family)
            print(f"  sha={sha[:12]}... family={family} filename={fname} notes={row['notes']}")
        print(f"Total would append: {len(to_download)} rows")
        return

    # --- Actual download ---
    downloaded = 0
    skipped = 0
    failed = 0
    rows_to_append = []

    last_ts = time.monotonic()

    for i, (sha, fname, sig, family) in enumerate(to_download, start=1):
        # Rate limit
        last_ts = rate_limit(last_ts)

        # Check dedup one more time against what we've already added in this run
        # (existing_shas was loaded at start; we track added sha256s in a set)
        # We'll maintain our own set
        pass  # placeholder - dedup handled below

        print(f"[{i}/{len(to_download)}] Downloading {fname} (sha256={sha[:12]}...)")

        # Download the ZIP
        zip_bytes = download_file(auth_key, sha)
        if zip_bytes is None:
            failed += 1
            log_action(datetime.now(timezone.utc).isoformat(), sha, family, fname, "download_error")
            skipped += 1  # count as skipped since we moved on
            continue

        # Unzip and save
        target_path = unzip_and_save(zip_bytes, Path(OTHER_DIR), fname)
        if target_path is None:
            failed += 1
            log_action(datetime.now(timezone.utc).isoformat(), sha, family, fname, "extraction_error")
            skipped += 1
            continue

        # Dedup: verify sha256 matches what we downloaded
        actual_sha = sha256_of_file(target_path)
        if actual_sha.lower() != sha.lower():
            print(f"    WARN  sha256 mismatch: manifest={actual_sha[:12]}... disk computed from file, expected={sha[:12]}...", file=sys.stderr)
            # Still use the file we extracted; mark as downloaded but note the mismatch
            actual_sha = actual_sha.lower()
        else:
            print(f"    OK    sha256 matches: {actual_sha[:12]}...")

        # Build manifest row
        row = build_manifest_row(actual_sha, target_path.name, sig or "", tags or [], family)
        rows_to_append.append(row)
        downloaded += 1

        # Log
        log_action(datetime.now(timezone.utc).isoformat(), actual_sha, family, target_path.name, "ok")

        # Small pause after each successful download (rate limit handled per-iteration)
        if downloaded < len(to_download):
            # Additional cooldown to be kind to the API
            time.sleep(DEFAULT_RATE_SEC)

    print(f"\n=== Download summary ===")
    print(f"  Downloaded: {downloaded}")
    print(f"  Skipped (already on disk / dedup): {skipped}")
    print(f"  Failed: {failed}")
    print(f"  Saved to: {OTHER_DIR}")

    # --- Append manifest rows ---
    if rows_to_append:
        print(f"Appending {len(rows_to_append)} manifest row(s)...")
        append_manifest_rows(rows_to_append)
    else:
        print("No new rows to append (all deduped).")

    # --- Run manifest_updater.py and manifest_check.py ---
    print("\nRunning manifest_updater.py to fill PE fingerprint columns...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, "Tools", "Manifestor", "manifest_updater.py")],
            cwd=BASE, capture_output=True, text=True, timeout=120
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        if result.returncode != 0:
            print("WARNING: manifest_updater.py exited with non-zero code.")
    except Exception as e:
        print(f"Error running manifest_updater.py: {e}")

    print("Running manifest_check.py to validate manifest integrity...")
    try:
        result = subprocess.run(
            [sys.executable, os.path.join(BASE, "Tools", "Manifestor", "manifest_check.py")],
            cwd=BASE, capture_output=True, text=True, timeout=60
        )
        print(result.stdout)
        if result.stderr:
            print("STDERR:", result.stderr)
        if result.returncode != 0:
            print("WARNING: manifest_check.py exited with non-zero code. Review issues above.")
    except Exception as e:
        print(f"Error running manifest_check.py: {e}")

    # Final summary
    print(f"\n=== Final summary ===")
    print(f"  Downloaded: {downloaded}")
    print(f"  Families present in this run: {set(r['family'] for r in rows_to_append if r)}")
    print(f"  Saved to: {OTHER_DIR}")
    print(f"  Manifest rows appended: {len(rows_to_append)}")
    print(f"  Log file: {LOG_PATH}")
    if downloaded > 0:
        print("\nNow run: Tools/Manifestor/manifest_updater.py && Tools/Manifestor/manifest_check.py")
    else:
        print("\nNo samples downloaded. Check your API key, signatures/tags, and try again.")


if __name__ == "__main__":
    main()
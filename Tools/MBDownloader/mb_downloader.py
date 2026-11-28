#!/usr/bin/env python3
"""Interactive MalwareBazaar sample downloader for an academic dataset."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import itertools
import json
import os
import re
import signal
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

import pyzipper
import tlsh

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from Tools._label_common import FAMILY_MAP, FAMILY_VERDICTS  # noqa: E402

SAMPLES_DIR = ROOT / "Samples"
ASYNCRAT_DIR = SAMPLES_DIR / "AsyncRAT"
OTHER_DIR = SAMPLES_DIR / "OtherMalwares"
BENIGN_DIR = SAMPLES_DIR / "Benign"
DB_PATH = SCRIPT_DIR / "samples.db"
TEMP_DIR = SCRIPT_DIR / "temp"
COMPARISON_DB = TEMP_DIR / "comparison.db"

API_URL = "https://mb-api.abuse.ch/api/v1/"
ZIP_PASSWORD = b"infected"
TAG_LIMIT = 500  # the API returns 502 / "error" at the documented max of 1000
DAILY_CAP = 1200
MAX_ERRORS = 10
MAX_ATTEMPTS = 5

TYPE_ALIASES = {"javascript": "js", "powershell": "ps1"}
EXT_BY_TYPE = {
    "exe": "exe", "dll": "dll", "ps1": "ps1", "bat": "bat", "cmd": "cmd",
    "js": "js", "vbs": "vbs", "hta": "hta", "scr": "scr", "msi": "msi",
    "lnk": "lnk", "jar": "jar",
}

STOP = {"requested": False, "in_run": False}
RAT_TAG_ALIASES = {
    alias for alias, canonical in FAMILY_MAP.items()
    if canonical in FAMILY_VERDICTS
}


class ApiError(Exception):
    pass


class StopRun(Exception):
    pass


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def on_sigint(_signum, _frame) -> None:
    if STOP["in_run"]:
        STOP["requested"] = True
    else:
        raise KeyboardInterrupt


signal.signal(signal.SIGINT, on_sigint)


def interruptible_sleep(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        if STOP["requested"]:
            return
        time.sleep(min(1.0, end - time.monotonic()))


# ---------------------------------------------------------------- auth / env

def load_auth_key() -> str:
    env_path = next((path for path in (SCRIPT_DIR / ".env", ROOT / ".env")
                     if path.is_file()), None)
    if env_path is None:
        print("ERROR: .env not found in the script folder or the project root", file=sys.stderr)
        raise SystemExit(1)
    values = {}
    for raw in env_path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    auth_key = values.get("MB_AUTH_KEY", "")
    if not auth_key:
        print("ERROR: MB_AUTH_KEY is missing or empty in .env", file=sys.stderr)
        raise SystemExit(1)
    return auth_key


# ---------------------------------------------------------------------- API

def with_watchdog(func, timeout: float):
    """Run a blocking call on a daemon thread; never wait longer than timeout."""
    result = {}

    def worker():
        try:
            result["value"] = func()
        except BaseException as exc:
            result["error"] = exc

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    deadline = time.monotonic() + timeout
    while thread.is_alive() and time.monotonic() < deadline:
        if STOP["requested"]:
            raise StopRun("Ctrl+C")
        thread.join(min(0.25, deadline - time.monotonic()))
    if thread.is_alive():
        raise TimeoutError(f"API call produced no response within {timeout:g}s")
    if "error" in result:
        raise result["error"]
    return result["value"]


def read_response(request):
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def api_post(auth_key: str, fields: dict, binary: bool, state: dict):
    data = urllib.parse.urlencode(fields).encode("utf-8")
    last_error = "unknown error"
    for attempt in range(1, MAX_ATTEMPTS + 1):
        if STOP["requested"]:
            raise StopRun("Ctrl+C")
        request = urllib.request.Request(
            API_URL,
            data=data,
            headers={"Auth-Key": auth_key, "User-Agent": "AsyncParser-MBDownloader/1.0"},
            method="POST",
        )
        if attempt > 1:
            console("RETRY", f"{fields['query']} attempt {attempt}/{MAX_ATTEMPTS}")
        try:
            body = with_watchdog(lambda: read_response(request), 35)
            state["consecutive_429"] = 0
            return body if binary else json.loads(body.decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 429:
                state["consecutive_429"] += 1
                if state["consecutive_429"] >= 3:
                    raise StopRun("HTTP 429 repeated; stopping this run")
                header = exc.headers.get("Retry-After")
                try:
                    delay = max(1, int(header))
                except (TypeError, ValueError):
                    delay = 2 ** state["consecutive_429"]
                console("THROTTLE", f"HTTP 429, waiting {delay}s")
                interruptible_sleep(delay)
                continue
            if 400 <= exc.code < 500:
                raise ApiError(f"HTTP {exc.code}: {exc.reason}")
            last_error = f"HTTP {exc.code}: {exc.reason}"
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last_error = f"network error: {exc}"
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            last_error = f"bad JSON response: {exc}"
        if attempt < MAX_ATTEMPTS:
            interruptible_sleep(2 ** (attempt - 1))
    raise ApiError(last_error)


def get_taginfo(auth_key: str, tag: str, state: dict) -> list:
    result = api_post(auth_key, {"query": "get_taginfo", "tag": tag, "limit": TAG_LIMIT},
                      binary=False, state=state)
    if not isinstance(result, dict):
        raise ApiError("get_taginfo: unexpected response")
    data = result.get("data")
    if not isinstance(data, list):
        raise ApiError(f"get_taginfo: {result.get('query_status', 'no data')}")
    return data


def get_file(auth_key: str, sha256: str, state: dict) -> bytes:
    body = api_post(auth_key, {"query": "get_file", "sha256_hash": sha256},
                    binary=True, state=state)
    if body.startswith(b"PK"):
        return body
    try:
        status = json.loads(body.decode("utf-8")).get("query_status", "unexpected response")
    except (UnicodeDecodeError, json.JSONDecodeError):
        status = "unexpected response"
    raise ApiError(f"get_file: {status}")


# ------------------------------------------------------------------ prompts

def prompt_file_types() -> list:
    while True:
        raw = input("File type(s), comma separated [exe]: ").strip()
        if not raw:
            return ["exe"]
        requested = [part.strip().lower() for part in raw.split(",") if part.strip()]
        unknown = [item for item in requested if TYPE_ALIASES.get(item, item) not in EXT_BY_TYPE]
        if unknown:
            print("Rejected: " + ", ".join(unknown) + ". Documents and Linux files are not supported.")
            print("Supported: " + ", ".join(sorted(EXT_BY_TYPE)))
            continue
        result = []
        for item in requested:
            normalized = TYPE_ALIASES.get(item, item)
            if normalized not in result:
                result.append(normalized)
        return result


def prompt_yes_no(question: str, default_no: bool = True) -> bool:
    suffix = " [y/N]: " if default_no else " [Y/n]: "
    while True:
        answer = input(question + suffix).strip().lower()
        if not answer:
            return not default_no
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no"):
            return False
        print("Answer yes or no.")


def prompt_secondary_tag() -> str:
    """Return an empty string, '*' for Surprise Me, or a required tag name."""
    while True:
        answer = input("Secondary tag [y/N/S]: ").strip().lower()
        if answer in ("", "n", "no"):
            return ""
        if answer in ("s", "surprise", "surprise me", "*"):
            return "*"
        if answer in ("y", "yes"):
            while True:
                tag = input("Secondary tag name: ").strip()
                if tag:
                    return tag
                print("Enter a tag name.")
        print("Answer y, n or s.")


def prompt_rate() -> int:
    while True:
        raw = input("Downloads per minute [10]: ").strip()
        if not raw:
            return 10
        try:
            value = int(raw)
        except ValueError:
            print("Enter a whole number.")
            continue
        if value < 1:
            print("Must be at least 1.")
            continue
        return value


# ----------------------------------------------------------------- database

def text_field(value) -> str:
    return "" if value is None else str(value)


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        conn.commit()


def init_main_db(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS downloads (
        sha256_hash TEXT PRIMARY KEY,
        api_file_name TEXT,
        local_filename TEXT,
        tag TEXT,
        secondary_tag TEXT,
        wildcard_extra INTEGER,
        api_tags TEXT,
        tag_rule TEXT,
        file_type TEXT,
        first_seen TEXT,
        downloaded_at TEXT,
        downloaded_epoch REAL,
        attempted_epoch REAL,
        signature TEXT,
        file_size TEXT,
        last_seen TEXT,
        status TEXT
    )""")
    ensure_column(conn, "downloads", "secondary_tag", "TEXT")
    ensure_column(conn, "downloads", "wildcard_extra", "INTEGER")
    ensure_column(conn, "downloads", "api_tags", "TEXT")
    ensure_column(conn, "downloads", "tag_rule", "TEXT")
    for column in ("attempted_epoch", "signature", "file_size", "last_seen"):
        definition = "REAL" if column == "attempted_epoch" else "TEXT"
        ensure_column(conn, "downloads", column, definition)
    conn.execute("""CREATE TABLE IF NOT EXISTS downloads_rejected (
        sha256_hash TEXT,
        api_tags TEXT,
        tag_rule TEXT,
        reason TEXT,
        seen_at TEXT
    )""")
    conn.commit()


def init_temp_db(conn: sqlite3.Connection) -> None:
    conn.execute("""CREATE TABLE IF NOT EXISTS session_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256_hash TEXT,
        tag TEXT,
        secondary_tag TEXT,
        wildcard_extra INTEGER,
        api_tags TEXT,
        tag_rule TEXT,
        file_type TEXT,
        timestamp TEXT,
        status TEXT,
        error TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS poll_cache (
        sha256_hash TEXT PRIMARY KEY,
        tag TEXT,
        file_type TEXT,
        first_seen TEXT,
        signature TEXT,
        file_size TEXT,
        last_seen TEXT
    )""")
    ensure_column(conn, "session_log", "secondary_tag", "TEXT")
    ensure_column(conn, "session_log", "wildcard_extra", "INTEGER")
    ensure_column(conn, "session_log", "api_tags", "TEXT")
    ensure_column(conn, "session_log", "tag_rule", "TEXT")
    for column in ("signature", "file_size", "last_seen"):
        ensure_column(conn, "poll_cache", column, "TEXT")
    conn.commit()


def log_session(conn: sqlite3.Connection, sha256: str, tag: str, file_type: str,
                status: str, error: str = "", secondary_tag: str = "",
                wildcard_extra: bool = False, api_tags: str = "",
                tag_rule: str = "") -> None:
    conn.execute(
        "INSERT INTO session_log (sha256_hash, tag, secondary_tag, wildcard_extra, "
        "api_tags, tag_rule, file_type, timestamp, status, error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (sha256, tag, secondary_tag, int(wildcard_extra), api_tags, tag_rule,
         file_type, utc_now(), status, error),
    )
    conn.commit()


def utc_now() -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())


def log_time() -> str:
    return time.strftime("%H:%M:%S", time.gmtime())


def console(label: str, message: str) -> None:
    print(f"[{log_time()}] {label:<7} {message}", flush=True)


def normalize_first_seen(value) -> str:
    return str(value or "").strip().replace("T", " ")


def attempts_in_last_24h(conn: sqlite3.Connection) -> int:
    cutoff = time.time() - 86400
    return conn.execute(
        "SELECT COUNT(*) FROM downloads "
        "WHERE COALESCE(attempted_epoch, downloaded_epoch) >= ?", (cutoff,)
    ).fetchone()[0]


def upsert_download(conn: sqlite3.Connection, values: dict) -> None:
    columns = list(values)
    placeholders = ",".join("?" for _ in columns)
    conn.execute(f"INSERT OR REPLACE INTO downloads ({','.join(columns)}) "
                 f"VALUES ({placeholders})", [values[column] for column in columns])
    conn.commit()


def record_attempt(conn: sqlite3.Connection, sha256_hash: str, tag: str,
                   secondary_tag: str, wildcard_extra: bool, rule: str,
                   file_type: str, first_seen: str, item: dict) -> None:
    upsert_download(conn, {
        "sha256_hash": sha256_hash,
        "api_file_name": text_field(item.get("file_name")),
        "tag": tag,
        "secondary_tag": secondary_tag,
        "wildcard_extra": int(wildcard_extra),
        "api_tags": tags_to_csv(item.get("tags")),
        "tag_rule": rule,
        "file_type": file_type,
        "first_seen": first_seen,
        "attempted_epoch": time.time(),
        "status": "attempted",
    })


def handle_existing_file(main_conn: sqlite3.Connection, temp_conn: sqlite3.Connection,
                         sha256_hash: str, file_type: str, dest_dir: Path, tag: str,
                         secondary_tag: str, wildcard_extra: bool, rule: str,
                         first_seen: str, item: dict) -> str | None:
    final_path = dest_dir / f"{sha256_hash}.{EXT_BY_TYPE[file_type]}"
    if not final_path.is_file():
        return None
    digest = hashlib.sha256()
    with final_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    if digest.hexdigest() == sha256_hash:
        upsert_download(main_conn, {
            "sha256_hash": sha256_hash,
            "api_file_name": text_field(item.get("file_name")),
            "local_filename": final_path.name,
            "tag": tag,
            "secondary_tag": secondary_tag,
            "wildcard_extra": int(wildcard_extra),
            "api_tags": tags_to_csv(item.get("tags")),
            "tag_rule": rule,
            "file_type": file_type,
            "first_seen": first_seen,
            "downloaded_at": utc_now(),
            "signature": text_field(item.get("signature")),
            "file_size": text_field(item.get("file_size")),
            "last_seen": normalize_first_seen(item.get("last_seen")),
            "status": "adopted",
        })
        log_session(temp_conn, sha256_hash, tag, file_type, "adopted",
                    secondary_tag=secondary_tag, wildcard_extra=wildcard_extra,
                    api_tags=tags_to_csv(item.get("tags")), tag_rule=rule)
        console("ADOPT", f"{final_path.name}: hash matches, no API call")
        return "adopted"

    quarantine_dir = ensure_dir(SAMPLES_DIR / "_quarantine")
    target = quarantine_dir / final_path.name
    if target.exists():
        target = quarantine_dir / f"{final_path.stem}.{int(time.time())}.{EXT_BY_TYPE[file_type]}"
    os.replace(final_path, target)
    log_session(temp_conn, sha256_hash, tag, file_type, "quarantined",
                "existing file hash does not match its name",
                secondary_tag=secondary_tag, wildcard_extra=wildcard_extra,
                api_tags=tags_to_csv(item.get("tags")), tag_rule=rule)
    console("QUARANTINE", f"{final_path.name} -> {target}")
    return "quarantined"


# ------------------------------------------------------------------ filtering

def normalize_type(value) -> str:
    text = str(value or "").strip().lower()
    return TYPE_ALIASES.get(text, text)


def tags_to_csv(tags) -> str:
    if isinstance(tags, list):
        return ",".join(str(item) for item in tags)
    return str(tags or "")


def composite_tag(tag: str, secondary_tag: str, wildcard_extra: bool = False,
                  tag_mode: str = "exact") -> str:
    parts = [tag]
    if secondary_tag:
        parts.append(secondary_tag)
    if wildcard_extra:
        parts.append("*")
    if tag_mode == "contains":
        parts.append("contains")
    return ",".join(parts)


def sample_passes(tags_csv: str, search_tag: str, file_type: str,
                  secondary_tag: str = "", wildcard_extra: bool = False,
                  tag_mode: str = "exact") -> bool:
    lowered = [item.strip().lower() for item in tags_csv.split(",") if item.strip()]
    lowered = [TYPE_ALIASES.get(item, item) for item in lowered]
    if search_tag.lower() not in lowered:
        return False
    types = [item for item in lowered if item in EXT_BY_TYPE]
    if len(types) != 1 or types[0] != file_type:
        return False
    if tag_mode == "contains":
        other_rat = {
            item for item in lowered
            if item in RAT_TAG_ALIASES and item != search_tag.lower()
        }
        return not other_rat
    if secondary_tag == "*":
        return True
    if secondary_tag:
        if secondary_tag.lower() not in lowered:
            return False
        if wildcard_extra:
            return True
        return set(lowered) == {search_tag.lower(), secondary_tag.lower(), file_type}
    return set(lowered) == {search_tag.lower(), file_type}


def build_candidates(temp_conn: sqlite3.Connection, main_conn: sqlite3.Connection,
                     tag: str, file_type: str, secondary_tag: str = "",
                     wildcard_extra: bool = False,
                     tag_mode: str = "exact") -> tuple:
    rows = temp_conn.execute(
        "SELECT sha256_hash, tag, file_type, first_seen FROM poll_cache"
    ).fetchall()
    filtered = []
    skipped = []
    skips = []
    rejected = 0
    for sha, tags_csv, api_type, first_seen in rows:
        if not sample_passes(tags_csv, tag, file_type, secondary_tag,
                             wildcard_extra, tag_mode):
            rejected += 1
            skips.append((sha, tags_csv, "tag_filter"))
            continue
        if normalize_type(api_type) != file_type:
            skipped.append((sha, str(api_type or "missing")))
            skips.append((sha, tags_csv, f"file_type:{api_type or 'missing'}"))
            continue
        filtered.append((sha, normalize_first_seen(first_seen)))
    known = {row[0] for row in main_conn.execute(
        "SELECT sha256_hash FROM downloads WHERE status IN ('success', 'adopted')")}
    duplicates = sum(1 for item in filtered if item[0] in known)
    for sha, _seen in filtered:
        if sha in known:
            skips.append((sha, "", "duplicate"))
    fresh = [item for item in filtered if item[0] not in known]

    cursor = main_conn.execute(
        "SELECT first_seen, sha256_hash FROM downloads "
        "WHERE tag_rule = ? AND status IN ('success', 'adopted') "
        "ORDER BY first_seen DESC, sha256_hash DESC LIMIT 1",
        (composite_tag(tag, secondary_tag, wildcard_extra, tag_mode),)
    ).fetchone()
    cursor_key = (normalize_first_seen(cursor[0]), cursor[1] or "") if cursor else ("", "")

    new = [item for item in fresh if (item[1], item[0]) > cursor_key]
    backlog = [item for item in fresh if (item[1], item[0]) <= cursor_key]
    for group in (new, backlog):
        group.sort(key=lambda item: (item[1], item[0]))
    return {"new": new, "backlog": backlog, "skipped": skipped,
            "skips": skips, "rows": len(rows), "rejected": rejected,
            "duplicates": duplicates}


# --------------------------------------------------------------- download I/O

def download_sample(auth_key: str, sha256: str, file_type: str, dest_dir: Path,
                    state: dict) -> str:
    ensure_dir(TEMP_DIR)
    ensure_dir(dest_dir)
    ext = EXT_BY_TYPE[file_type]
    zip_path = TEMP_DIR / f"{sha256}.zip"
    part_path = TEMP_DIR / f"{sha256}.{ext}.part"
    final_path = dest_dir / f"{sha256}.{ext}"

    try:
        body = get_file(auth_key, sha256, state)
        with open(zip_path, "wb") as handle:
            handle.write(body)

        # User asserted MalwareBazaar always names both the ZIP and its single
        # inner file with the SHA256; if that is false, it simply cannot be true.
        with pyzipper.AESZipFile(zip_path) as archive:
            archive.setpassword(ZIP_PASSWORD)
            names = [name for name in archive.namelist() if not name.endswith("/")]
            if len(names) != 1:
                raise ValueError(f"expected one file in ZIP, found {len(names)}")
            inner_name = names[0]
            if Path(inner_name).stem != sha256:
                raise ValueError(f"inner name {inner_name!r} does not match {sha256}")
            payload = archive.read(inner_name)

        if hashlib.sha256(payload).hexdigest() != sha256:
            raise ValueError("SHA256 of extracted bytes does not match API hash")

        with open(part_path, "wb") as handle:
            handle.write(payload)
        if final_path.exists():
            raise ApiError("destination file appeared during download")
        os.replace(part_path, final_path)
        return final_path.name
    except Exception:
        for path in (zip_path, part_path):
            if path.exists():
                path.unlink()
        raise
    finally:
        if zip_path.exists():
            zip_path.unlink()


def cleanup_temp() -> None:
    if COMPARISON_DB.exists():
        COMPARISON_DB.unlink()
    if TEMP_DIR.exists():
        for path in TEMP_DIR.iterdir():
            if path.is_file() and (path.suffix in (".zip", ".part")):
                path.unlink()


def check_ledger(conn: sqlite3.Connection, dest_dir: Path, file_type: str) -> list[str]:
    known = {row[0] for row in conn.execute("SELECT sha256_hash FROM downloads")}
    on_disk = {path.stem for path in dest_dir.glob(f"*.{EXT_BY_TYPE[file_type]}")}
    missing = sorted(on_disk - known)
    if missing:
        console("WARN", f"{len(missing)} files on disk have no ledger row")
        for sha256 in missing:
            console("WARN", f"  {sha256}")
    else:
        console("LEDGER", f"ok; files={len(on_disk)} rows={len(known)}")
    return missing


# ------------------------------------------------------------- export batch

EXPORT_DIR = ROOT / "Data" / "Exports"
EXPORT_MANIFEST = EXPORT_DIR / "mb_full_selection.json"
EXPORT_URL = "https://mb-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
EXPORT_MIN_BYTES = 50 * 1024 * 1024
EXPORT_MAX_AGE = 3600.0
EXPORT_SIGNATURE = "asyncrat"


def normalize_field(value) -> str:
    text = str(value or "").strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text.strip()


def ensure_export_archive(path: Path, auth_key: str) -> Path:
    """Reuse a fresh archive; otherwise fetch it. The URL is never logged."""
    if path.is_file():
        age = time.time() - path.stat().st_mtime
        if path.stat().st_size >= EXPORT_MIN_BYTES and age <= EXPORT_MAX_AGE:
            console("EXPORT", f"reusing {path.name} "
                    f"({path.stat().st_size / 2**20:.1f} MiB, {age / 60:.1f} min old)")
            return path
    ensure_dir(path.parent)
    console("EXPORT", "downloading full export (URL hidden)")
    part = path.with_suffix(path.suffix + ".part")
    request = urllib.request.Request(
        EXPORT_URL.format(key=auth_key),
        headers={"User-Agent": "AsyncParser-MBDownloader/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=120) as response, \
                open(part, "wb") as handle:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                handle.write(chunk)
    except urllib.error.HTTPError as exc:
        if part.exists():
            part.unlink()
        raise ApiError(f"export download failed: HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        if part.exists():
            part.unlink()
        raise ApiError(f"export download failed: {exc.__class__.__name__}") from None
    if part.stat().st_size < EXPORT_MIN_BYTES:
        size = part.stat().st_size
        part.unlink()
        raise ApiError(f"export download truncated at {size} bytes")
    os.replace(part, path)
    path.touch()
    console("EXPORT", f"saved {path.name} ({path.stat().st_size / 2**20:.1f} MiB)")
    return path


def iter_export_rows(path: Path):
    """Stream full.csv from the zip; never extract the CSV to disk."""
    with zipfile.ZipFile(path) as archive:
        member = next((name for name in archive.namelist()
                       if name.endswith(".csv")), None)
        if member is None:
            raise RuntimeError(f"no CSV member in {path.name}")
        with archive.open(member) as raw:
            text = io.TextIOWrapper(raw, encoding="utf-8", errors="replace",
                                    newline="")
            header = None
            first = None
            for line in text:
                if line.startswith("#"):
                    if "first_seen_utc" in line:
                        header = [normalize_field(item) for item in
                                  line.lstrip("#").split(",")]
                    continue
                first = line
                break
            if header is None:
                raise RuntimeError(f"no CSV header in {path.name}")
            body = text if first is None else itertools.chain([first], text)
            reader = csv.reader(body, skipinitialspace=True)
            index = {name: position for position, name in enumerate(header)}
            for missing in ("first_seen_utc", "sha256_hash", "file_name",
                            "file_type_guess", "signature", "tlsh"):
                if missing not in index:
                    raise RuntimeError(f"export CSV missing column {missing}")
            for row in reader:
                if not row:
                    continue
                yield {name: normalize_field(row[position])
                       for name, position in index.items() if position < len(row)}


def parse_years(spec: str) -> list[int]:
    years: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start, end = part.split("-", 1)
            years.extend(range(int(start), int(end) + 1))
        else:
            years.append(int(part))
    if not years:
        raise ValueError(f"no years in {spec!r}")
    return years


def load_selection_manifest(path: Path) -> dict:
    if not path.is_file():
        return {"schema_version": 1, "source": "malwarebazaar_full_export",
                "entries": [], "runs": []}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload.get("entries"), list):
        raise RuntimeError(f"selection manifest has no entries: {path}")
    payload.setdefault("runs", [])
    return payload


def save_selection_manifest(path: Path, payload: dict) -> None:
    ensure_dir(path.parent)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True),
                         encoding="utf-8")
    os.replace(temporary, path)


def export_candidates(path: Path, ledger: set[str], selected: set[str],
                      years: list[int]) -> dict:
    stats = {"rows": 0, "signature": 0, "exe": 0, "ledger": 0,
             "manifest": 0, "tlsh_missing": 0}
    by_year: dict[int, list[dict]] = {year: [] for year in years}
    reasons: list[tuple[str, str]] = []
    for row in iter_export_rows(path):
        stats["rows"] += 1
        if row.get("signature", "").lower() != EXPORT_SIGNATURE:
            continue
        stats["signature"] += 1
        if row.get("file_type_guess", "").lower() != "exe":
            continue
        stats["exe"] += 1
        sha256 = row.get("sha256_hash", "").lower()
        if sha256 in ledger:
            stats["ledger"] += 1
            reasons.append((sha256, "ledger"))
            continue
        if sha256 in selected:
            stats["manifest"] += 1
            reasons.append((sha256, "manifest"))
            continue
        first_seen = row.get("first_seen_utc", "")
        year = int(first_seen[:4]) if first_seen[:4].isdigit() else 0
        if year not in by_year:
            continue
        try:
            digest = tlsh.Tlsh()
            digest.fromTlshStr(row.get("tlsh", ""))
            tlsh_value = digest.hexdigest()
        except ValueError:
            stats["tlsh_missing"] += 1
            reasons.append((sha256, "tlsh_missing"))
            continue
        by_year[year].append({
            "sha256": sha256, "year": year, "first_seen": first_seen,
            "tlsh": tlsh_value, "file_name": row.get("file_name", ""),
        })
    for items in by_year.values():
        items.sort(key=lambda item: (item["first_seen"], item["sha256"]))
    return {"stats": stats, "by_year": by_year, "reasons": reasons}


def select_export_batch(by_year: dict[int, list[dict]], anchors: list[str],
                        per_year: int, threshold: int, limit: int) -> dict:
    selected: list[dict] = []
    rejected: list[tuple[str, str]] = []
    pool = list(anchors)
    per_year_counts: dict[int, int] = {}
    for year in sorted(by_year):
        count = 0
        per_year_counts[year] = 0
        ordered = sorted(by_year[year],
                         key=lambda item: (item["first_seen"], item["sha256"]))
        for candidate in ordered:
            if count >= per_year:
                break
            if limit and len(selected) >= limit:
                break
            if any(tlsh.diff(candidate["tlsh"], anchor) <= threshold
                   for anchor in pool):
                rejected.append((candidate["sha256"], "tlsh_reject"))
                continue
            selected.append(candidate)
            pool.append(candidate["tlsh"])
            count += 1
            per_year_counts[year] += 1
        if limit and len(selected) >= limit:
            break
    return {"selected": selected, "rejected": rejected,
            "per_year": per_year_counts}


def record_rejection(conn: sqlite3.Connection, sha256: str, reason: str,
                     rule: str, detail: str = "") -> None:
    conn.execute(
        "INSERT INTO downloads_rejected (sha256_hash, api_tags, tag_rule, reason, seen_at) "
        "SELECT ?, ?, ?, ?, ? WHERE NOT EXISTS ("
        "SELECT 1 FROM downloads_rejected WHERE sha256_hash = ? "
        "AND reason = ? AND tag_rule = ?)",
        (sha256, detail, rule, reason, utc_now(), sha256, reason, rule),
    )


def run_export_batch(auth_key: str, export_path: Path, batch: int,
                     per_year: int, years: list[int], threshold: int,
                     limit: int, rate: int,
                     main_conn: sqlite3.Connection) -> dict:
    rule = f"asyncrat_full_export_b{batch}"
    archive = ensure_export_archive(export_path, auth_key)
    manifest = load_selection_manifest(EXPORT_MANIFEST)
    ledger = {row[0] for row in main_conn.execute(
        "SELECT sha256_hash FROM downloads")}
    selected_before = {entry["sha256"] for entry in manifest["entries"]}
    anchors = [entry["tlsh"] for entry in manifest["entries"] if entry.get("tlsh")]

    scan = export_candidates(archive, ledger, selected_before, years)
    stats = scan["stats"]
    resume = [entry for entry in manifest["entries"]
              if entry.get("batch") == batch and entry.get("status") == "selected"]
    remaining = max(0, limit - len(resume)) if limit else 0
    if remaining > 0 or not resume:
        chosen = select_export_batch(scan["by_year"], anchors, per_year,
                                     threshold, remaining)
    else:
        chosen = {"selected": [], "rejected": [], "per_year": {}}
    console("SELECT", f"rows={stats['rows']} signature={stats['signature']} "
            f"exe={stats['exe']} ledger={stats['ledger']} "
            f"manifest={stats['manifest']} tlsh_missing={stats['tlsh_missing']} "
            f"tlsh_reject={len(chosen['rejected'])} "
            f"selected={len(chosen['selected'])} resume={len(resume)}")

    record_rejection(main_conn, "", "signature_filter", rule,
                     f"count={stats['rows'] - stats['signature']}")
    record_rejection(main_conn, "", "file_type", rule,
                     f"count={stats['signature'] - stats['exe']}")
    for sha256, reason in scan["reasons"] + chosen["rejected"]:
        record_rejection(main_conn, sha256, reason, rule)
    main_conn.commit()

    now = utc_now()
    new_entries = [{**item, "batch": batch, "status": "selected",
                    "selected_at": now} for item in chosen["selected"]]
    entries = resume + new_entries
    manifest["entries"].extend(new_entries)
    if chosen["selected"]:
        manifest["runs"].append({
            "batch": batch, "selected_at": now, "years": years,
            "per_year": per_year, "tlsh_threshold": threshold, "limit": limit,
            "counts": {**stats, "tlsh_reject": len(chosen["rejected"]),
                       "selected": len(chosen["selected"])},
            "per_year_selected": {str(key): value
                                  for key, value in chosen["per_year"].items()},
        })
    save_selection_manifest(EXPORT_MANIFEST, manifest)

    ensure_dir(TEMP_DIR)
    if COMPARISON_DB.exists():
        COMPARISON_DB.unlink()
    temp_conn = sqlite3.connect(COMPARISON_DB)
    init_temp_db(temp_conn)
    downloaded = failed = adopted = 0
    state = {"consecutive_429": 0}
    last_download = None
    try:
        for index, entry in enumerate(entries, 1):
            if STOP["requested"]:
                raise StopRun("Ctrl+C")
            if attempts_in_last_24h(main_conn) >= DAILY_CAP:
                raise StopRun(f"daily cap of {DAILY_CAP} downloads reached")
            sha256 = entry["sha256"]
            item = {"file_name": entry["file_name"], "signature": "AsyncRAT"}
            outcome = handle_existing_file(main_conn, temp_conn, sha256, "exe",
                                           ASYNCRAT_DIR, "AsyncRAT", "", False,
                                           rule, entry["first_seen"], item)
            if outcome == "adopted":
                entry["status"] = "downloaded"
                adopted += 1
                save_selection_manifest(EXPORT_MANIFEST, manifest)
                continue
            wait_seconds = 60.0 / rate
            if last_download is not None:
                pause = max(0.0, wait_seconds - (time.monotonic() - last_download))
                if pause > 0:
                    console("WAIT", f"{pause:.1f}s")
                interruptible_sleep(pause)
            console("GET", f"{index}/{len(entries)} {sha256[:12]}... "
                    f"year={entry['year']}")
            try:
                local_name = download_sample(auth_key, sha256, "exe",
                                             ASYNCRAT_DIR, state)
                upsert_download(main_conn, {
                    "sha256_hash": sha256,
                    "api_file_name": text_field(item.get("file_name")),
                    "local_filename": local_name,
                    "tag": "AsyncRAT",
                    "secondary_tag": "",
                    "wildcard_extra": 0,
                    "api_tags": "",
                    "tag_rule": rule,
                    "file_type": "exe",
                    "first_seen": entry["first_seen"],
                    "downloaded_at": utc_now(),
                    "downloaded_epoch": time.time(),
                    "attempted_epoch": time.time(),
                    "signature": "AsyncRAT",
                    "last_seen": "",
                    "status": "success",
                })
                entry["status"] = "downloaded"
                downloaded += 1
            except (ApiError, OSError, ValueError, sqlite3.Error,
                    zipfile.BadZipFile, RuntimeError) as exc:
                entry["status"] = "failed"
                failed += 1
                record_rejection(main_conn, sha256, "download_failed", rule,
                                 str(exc)[:200])
                console("ERROR", f"{sha256[:12]}... {exc}")
                main_conn.commit()
            last_download = time.monotonic()
            save_selection_manifest(EXPORT_MANIFEST, manifest)
    finally:
        temp_conn.close()
        cleanup_temp()

    missing = check_ledger(main_conn, ASYNCRAT_DIR, "exe")
    if missing:
        raise RuntimeError(f"{len(missing)} export files have no ledger row")
    console("EXPORT", f"batch={batch} downloaded={downloaded} adopted={adopted} "
            f"failed={failed} selected={len(entries)}")
    return {"stats": stats, "selected": len(entries), "downloaded": downloaded,
            "adopted": adopted, "failed": failed}



# ------------------------------------------------------------------ run loop

def run_poll_loop(auth_key: str, tag: str, dest_dir: Path, file_types: list,
                  rate: int, main_conn: sqlite3.Connection,
                  secondary_tag: str = "", wildcard_extra: bool = False,
                  tag_mode: str = "exact", limit: int = 0) -> None:
    ensure_dir(TEMP_DIR)
    if COMPARISON_DB.exists():
        COMPARISON_DB.unlink()
    temp_conn = sqlite3.connect(COMPARISON_DB)
    init_temp_db(temp_conn)
    rule = composite_tag(tag, secondary_tag, wildcard_extra, tag_mode)
    console("START", f"tag={rule} main={tag} "
            f"secondary={secondary_tag or '-'} "
            f"wildcard_extra={'yes' if wildcard_extra else 'no'} "
            f"dir={dest_dir} types={','.join(file_types)} rate={rate}/min")
    state = {"consecutive_429": 0}
    errors = 0
    session_downloads = 0
    started_at = time.monotonic()
    last_download = None

    session_adopted = 0
    session_quarantined = 0

    try:
        while True:
            if STOP["requested"]:
                raise StopRun("Ctrl+C")

            console("QUERY", f"tag={tag}")
            query_start = time.monotonic()
            try:
                metadata = get_taginfo(auth_key, tag, state)
            except StopRun:
                raise
            except ApiError as exc:
                console("ERROR", f"tag query failed: {exc}")
                errors += 1
                if errors > MAX_ERRORS:
                    raise StopRun("error limit reached")
                raise StopRun("tag query failed; ending run")
            console("RESULT", f"{len(metadata)} rows in {time.monotonic()-query_start:.1f}s")

            # last_seen ordering (user-confirmed) decides which TAG_LIMIT samples
            # are visible in this window; first_seen orders the download queue below.
            metadata_by_sha = {}
            temp_conn.execute("DELETE FROM poll_cache")
            for item in metadata:
                sha = str(item.get("sha256_hash") or "")
                if not sha:
                    continue
                metadata_by_sha[sha] = item
                temp_conn.execute(
                    "INSERT OR REPLACE INTO poll_cache "
                    "(sha256_hash, tag, file_type, first_seen, signature, file_size, last_seen) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (sha, tags_to_csv(item.get("tags")), text_field(item.get("file_type")),
                     normalize_first_seen(item.get("first_seen")),
                     text_field(item.get("signature")), text_field(item.get("file_size")),
                     normalize_first_seen(item.get("last_seen"))),
                )
            temp_conn.commit()

            for file_type in file_types:
                if STOP["requested"]:
                    raise StopRun("Ctrl+C")
                result = build_candidates(temp_conn, main_conn, tag, file_type,
                                          secondary_tag, wildcard_extra, tag_mode)
                for sha256, tags_csv, reason in result["skips"]:
                    log_session(temp_conn, sha256, tag, file_type, "skipped",
                                reason, secondary_tag=secondary_tag,
                                wildcard_extra=wildcard_extra,
                                api_tags=tags_csv, tag_rule=rule)
                    main_conn.execute(
                        "INSERT INTO downloads_rejected "
                        "(sha256_hash, api_tags, tag_rule, reason, seen_at) "
                        "VALUES (?, ?, ?, ?, ?)",
                        (sha256, tags_csv, rule, reason, utc_now()),
                    )
                main_conn.commit()
                console("FILTER", f"rows={result['rows']} drop={result['rejected']} "
                        f"dup={result['duplicates']} bad_type={len(result['skipped'])} "
                        f"new={len(result['new'])} backlog={len(result['backlog'])}")

                todo = result["new"] + result["backlog"]
                for index, (sha256, first_seen) in enumerate(todo, 1):
                    if STOP["requested"]:
                        raise StopRun("Ctrl+C")
                    if attempts_in_last_24h(main_conn) >= DAILY_CAP:
                        raise StopRun(f"daily cap of {DAILY_CAP} downloads reached")
                    if limit and (session_downloads + session_adopted
                                  + session_quarantined) >= limit:
                        raise StopRun(f"batch limit {limit} reached")

                    item = metadata_by_sha.get(sha256, {})
                    outcome = handle_existing_file(main_conn, temp_conn, sha256, file_type,
                                                   dest_dir, tag, secondary_tag,
                                                   wildcard_extra, rule, first_seen, item)
                    if outcome == "adopted":
                        session_adopted += 1
                        continue
                    if outcome == "quarantined":
                        session_quarantined += 1
                        continue

                    wait_seconds = 60.0 / rate
                    if last_download is not None:
                        pause = max(0.0, wait_seconds - (time.monotonic() - last_download))
                        if pause > 0:
                            console("WAIT", f"{pause:.1f}s")
                        interruptible_sleep(pause)
                    console("GET", f"{index}/{len(todo)} {sha256} first_seen={first_seen}")

                    api_tags = tags_to_csv(item.get("tags"))
                    attempt_epoch = time.time()
                    record_attempt(main_conn, sha256, tag, secondary_tag, wildcard_extra,
                                   rule, file_type, first_seen, item)
                    download_start = time.monotonic()
                    created_path = None
                    try:
                        local_name = download_sample(auth_key, sha256, file_type, dest_dir, state)
                        created_path = dest_dir / local_name
                        upsert_download(main_conn, {
                            "sha256_hash": sha256,
                            "api_file_name": text_field(item.get("file_name")),
                            "local_filename": local_name,
                            "tag": tag,
                            "secondary_tag": secondary_tag,
                            "wildcard_extra": int(wildcard_extra),
                            "api_tags": api_tags,
                            "tag_rule": rule,
                            "file_type": file_type,
                            "first_seen": first_seen,
                            "downloaded_at": utc_now(),
                            "downloaded_epoch": time.time(),
                            "attempted_epoch": attempt_epoch,
                            "signature": text_field(item.get("signature")),
                            "file_size": text_field(item.get("file_size")),
                            "last_seen": normalize_first_seen(item.get("last_seen")),
                            "status": "success",
                        })
                        log_session(temp_conn, sha256, tag, file_type, "success",
                                    secondary_tag=secondary_tag,
                                    wildcard_extra=wildcard_extra,
                                    api_tags=api_tags, tag_rule=rule)
                        session_downloads += 1
                        console("SAVE", f"{local_name} sha256=ok db=ok "
                                f"first_seen={first_seen} "
                                f"in {time.monotonic()-download_start:.1f}s")
                    except StopRun:
                        raise
                    except ApiError as exc:
                        _record_failure(temp_conn, sha256, file_type, tag, str(exc),
                                        secondary_tag, wildcard_extra, rule, created_path)
                        errors += 1
                    except (OSError, ValueError, sqlite3.Error, zipfile.BadZipFile,
                            RuntimeError) as exc:
                        _record_failure(temp_conn, sha256, file_type, tag, str(exc),
                                        secondary_tag, wildcard_extra, rule, created_path)
                        errors += 1

                    last_download = time.monotonic()
                    if errors > MAX_ERRORS:
                        raise StopRun("error limit reached")

            raise StopRun("batch complete; ending run")
    except StopRun as exc:
        reason = "Ctrl+C received" if STOP["requested"] else str(exc)
        console("STOP", reason)
        raise
    finally:
        temp_conn.close()
        cleanup_temp()
        elapsed = time.monotonic() - started_at
        console("SUMMARY", f"downloaded={session_downloads} adopted={session_adopted} "
                f"quarantined={session_quarantined} errors={errors} "
                f"elapsed={int(elapsed//60)}m{int(elapsed%60)}s temp_db=removed")


def _record_failure(temp_conn, sha256, file_type, tag, message,
                    secondary_tag: str = "", wildcard_extra: bool = False,
                    tag_rule: str = "", created_path: Path | None = None) -> None:
    for suffix in (".zip", f".{file_type}.part"):
        path = TEMP_DIR / f"{sha256}{suffix}"
        if path.exists():
            path.unlink()
    if created_path is not None and created_path.exists():
        created_path.unlink()
    log_session(temp_conn, sha256, tag, file_type, "error", message, secondary_tag,
                wildcard_extra, tag_rule=tag_rule)
    console("ERROR", f"{sha256[:12]}... {message}")


# ---------------------------------------------------------------------- main

def backfill_signature(conn: sqlite3.Connection) -> None:
    ensure_column(conn, "downloads", "signature", "TEXT")
    has_poll = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='poll_cache'"
    ).fetchone()
    if has_poll:
        conn.execute(
            "UPDATE downloads SET signature = ("
            "SELECT signature FROM poll_cache p "
            "WHERE p.sha256_hash = downloads.sha256_hash"
            ") WHERE signature IS NULL"
        )
    conn.commit()


def backfill_signature_from_export(conn: sqlite3.Connection, path: Path) -> dict:
    missing = {row[0] for row in conn.execute(
        "SELECT sha256_hash FROM downloads WHERE signature IS NULL")}
    found: dict[str, str] = {}
    for row in iter_export_rows(path):
        sha256 = row.get("sha256_hash", "").lower()
        if sha256 in missing:
            signature = row.get("signature", "").strip()
            if signature:
                found[sha256] = signature
                if len(found) == len(missing):
                    break
    for sha256, signature in found.items():
        conn.execute("UPDATE downloads SET signature = ? WHERE sha256_hash = ?",
                     (signature, sha256))
    conn.commit()
    return {"missing": sorted(missing - set(found)), "filled": len(found),
            "requested": len(missing)}


# ------------------------------------------------------------- family queue

FAMILY_MANIFEST = EXPORT_DIR / "family_selection.json"
DEFAULT_FAMILIES = SCRIPT_DIR / "families.json"


def load_families(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    families = payload.get("families")
    if not isinstance(families, list) or not families:
        raise RuntimeError(f"no families in {path}")
    return families


def family_maps(families: list[dict]) -> tuple[dict[str, str], dict[str, str]]:
    signature_map: dict[str, str] = {}
    filename_map: dict[str, str] = {}
    for family in families:
        if family.get("availability") != "mb":
            continue
        name = str(family["name"])
        for alias in [name, *family.get("aliases", [])]:
            key = str(alias).strip().lower()
            signature_map[key] = name
            compact = re.sub(r"[^a-z0-9]", "", key)
            if len(compact) >= 5:
                filename_map[compact] = name
    return signature_map, filename_map


def match_filename_family(file_name: str, filename_map: dict[str, str]) -> str | None:
    compact = re.sub(r"[^a-z0-9]", "", file_name.lower())
    matches = [(len(key), family) for key, family in filename_map.items()
               if key in compact]
    return max(matches)[1] if matches else None


def family_candidates(path: Path, families: list[dict], ledger: set[str],
                      selected: set[str]) -> dict:
    signature_map, filename_map = family_maps(families)
    stats = {"rows": 0, "exe": 0, "ledger": 0, "manifest": 0,
             "tlsh_missing": 0, "signature": 0, "filename": 0}
    by_family: dict[str, list[dict]] = {str(f["name"]): [] for f in families
                                        if f.get("availability") == "mb"}
    rejected: list[tuple[str, str, str]] = []
    for row in iter_export_rows(path):
        stats["rows"] += 1
        signature = row.get("signature", "").lower()
        family = signature_map.get(signature)
        source = "signature"
        if family is not None:
            stats["signature"] += 1
        else:
            if signature == EXPORT_SIGNATURE:
                continue
            if signature not in {"", "n/a"}:
                continue
            family = match_filename_family(row.get("file_name", ""), filename_map)
            if family is None:
                continue
            stats["filename"] += 1
            source = "filename"
        if row.get("file_type_guess", "").lower() != "exe":
            continue
        stats["exe"] += 1
        sha256 = row.get("sha256_hash", "").lower()
        if sha256 in ledger:
            stats["ledger"] += 1
            rejected.append((sha256, family, "ledger"))
            continue
        if sha256 in selected:
            stats["manifest"] += 1
            rejected.append((sha256, family, "manifest"))
            continue
        try:
            digest = tlsh.Tlsh()
            digest.fromTlshStr(row.get("tlsh", ""))
            tlsh_value = digest.hexdigest()
        except ValueError:
            stats["tlsh_missing"] += 1
            rejected.append((sha256, family, "tlsh_missing"))
            continue
        by_family[family].append({
            "family": family, "sha256": sha256,
            "first_seen": row.get("first_seen_utc", ""),
            "tlsh": tlsh_value, "source": source,
        })
    for items in by_family.values():
        items.sort(key=lambda item: (item["first_seen"], item["sha256"]))
    return {"stats": stats, "by_family": by_family, "rejected": rejected}


def export_tlsh_map(path: Path, wanted: set[str]) -> dict[str, dict]:
    found: dict[str, dict] = {}
    for row in iter_export_rows(path):
        sha256 = row.get("sha256_hash", "").lower()
        if sha256 in wanted and sha256 not in found:
            found[sha256] = {"tlsh": row.get("tlsh", ""),
                             "first_seen": row.get("first_seen_utc", "")}
            if len(found) == len(wanted):
                break
    return found


def tag_fallback(auth_key: str, families: list[dict], by_family: dict[str, list[dict]],
                 caps: dict[str, int], ledger: set[str], selected: set[str],
                 export_path: Path) -> dict:
    """Recent MB tag lookup for families the export does not cover."""
    stats = {"families": 0, "rows": 0, "exe": 0, "no_tlsh": 0, "added": 0}
    shortfalls = {str(f["name"]): caps[str(f["name"])] - len(by_family.get(str(f["name"]), []))
                  for f in families if f.get("availability") == "mb"
                  and len(by_family.get(str(f["name"]), [])) < caps[str(f["name"])]}
    if not shortfalls:
        return stats
    state = {"consecutive_429": 0}
    aliases = {str(f["name"]): [str(f["name"]), *f.get("aliases", [])]
               for f in families}
    collected: list[dict] = []
    seen: set[str] = set()
    for family, missing in sorted(shortfalls.items()):
        if missing <= 0:
            continue
        stats["families"] += 1
        wanted = max(missing * 2, 10)
        got = 0
        alias_list = []
        for alias in [family, *aliases[family]]:
            if alias.lower() not in {item.lower() for item in alias_list}:
                alias_list.append(alias)
        for alias in alias_list[:2]:
            if got >= wanted:
                break
            console("TAG", f"{family}: tag={alias}")
            try:
                rows = get_taginfo(auth_key, alias, state)
            except (ApiError, StopRun) as exc:
                console("TAG", f"{family}: {exc}")
                break
            for row in rows:
                sha256 = str(row.get("sha256_hash") or "").lower()
                if not sha256 or sha256 in ledger or sha256 in selected or sha256 in seen:
                    continue
                if str(row.get("file_type") or "").lower() != "exe":
                    continue
                seen.add(sha256)
                collected.append({"family": family, "sha256": sha256,
                                  "first_seen": normalize_first_seen(
                                      row.get("first_seen")),
                                  "file_name": normalize_field(row.get("file_name")),
                                  "source": "tag"})
                got += 1
                if got >= wanted:
                    break
            interruptible_sleep(1.0)
        if got == 0:
            console("TAG", f"{family}: no recent tag rows")
    if not collected:
        return stats
    stats["rows"] = len(collected)
    wanted_shas = {item["sha256"] for item in collected}
    tlsh_rows = export_tlsh_map(export_path, wanted_shas)
    for item in collected:
        meta = tlsh_rows.get(item["sha256"])
        if meta is None:
            stats["no_tlsh"] += 1
            continue
        try:
            digest = tlsh.Tlsh()
            digest.fromTlshStr(meta["tlsh"])
            item["tlsh"] = digest.hexdigest()
        except ValueError:
            stats["no_tlsh"] += 1
            continue
        if not item["first_seen"]:
            item["first_seen"] = meta["first_seen"]
        by_family.setdefault(item["family"], []).append(item)
        stats["exe"] += 1
        stats["added"] += 1
    return stats


def select_family_batch(by_family: dict[str, list[dict]],
                        anchors: dict[str, list[str]], caps: dict[str, int],
                        threshold: int, limit: int) -> dict:
    selected: list[dict] = []
    rejected: list[tuple[str, str, str]] = []
    per_family: dict[str, int] = {}
    pools = {family: list(values) for family, values in anchors.items()}
    for family in sorted(by_family):
        cap = caps.get(family, 50)
        count = 0
        per_family[family] = 0
        pool = pools.setdefault(family, [])
        for candidate in by_family[family]:
            if count >= cap:
                break
            if limit and len(selected) >= limit:
                break
            if any(tlsh.diff(candidate["tlsh"], anchor) <= threshold
                   for anchor in pool):
                rejected.append((candidate["sha256"], family, "tlsh_reject"))
                continue
            selected.append(candidate)
            pool.append(candidate["tlsh"])
            count += 1
            per_family[family] += 1
        if limit and len(selected) >= limit:
            break
    return {"selected": selected, "rejected": rejected, "per_family": per_family}


def run_family_queue(auth_key: str, export_path: Path, families_path: Path,
                     target: int, threshold: int, limit: int, rate: int,
                     main_conn: sqlite3.Connection) -> dict:
    archive = ensure_export_archive(export_path, auth_key)
    families = load_families(families_path)
    manifest = load_selection_manifest(FAMILY_MANIFEST)
    manifest["source"] = "family_queue"
    ledger = {row[0] for row in main_conn.execute(
        "SELECT sha256_hash FROM downloads")}
    selected_before = {entry["sha256"] for entry in manifest["entries"]}
    anchors: dict[str, list[str]] = {}
    for entry in manifest["entries"]:
        if entry.get("tlsh"):
            anchors.setdefault(entry["family"], []).append(entry["tlsh"])

    scan = family_candidates(archive, families, ledger, selected_before)
    stats = scan["stats"]
    caps = {str(family["name"]): min(target, int(family.get("mb_count") or 0))
            for family in families if family.get("availability") == "mb"}
    fallback = tag_fallback(auth_key, families, scan["by_family"], caps,
                            ledger, selected_before, archive)
    console("TAG", f"families={fallback['families']} rows={fallback['rows']} "
            f"with_tlsh={fallback['added']} no_tlsh={fallback['no_tlsh']}")
    chosen = select_family_batch(scan["by_family"], anchors, caps,
                                 threshold, limit)
    console("FAMILY", f"rows={stats['rows']} signature={stats['signature']} "
            f"filename={stats['filename']} exe={stats['exe']} "
            f"ledger={stats['ledger']} manifest={stats['manifest']} "
            f"tlsh_missing={stats['tlsh_missing']} "
            f"tlsh_reject={len(chosen['rejected'])} "
            f"selected={len(chosen['selected'])}")
    for family, count in sorted(chosen["per_family"].items()):
        console("FAMILY", f"  {family}: {count}")

    for sha256, family, reason in scan["rejected"] + chosen["rejected"]:
        record_rejection(main_conn, sha256, reason,
                         f"family_queue_{family.lower().replace(' ', '_')}")
    main_conn.commit()

    now = utc_now()
    entries = [{**item, "status": "selected", "selected_at": now}
               for item in chosen["selected"]]
    manifest["entries"].extend(entries)
    manifest["runs"].append({
        "selected_at": now, "target": target, "tlsh_threshold": threshold,
        "limit": limit, "counts": {**stats,
                                   "tlsh_reject": len(chosen["rejected"]),
                                   "selected": len(entries)},
        "per_family_selected": chosen["per_family"],
    })
    save_selection_manifest(FAMILY_MANIFEST, manifest)

    ensure_dir(TEMP_DIR)
    if COMPARISON_DB.exists():
        COMPARISON_DB.unlink()
    temp_conn = sqlite3.connect(COMPARISON_DB)
    init_temp_db(temp_conn)
    downloaded = adopted = failed = 0
    state = {"consecutive_429": 0}
    last_download = None
    try:
        for index, entry in enumerate(entries, 1):
            if STOP["requested"]:
                raise StopRun("Ctrl+C")
            if attempts_in_last_24h(main_conn) >= DAILY_CAP:
                raise StopRun(f"daily cap of {DAILY_CAP} downloads reached")
            family = entry["family"]
            rule = f"family_queue_{family.lower().replace(' ', '_')}"
            sha256 = entry["sha256"]
            item = {"file_name": entry.get("file_name", ""),
                    "signature": family}
            outcome = handle_existing_file(main_conn, temp_conn, sha256, "exe",
                                           OTHER_DIR, family, "", False, rule,
                                           entry["first_seen"], item)
            if outcome == "adopted":
                entry["status"] = "downloaded"
                adopted += 1
                save_selection_manifest(FAMILY_MANIFEST, manifest)
                continue
            wait_seconds = 60.0 / rate
            if last_download is not None:
                pause = max(0.0, wait_seconds - (time.monotonic() - last_download))
                if pause > 0:
                    console("WAIT", f"{pause:.1f}s")
                interruptible_sleep(pause)
            console("GET", f"{index}/{len(entries)} {sha256[:12]}... "
                    f"family={family}")
            try:
                local_name = download_sample(auth_key, sha256, "exe",
                                             OTHER_DIR, state)
                upsert_download(main_conn, {
                    "sha256_hash": sha256,
                    "api_file_name": text_field(item.get("file_name")),
                    "local_filename": local_name,
                    "tag": family,
                    "secondary_tag": "",
                    "wildcard_extra": 0,
                    "api_tags": "",
                    "tag_rule": rule,
                    "file_type": "exe",
                    "first_seen": entry["first_seen"],
                    "downloaded_at": utc_now(),
                    "downloaded_epoch": time.time(),
                    "attempted_epoch": time.time(),
                    "signature": family,
                    "last_seen": "",
                    "status": "success",
                })
                entry["status"] = "downloaded"
                downloaded += 1
            except (ApiError, OSError, ValueError, sqlite3.Error,
                    zipfile.BadZipFile, RuntimeError) as exc:
                entry["status"] = "failed"
                failed += 1
                record_rejection(main_conn, sha256, "download_failed", rule,
                                 str(exc)[:200])
                console("ERROR", f"{sha256[:12]}... {exc}")
                main_conn.commit()
            last_download = time.monotonic()
            save_selection_manifest(FAMILY_MANIFEST, manifest)
    finally:
        temp_conn.close()
        cleanup_temp()

    missing = check_ledger(main_conn, OTHER_DIR, "exe")
    if missing:
        raise RuntimeError(f"{len(missing)} family files have no ledger row")
    console("FAMILY", f"downloaded={downloaded} adopted={adopted} "
            f"failed={failed} selected={len(entries)}")
    return {"stats": stats, "per_family": chosen["per_family"],
            "downloaded": downloaded, "adopted": adopted, "failed": failed}


def main() -> None:
    parser = argparse.ArgumentParser(description="MalwareBazaar downloader")
    parser.add_argument("--tag-mode", choices=("exact", "contains"),
                        default="exact")
    parser.add_argument("--migrate-signature", action="store_true")
    parser.add_argument("--backfill-export", type=Path, default=None)
    parser.add_argument("--batch", nargs="?", const=0, type=int, default=None,
                        help="tag batch when bare; export batch number with --from-export")
    parser.add_argument("--from-export", type=Path, default=None)
    parser.add_argument("--family-queue", type=Path, default=None)
    parser.add_argument("--families", type=Path, default=DEFAULT_FAMILIES)
    parser.add_argument("--family-target", type=int, default=50)
    parser.add_argument("--per-year", type=int, default=50)
    parser.add_argument("--years", default="2020-2026")
    parser.add_argument("--tlsh-threshold", type=int, default=100)
    parser.add_argument("--tag", default=None)
    parser.add_argument("--file-type", choices=sorted(EXT_BY_TYPE), default="exe")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--rate", type=int, default=10)
    args = parser.parse_args()

    if args.migrate_signature:
        conn = sqlite3.connect(DB_PATH)
        try:
            init_main_db(conn)
            backfill_signature(conn)
            count = conn.execute(
                "SELECT COUNT(*) FROM downloads WHERE signature IS NOT NULL"
            ).fetchone()[0]
        finally:
            conn.close()
        console("MIGRATE", f"downloads.signature backfilled; non-null={count}")
        return

    if args.backfill_export is not None:
        conn = sqlite3.connect(DB_PATH)
        try:
            init_main_db(conn)
            result = backfill_signature_from_export(conn, args.backfill_export)
        finally:
            conn.close()
        console("BACKFILL", f"requested={result['requested']} "
                f"filled={result['filled']} missing={len(result['missing'])}")
        for sha256 in result["missing"]:
            console("BACKFILL", f"  not found: {sha256}")
        return

    auth_key = load_auth_key()
    ensure_dir(TEMP_DIR)
    for directory in (ASYNCRAT_DIR, OTHER_DIR, BENIGN_DIR):
        ensure_dir(directory)
    main_conn = sqlite3.connect(DB_PATH)
    init_main_db(main_conn)

    if args.family_queue is not None:
        STOP["in_run"] = True
        try:
            run_family_queue(auth_key, args.family_queue, args.families,
                             args.family_target, args.tlsh_threshold,
                             args.limit, args.rate, main_conn)
        except StopRun as exc:
            console("QUEUE", str(exc))
        finally:
            STOP["in_run"] = False
            main_conn.close()
        return

    if args.from_export is not None:
        if not args.batch:
            parser.error("--from-export requires --batch <number>")
        STOP["in_run"] = True
        try:
            run_export_batch(auth_key, args.from_export, args.batch,
                             args.per_year, parse_years(args.years),
                             args.tlsh_threshold, args.limit, args.rate,
                             main_conn)
        except StopRun as exc:
            console("BATCH", str(exc))
        finally:
            STOP["in_run"] = False
            main_conn.close()
        return

    if args.batch is not None:
        if not args.tag:
            parser.error("--batch requires --tag")
        backfill_signature(main_conn)
        dest_dir = ASYNCRAT_DIR if args.tag.lower() == "asyncrat" else OTHER_DIR
        try:
            run_poll_loop(
                auth_key, args.tag, dest_dir, [args.file_type], args.rate,
                main_conn, tag_mode=args.tag_mode, limit=args.limit,
            )
        except StopRun as exc:
            console("BATCH", str(exc))
        finally:
            missing = check_ledger(main_conn, dest_dir, args.file_type)
            main_conn.close()
            if missing:
                raise RuntimeError(f"{len(missing)} files on disk have no ledger row")
        return

    try:
        while True:
            print("\n1) AsyncRAT\n2) Other Malwares\n3) Benign")
            try:
                choice = input("Choose [1/2/3] (AsyncRAT): ").strip()
                if not choice:
                    choice = "1"
            except (KeyboardInterrupt, EOFError):
                console("STOP", "no run started")
                return
            if choice == "3":
                print("source not configured")
                continue
            if choice not in ("1", "2"):
                print("Invalid choice.")
                continue

            if choice == "1":
                tag = "AsyncRAT"
            else:
                try:
                    tag = input("Tag to search: ").strip()
                except (KeyboardInterrupt, EOFError):
                    console("STOP", "no run started")
                    return
            if not tag:
                print("No tag entered.")
                continue
            dest_dir = ASYNCRAT_DIR if choice == "1" else OTHER_DIR

            try:
                secondary_tag = prompt_secondary_tag()
                file_types = prompt_file_types()
                wildcard_extra = False
                if secondary_tag and secondary_tag != "*":
                    wildcard_extra = prompt_yes_no("Allow any other tags (Surprise Me)?")
                if secondary_tag or wildcard_extra:
                    console("CONFIG",
                            f"tag_rule={composite_tag(tag, secondary_tag, wildcard_extra)}")
                rate = prompt_rate()
            except (KeyboardInterrupt, EOFError):
                console("STOP", "no run started")
                return

            STOP["in_run"] = True
            try:
                run_poll_loop(auth_key, tag, dest_dir, file_types, rate, main_conn,
                              secondary_tag, wildcard_extra, args.tag_mode)
            except StopRun:
                return
            except KeyboardInterrupt:
                console("STOP", "interrupted")
                return
            finally:
                STOP["in_run"] = False
                STOP["requested"] = False
    finally:
        main_conn.close()


if __name__ == "__main__":
    main()

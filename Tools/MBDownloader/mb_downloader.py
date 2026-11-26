#!/usr/bin/env python3
"""Interactive MalwareBazaar sample downloader for an academic dataset."""

from __future__ import annotations

import hashlib
import json
import os
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

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
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


def composite_tag(tag: str, secondary_tag: str, wildcard_extra: bool = False) -> str:
    parts = [tag]
    if secondary_tag:
        parts.append(secondary_tag)
    if wildcard_extra:
        parts.append("*")
    return ",".join(parts)


def sample_passes(tags_csv: str, search_tag: str, file_type: str,
                  secondary_tag: str = "", wildcard_extra: bool = False) -> bool:
    lowered = [item.strip().lower() for item in tags_csv.split(",") if item.strip()]
    lowered = [TYPE_ALIASES.get(item, item) for item in lowered]
    if search_tag.lower() not in lowered:
        return False
    types = [item for item in lowered if item in EXT_BY_TYPE]
    if len(types) != 1 or types[0] != file_type:
        return False
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
                     wildcard_extra: bool = False) -> tuple:
    rows = temp_conn.execute(
        "SELECT sha256_hash, tag, file_type, first_seen FROM poll_cache"
    ).fetchall()
    filtered = []
    skipped = []
    rejected = 0
    for sha, tags_csv, api_type, first_seen in rows:
        if not sample_passes(tags_csv, tag, file_type, secondary_tag, wildcard_extra):
            rejected += 1
            continue
        if normalize_type(api_type) != file_type:
            skipped.append((sha, str(api_type or "missing")))
            continue
        filtered.append((sha, normalize_first_seen(first_seen)))
    known = {row[0] for row in main_conn.execute(
        "SELECT sha256_hash FROM downloads WHERE status IN ('success', 'adopted')")}
    duplicates = sum(1 for item in filtered if item[0] in known)
    fresh = [item for item in filtered if item[0] not in known]

    cursor = main_conn.execute(
        "SELECT first_seen, sha256_hash FROM downloads "
        "WHERE tag_rule = ? AND status IN ('success', 'adopted') "
        "ORDER BY first_seen DESC, sha256_hash DESC LIMIT 1",
        (composite_tag(tag, secondary_tag, wildcard_extra),)
    ).fetchone()
    cursor_key = (normalize_first_seen(cursor[0]), cursor[1] or "") if cursor else ("", "")

    new = [item for item in fresh if (item[1], item[0]) > cursor_key]
    backlog = [item for item in fresh if (item[1], item[0]) <= cursor_key]
    for group in (new, backlog):
        group.sort(key=lambda item: (item[1], item[0]))
    return {"new": new, "backlog": backlog, "skipped": skipped,
            "rows": len(rows), "rejected": rejected, "duplicates": duplicates}


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


# ------------------------------------------------------------------ run loop

def run_poll_loop(auth_key: str, tag: str, dest_dir: Path, file_types: list,
                  rate: int, main_conn: sqlite3.Connection,
                  secondary_tag: str = "", wildcard_extra: bool = False) -> None:
    ensure_dir(TEMP_DIR)
    if COMPARISON_DB.exists():
        COMPARISON_DB.unlink()
    temp_conn = sqlite3.connect(COMPARISON_DB)
    init_temp_db(temp_conn)
    rule = composite_tag(tag, secondary_tag, wildcard_extra)
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
                                          secondary_tag, wildcard_extra)
                for sha256, api_type in result["skipped"]:
                    log_session(temp_conn, sha256, tag, api_type, "skipped",
                                f"unsupported API file_type: {api_type}",
                                secondary_tag=secondary_tag, wildcard_extra=wildcard_extra,
                                tag_rule=rule)
                console("FILTER", f"rows={result['rows']} drop={result['rejected']} "
                        f"dup={result['duplicates']} bad_type={len(result['skipped'])} "
                        f"new={len(result['new'])} backlog={len(result['backlog'])}")

                todo = result["new"] + result["backlog"]
                for index, (sha256, first_seen) in enumerate(todo, 1):
                    if STOP["requested"]:
                        raise StopRun("Ctrl+C")
                    if attempts_in_last_24h(main_conn) >= DAILY_CAP:
                        raise StopRun(f"daily cap of {DAILY_CAP} downloads reached")

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

def main() -> None:
    auth_key = load_auth_key()
    ensure_dir(TEMP_DIR)
    for directory in (ASYNCRAT_DIR, OTHER_DIR, BENIGN_DIR):
        ensure_dir(directory)
    main_conn = sqlite3.connect(DB_PATH)
    init_main_db(main_conn)

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
                              secondary_tag, wildcard_extra)
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

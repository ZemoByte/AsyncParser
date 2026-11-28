#!/usr/bin/env python3
"""Pipeline state, fingerprints and skip decisions.

State lives in ``Data/Pipeline/state.json``. A stage is skipped only when its
fingerprint matches, status is ok, and every declared output exists. The
fingerprint covers schema versions, source-code hashes, input digests and the
fingerprints of upstream stages; mtime alone is never used.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._versions import PIPELINE_SCHEMA_VERSION, all_versions  # noqa: E402

STATE_PATH = ROOT / "Data" / "Pipeline" / "state.json"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_paths(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(path.name.encode())
        digest.update(b"\0")
        if path.is_file():
            digest.update(sha256_file(path).encode())
        digest.update(b"\0")
    return digest.hexdigest()


def code_sha(paths: list[Path]) -> str:
    parts = []
    for path in sorted(paths):
        if not path.is_file():
            continue
        parts.append({"path": str(path.relative_to(ROOT)),
                      "sha": sha256_file(path)})
    return sha256_bytes(json.dumps(parts, sort_keys=True).encode())


def samples_digest(samples_root: Path, ledger: Path) -> str:
    shas = set()
    if ledger.is_file():
        conn = sqlite3.connect(f"file:{ledger}?mode=ro", uri=True)
        try:
            shas.update(str(row[0]) for row in conn.execute(
                "SELECT sha256_hash FROM downloads"))
        finally:
            conn.close()
    benign = []
    directory = samples_root / "Benign"
    if directory.is_dir():
        for path in sorted(directory.iterdir()):
            if path.is_file():
                benign.append([path.name, path.stat().st_size])
    payload = {"ledger": sorted(shas), "benign": benign}
    return sha256_bytes(json.dumps(payload, sort_keys=True).encode())


def file_digest(path: Path) -> str:
    return sha256_file(path) if path.is_file() else ""


def die_digest(wrapper: str) -> str:
    """DIE version + signature DB digest; never raises."""
    try:
        proc = subprocess.run([wrapper, "--version"], capture_output=True,
                              text=True, timeout=30, check=False)
        version = (proc.stdout or proc.stderr).strip().splitlines()[0]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return "unavailable"
    base = Path(wrapper).resolve().parent
    db = base / "die_db" / "db"
    digest = "no-db"
    if db.is_dir():
        digest = digest_paths([path for path in db.rglob("*") if path.is_file()])
    return sha256_bytes(f"{version}\0{digest}".encode())


def stage_fingerprint(name: str, versions: dict, code_paths: list[Path],
                      inputs: dict, upstream: dict) -> str:
    payload = {
        "stage": name,
        "pipeline_schema": PIPELINE_SCHEMA_VERSION,
        "versions": versions,
        "code": code_sha(code_paths),
        "inputs": inputs,
        "upstream": upstream,
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True).encode())


def load_state(path: Path = STATE_PATH) -> dict:
    if not path.is_file():
        return {"schema_version": PIPELINE_SCHEMA_VERSION, "stages": {}}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"schema_version": PIPELINE_SCHEMA_VERSION, "stages": {}}
    if not isinstance(payload, dict) or not isinstance(payload.get("stages"), dict):
        return {"schema_version": PIPELINE_SCHEMA_VERSION, "stages": {}}
    return payload


def save_state(payload: dict, path: Path = STATE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True),
                         encoding="utf-8")
    os.replace(temporary, path)


def stage_fresh(entry: dict | None, fingerprint: str,
                outputs: list[Path]) -> tuple[bool, str]:
    if entry is None:
        return False, "no state entry"
    if entry.get("status") != "ok":
        return False, f"status={entry.get('status')}"
    if entry.get("fingerprint") != fingerprint:
        return False, "fingerprint changed"
    if entry.get("schema_version") != PIPELINE_SCHEMA_VERSION:
        return False, "state schema changed"
    missing = [str(path) for path in outputs if not path.exists()]
    if missing:
        return False, f"missing outputs: {', '.join(missing[:3])}"
    return True, "cached"


def stage_record(name: str, fingerprint: str, outputs: list[Path],
                 seconds: float, status: str = "ok",
                 started_at: str = "", finished_at: str = "",
                 returncode: int | None = None,
                 marker_mtime: float | None = None) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")
    return {"stage": name, "fingerprint": fingerprint,
            "schema_version": PIPELINE_SCHEMA_VERSION,
            "outputs": [str(path) for path in outputs],
            "status": status, "seconds": round(seconds, 3),
            "wall_seconds": round(seconds, 3),
            "started_at": started_at, "finished_at": finished_at or now,
            "returncode": returncode,
            "output_count": len(outputs),
            "marker_mtime": marker_mtime}


def default_versions() -> dict:
    return all_versions()

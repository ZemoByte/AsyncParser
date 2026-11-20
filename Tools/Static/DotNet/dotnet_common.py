#!/usr/bin/env python3
"""Shared path, hashing, provenance and tool helpers for the DotNet cleaners."""

import hashlib
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[3]
CLEANED = BASE / "Cleaned"


def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def resolve_sha(path, sha_arg=None):
    """Return artifact key: explicit --sha (original sample) or hash of path."""
    if sha_arg:
        return sha_arg.lower()
    return sha256_of_file(path)


def artifacts_dir(sha, name):
    d = CLEANED / sha / name
    d.mkdir(parents=True, exist_ok=True)
    return d


def safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", str(value)).strip("._")[:120] or "unnamed"


def _prov_path(sha):
    return CLEANED / sha / "provenance.json"


def load_provenance(sha):
    path = _prov_path(sha)
    if path.is_file():
        try:
            return json.loads(path.read_text())
        except (ValueError, OSError):
            pass
    return {"sha256": sha, "steps": []}


def record(sha, step, status, *, tool="", artifacts=None, dropped=None, reason=""):
    """Append one step to Cleaned/<sha>/provenance.json (atomic write)."""
    prov = load_provenance(sha)
    prov["steps"].append({
        "step": step,
        "status": status,          # ok | failed | skipped
        "tool": tool,
        "artifacts": [str(a) for a in (artifacts or [])],
        "dropped": list(dropped or []),
        "reason": reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })
    path = _prov_path(sha)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(prov, indent=2) + "\n")
    os.replace(tmp, path)


def tool_path(name):
    return shutil.which(name)


def run_tool(cmd, *, timeout=300):
    """Run an external command. Returns (returncode, stdout, stderr, error).

    Catches FileNotFoundError (tool not installed), TimeoutExpired (too slow),
    and OSError (permission denied, not a valid executable on this OS).
    """
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True,
                            timeout=timeout, errors="replace")
        return cp.returncode, cp.stdout, cp.stderr, ""
    except FileNotFoundError:
        return None, "", "", f"tool not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, "", "", f"timeout after {timeout}s: {cmd[0]}"
    except OSError as e:
        return None, "", "", f"cannot execute {cmd[0]}: {e.strerror} ({e.errno})"

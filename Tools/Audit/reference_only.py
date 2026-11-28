#!/usr/bin/env python3
"""Mark server/builder/stub/panel samples as reference_only.

File names are labeling metadata only; they are never model features. A
filename match alone is not enough: the label must also lack a valid config
(no parsed config / parse_error) or be explicitly flagged by a human. Manual
flags always win, and auto-flags are restored when the evidence changes.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import load_final_label  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
DEFAULT_LEDGER = ROOT / "Tools" / "MBDownloader" / "samples.db"
PATTERN = re.compile(r"(server|builder|stub|panel)", re.IGNORECASE)
FLAGGABLE = {"verified", "verified_other"}
AUTO_PREFIX = "file_name:"


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True),
                         encoding="utf-8")
    os.replace(temporary, path)


def ledger_names(path: Path) -> dict[str, str]:
    if not path.is_file():
        return {}
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        return {str(sha): str(name or "")
                for sha, name in conn.execute(
                    "SELECT sha256_hash, api_file_name FROM downloads")}
    finally:
        conn.close()


def name_matches(names: dict[str, str]) -> dict[str, str]:
    matches = {}
    for sha256, name in names.items():
        found = PATTERN.search(name)
        if found:
            matches[sha256] = f"{AUTO_PREFIX}{found.group(1).lower()}"
    return matches


def manual_flags(path: Path | None) -> dict[str, str]:
    if path is None or not path.is_file():
        return {}
    flags = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sha256, _, reason = line.partition(" ")
        flags[sha256.strip().lower()] = reason.strip() or "manual_review"
    return flags


def has_valid_config(fields: dict) -> bool:
    config = fields.get("config")
    if isinstance(config, str) and config.strip():
        try:
            config = json.loads(config)
        except json.JSONDecodeError:
            return False
    if not isinstance(config, dict) or not config:
        return False
    return not bool(config.get("parse_error"))


def label_path(data_root: Path, sha256: str) -> Path:
    aggregate = data_root / "Aggregated" / f"{sha256}.json"
    return aggregate if aggregate.is_file() else data_root / "Labels" / f"{sha256}.json"


def apply_flags(data_root: Path, auto_flags: dict[str, str],
                manual: dict[str, str], names: dict[str, str],
                dry_run: bool) -> dict:
    changed = []
    restored = []
    skipped = Counter()
    keep = set()
    for sha256, reason in sorted(auto_flags.items()):
        try:
            fields = load_final_label(sha256, data_root)
        except RuntimeError:
            skipped["missing_label"] += 1
            continue
        status = str(fields.get("lbl_sts") or "")
        if has_valid_config(fields) and sha256 not in manual:
            skipped["client_evidence"] += 1
            continue
        if status == "reference_only":
            keep.add(sha256)
            skipped["already_flagged"] += 1
            continue
        if status not in FLAGGABLE:
            skipped[f"status:{status or 'empty'}"] += 1
            continue
        keep.add(sha256)
        changed.append({"sha256": sha256, "previous_status": status,
                        "reason": reason, "file_name": names.get(sha256, "")})
        if not dry_run:
            path = label_path(data_root, sha256)
            if path.is_file():
                payload = json.loads(path.read_text(encoding="utf-8"))
                target = payload.setdefault("fields", {})
                target["previous_status"] = status
                target["lbl_sts"] = "reference_only"
                target["scope_reason"] = reason
                write_json(path, payload)

    for sha256, reason in sorted(manual.items()):
        try:
            fields = load_final_label(sha256, data_root)
        except RuntimeError:
            skipped["missing_label"] += 1
            continue
        status = str(fields.get("lbl_sts") or "")
        if status == "reference_only":
            keep.add(sha256)
            continue
        if status not in FLAGGABLE:
            skipped[f"status:{status or 'empty'}"] += 1
            continue
        keep.add(sha256)
        changed.append({"sha256": sha256, "previous_status": status,
                        "reason": reason, "file_name": names.get(sha256, "")})
        if not dry_run:
            path = label_path(data_root, sha256)
            if path.is_file():
                payload = json.loads(path.read_text(encoding="utf-8"))
                target = payload.setdefault("fields", {})
                target["previous_status"] = status
                target["lbl_sts"] = "reference_only"
                target["scope_reason"] = reason
                write_json(path, payload)

    for directory in (data_root / "Aggregated", data_root / "Labels"):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.json")):
            sha256 = path.stem
            if sha256 in keep:
                continue
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            fields = payload.get("fields")
            if not isinstance(fields, dict):
                continue
            reason = str(fields.get("scope_reason") or "")
            previous = str(fields.get("previous_status") or "")
            if (fields.get("lbl_sts") != "reference_only"
                    or not reason.startswith(AUTO_PREFIX)
                    or previous not in FLAGGABLE):
                continue
            restored.append({"sha256": sha256, "restored_status": previous,
                             "reason": reason})
            if not dry_run:
                fields["lbl_sts"] = previous
                fields.pop("scope_reason", None)
                fields.pop("previous_status", None)
                write_json(path, payload)

    return {"changed": changed, "restored": restored,
            "skipped": dict(skipped), "dry_run": dry_run}


def main() -> int:
    parser = argparse.ArgumentParser(description="Flag server/builder samples")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--manual", type=Path, default=None,
                        help="optional sha256 [reason] per line")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    names = ledger_names(args.ledger)
    auto = name_matches(names)
    manual = manual_flags(args.manual)
    result = apply_flags(args.data_root.resolve(), auto, manual, names,
                         args.dry_run)
    report = {
        "schema_version": 1,
        "producer": "reference_only_audit",
        "pattern": PATTERN.pattern,
        "ledger_rows": len(names),
        "name_matches": len(auto),
        "manual_flags": len(manual),
        **result,
    }
    if not args.dry_run:
        write_json(args.data_root.resolve() / "Audit" / "reference_only.json",
                   report)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

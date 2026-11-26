#!/usr/bin/env python3
"""Import labeled and carved JSON files into the project databases.

Only this tool writes to Data/DataSet.db and the three class databases.
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DATA_DIR = ROOT / "Data"
SAMPLES_DB = ROOT / "Tools" / "MBDownloader" / "samples.db"
SUPPORTED_SCHEMA_VERSION = 1
TOOLS = ("ImportTable", "TypeRef", "MemberRef", "AssemblyRef", "ImplMap")
FAMILY_MAP = {
    "asyncrat": "AsyncRAT",
    "dcrat": "DcRat",
    "quasarrat": "QuasarRAT",
    "venomrat": "VenomRAT",
    "xworm": "XWorm",
    "xenorat": "XenoRat",
    "benign": "Benign",
    "no match": "",
    "": "",
}
EXCLUDED_LABELS = {"unverified", "review", "rejected_non_dotnet",
                   "rejected_hash_mismatch", "reference_only"}


def canonical_family(raw) -> str:
    value = str(raw or "").strip()
    if not value:
        return ""
    canonical = FAMILY_MAP.get(value.lower())
    if canonical is None:
        raise RuntimeError(f"unknown suggested family: {value}")
    return canonical


def target_class_db(label: dict) -> str | None:
    status = label.get("lbl_sts")
    suggested = str(label.get("sug_fam") or "").strip()
    if status == "verified":
        return "AsyncRAT.db"
    if suggested == "Benign":
        return "Benign.db"
    return None
    return None


def safe_column(name: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in name)
    if not cleaned or not cleaned[0].isalpha() and cleaned[0] != "_":
        cleaned = "field_" + cleaned
    return cleaned


def sqlite_type(value) -> str:
    if isinstance(value, bool):
        return "INTEGER"
    if isinstance(value, int):
        return "INTEGER"
    if isinstance(value, float):
        return "REAL"
    return "TEXT"


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN "{column}" {definition}')
        conn.commit()


def ensure_table(conn: sqlite3.Connection, table: str, base_columns: dict[str, str]) -> None:
    exists = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if not exists:
        conn.execute(f'CREATE TABLE {table} (sha256 TEXT PRIMARY KEY)')
    for column, definition in base_columns.items():
        ensure_column(conn, table, column, definition)


def read_json(path: Path) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON in {path} is not an object")
    if payload.get("schema_version", 1) > SUPPORTED_SCHEMA_VERSION:
        raise RuntimeError(f"unsupported schema_version in {path}: {payload.get('schema_version')}")
    if "sha256" not in payload or "fields" not in payload or not isinstance(payload["fields"], dict):
        raise RuntimeError(f"missing sha256 or fields in {path}")
    if path.stem != str(payload["sha256"]):
        raise RuntimeError(f"filename does not match sha256 in {path}")
    return payload


def collect_markers() -> None:
    if (DATA_DIR / "Labels").is_dir() and not (DATA_DIR / "Labels" / ".labeler.done").is_file():
        raise RuntimeError(f"missing done marker: {DATA_DIR / 'Labels' / '.labeler.done'}")
    for class_dir in (DATA_DIR / "AsyncRAT", DATA_DIR / "OtherMalwares", DATA_DIR / "Benign"):
        if not class_dir.is_dir():
            continue
        for tool in TOOLS:
            marker = class_dir / tool / ".done"
            if not marker.is_file():
                raise RuntimeError(f"missing done marker: {marker}")


def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    collect_markers()

    samples = {}
    with sqlite3.connect(f"file:{SAMPLES_DB}?mode=ro", uri=True) as conn:
        for row in conn.execute(
            "SELECT sha256_hash, tag, secondary_tag, api_tags, tag_rule, file_type, "
            "first_seen, downloaded_at, status FROM downloads"
        ):
            samples[row[0]] = {
                "tag": row[1], "secondary_tag": row[2], "api_tags": row[3],
                "tag_rule": row[4], "file_type": row[5], "first_seen": row[6],
                "downloaded_at": row[7], "status": row[8],
            }

    labels = {}
    labels_dir = DATA_DIR / "Labels"
    for path in sorted(labels_dir.glob("*.json")):
        payload = read_json(path)
        sha256 = str(payload["sha256"])
        if sha256 in labels:
            raise RuntimeError(f"duplicate label JSON for {sha256}")
        labels[sha256] = payload
        # Hand-supplied samples (for example benign .NET files) are not in the
        # download ledger, but their label JSON is the authoritative input.
        samples.setdefault(sha256, {
            "tag": str(payload["fields"].get("sug_fam") or "Benign"),
            "secondary_tag": "", "api_tags": "", "tag_rule": "",
            "file_type": "", "first_seen": "", "downloaded_at": "",
            "status": "success",
        })

    carved = {sha: {} for sha in samples}
    for class_dir in (DATA_DIR / "AsyncRAT", DATA_DIR / "OtherMalwares", DATA_DIR / "Benign"):
        if not class_dir.is_dir():
            continue
        for tool in TOOLS:
            for path in sorted((class_dir / tool).glob("*.json")):
                payload = read_json(path)
                sha256 = str(payload["sha256"])
                if sha256 not in samples:
                    raise RuntimeError(f"carved JSON for unknown sample: {sha256}")
                if tool in carved[sha256]:
                    raise RuntimeError(f"duplicate carved JSON for {sha256}/{tool}")
                carved[sha256][tool] = payload["fields"]

    dataset_columns: dict[str, str] = {
        "sha256": "TEXT", "lbl_sts": "TEXT", "sug_fam": "TEXT",
        "obf_lvl": "TEXT", "parser_version": "TEXT", "config": "TEXT",
        "target_class_db": "TEXT",
    }
    class_columns: dict[str, str] = {
        "sha256": "TEXT", "tag": "TEXT", "secondary_tag": "TEXT",
        "api_tags": "TEXT", "tag_rule": "TEXT", "file_type": "TEXT",
        "first_seen": "TEXT", "downloaded_at": "TEXT",
    }
    field_types: dict[str, str] = {}

    for sha256, sample in samples.items():
        if sample["status"] not in {"success", "adopted"}:
            label = {"lbl_sts": "rejected_hash_mismatch", "sug_fam": "",
                     "obf_lvl": "unknown", "parser_version": "", "config": None}
        else:
            if sha256 not in labels:
                raise RuntimeError(f"missing label JSON for {sha256}")
            fields = labels[sha256]["fields"]
            label = {
                "lbl_sts": fields.get("lbl_sts", ""),
                "sug_fam": fields.get("sug_fam", ""),
                "obf_lvl": fields.get("obf_lvl", ""),
                "parser_version": fields.get("parser_version", ""),
                "config": fields.get("config", None),
            }
            for key, value in fields.items():
                if key in label:
                    continue
                column = safe_column(key)
                if column in field_types and field_types[column] != sqlite_type(value):
                    raise RuntimeError(f"conflicting field type for {column}")
                field_types[column] = sqlite_type(value)
        for key, value in label.items():
            if key == "config":
                continue
            column = safe_column(key)
            if column in field_types and field_types[column] != sqlite_type(value):
                raise RuntimeError(f"conflicting field type for {column}")
            field_types[column] = sqlite_type(value)

        for tool, fields in carved.get(sha256, {}).items():
            for key, value in fields.items():
                column = safe_column(f"{tool}_{key}")
                if column in field_types and field_types[column] != sqlite_type(value):
                    raise RuntimeError(f"conflicting field type for {column}")
                field_types[column] = sqlite_type(value)

    for column, definition in field_types.items():
        dataset_columns[column] = definition

    class_field_types: dict[str, str] = {}
    for sha256, sample in samples.items():
        if sample["status"] not in {"success", "adopted"}:
            continue
        label = labels.get(sha256, {}).get("fields", {})
        if label.get("lbl_sts") in EXCLUDED_LABELS:
            continue
        for tool, fields in carved.get(sha256, {}).items():
            for key, value in fields.items():
                column = safe_column(f"{tool}_{key}")
                if column in class_field_types and class_field_types[column] != sqlite_type(value):
                    raise RuntimeError(f"conflicting field type for {column}")
                class_field_types[column] = sqlite_type(value)
    for column, definition in class_field_types.items():
        class_columns[column] = definition

    dataset_path = DATA_DIR / "DataSet.db"
    conn_dataset = sqlite3.connect(dataset_path)
    try:
        ensure_table(conn_dataset, "dataset", dataset_columns)
        for sha256, sample in samples.items():
            if sample["status"] not in {"success", "adopted"}:
                label = {"lbl_sts": "rejected_hash_mismatch", "sug_fam": "",
                         "obf_lvl": "unknown", "parser_version": "", "config": None}
            else:
                if sha256 not in labels:
                    raise RuntimeError(f"missing label JSON for {sha256}")
                label = labels[sha256]["fields"]
            label["sug_fam"] = canonical_family(label.get("sug_fam", ""))
            target_class = target_class_db(label)
            row = {"sha256": sha256, "target_class_db": target_class}
            for key in ("lbl_sts", "sug_fam", "obf_lvl", "parser_version"):
                row[safe_column(key)] = label.get(key, "")
            config = label.get("config", None)
            row["config"] = json.dumps(config) if isinstance(config, (dict, list)) else config
            for key, value in label.items():
                if key in {"sha256", "lbl_sts", "sug_fam", "obf_lvl", "parser_version", "config"}:
                    continue
                row[safe_column(key)] = value if not isinstance(value, (dict, list)) else json.dumps(value)
            for tool, fields in carved.get(sha256, {}).items():
                for key, value in fields.items():
                    row[safe_column(f"{tool}_{key}")] = value if not isinstance(value, (dict, list)) else json.dumps(value)
            columns = list(dataset_columns)
            placeholders = ",".join("?" for _ in columns)
            conn_dataset.execute(
                f'INSERT OR REPLACE INTO dataset ({",".join(columns)}) VALUES ({placeholders})',
                [row.get(column) for column in columns],
            )

            if target_class is None:
                continue
            class_path = DATA_DIR / target_class
            conn_class = sqlite3.connect(class_path)
            try:
                ensure_table(conn_class, "samples", class_columns)
                class_row = {
                    "sha256": sha256,
                    "tag": sample["tag"],
                    "secondary_tag": sample["secondary_tag"],
                    "api_tags": sample["api_tags"],
                    "tag_rule": sample["tag_rule"],
                    "file_type": sample["file_type"],
                    "first_seen": sample["first_seen"],
                    "downloaded_at": sample["downloaded_at"],
                }
                for tool, fields in carved.get(sha256, {}).items():
                    for key, value in fields.items():
                        class_row[safe_column(f"{tool}_{key}")] = value if not isinstance(value, (dict, list)) else json.dumps(value)
                columns = list(class_columns)
                placeholders = ",".join("?" for _ in columns)
                conn_class.execute(
                    f'INSERT OR REPLACE INTO samples ({",".join(columns)}) VALUES ({placeholders})',
                    [class_row.get(column) for column in columns],
                )
                conn_class.commit()
            finally:
                conn_class.close()
        conn_dataset.commit()
    finally:
        conn_dataset.close()

    for class_dir in (DATA_DIR / "AsyncRAT", DATA_DIR / "OtherMalwares", DATA_DIR / "Benign"):
        if not class_dir.is_dir():
            continue
        for tool in TOOLS:
            marker = class_dir / tool / ".done"
            if marker.is_file():
                marker.unlink()
    print("import complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

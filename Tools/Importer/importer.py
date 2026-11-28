#!/usr/bin/env python3
"""Import labeled and carved JSON files into the project databases.

Only this tool writes to Data/DataSet.db and the three class databases.
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import (  # noqa: E402
    FAMILY_VERDICTS,
    STRENGTHS,
    canonical_family,
    load_final_label,
    load_gold_labels,
)

DATA_DIR = ROOT / "Data"
SAMPLES_DB = ROOT / "Tools" / "MBDownloader" / "samples.db"
EVIDENCE_DIR = DATA_DIR / "Evidence"
AGGREGATED_DIR = DATA_DIR / "Aggregated"
STRUCTURE_DIR = DATA_DIR / "Structure"
SPLITS_DIR = DATA_DIR / "Splits"
SUPPORTED_SCHEMA_VERSION = 1
TOOLS = ("ImportTable", "TypeRef", "MemberRef", "AssemblyRef", "ImplMap")
REQUIRED_EVIDENCE_SOURCES = ("rat_king_parser", "own_yara", "elastic", "malpedia",
                             "malwarebazaar", "detect_it_easy", "yaraify")
EXCLUDED_LABELS = {"unverified", "review", "rejected_non_dotnet",
                   "rejected_hash_mismatch", "reference_only"}
EVIDENCE_COLUMNS = {
    "sha256": "TEXT",
    "source": "TEXT",
    "source_version": "TEXT",
    "independence_group": "TEXT",
    "verdict": "TEXT",
    "strength": "TEXT",
    "scope": "TEXT",
    "raw": "TEXT",
    "observed_at": "TEXT",
}


def persisted_scope(raw) -> str:
    """Store the decision scope. Attribute voters act as family voters."""
    if isinstance(raw, dict) and str(raw.get("scope") or "") == "lineage":
        return "lineage"
    return "family"


def target_class_db(label: dict) -> str | None:
    status = label.get("lbl_sts")
    suggested = str(label.get("sug_fam") or "").strip()
    if status == "verified":
        return "AsyncRAT.db"
    if status == "verified_other":
        if suggested not in FAMILY_VERDICTS:
            raise RuntimeError(
                f"verified_other without a canonical family: {suggested!r}"
            )
        return "OtherMalwares.db"
    if status == "benign" and suggested == "Benign":
        return "Benign.db"
    return None


def gold_flags(gold_row: dict | None) -> tuple[int, str | None]:
    """A row is gold only after a human fills gold_status."""
    if not gold_row:
        return 0, None
    status = str(gold_row.get("gold_status") or "").strip()
    is_gold = 1 if status else 0
    family = str(gold_row.get("gold_family") or "").strip()
    gold_fam = canonical_family(family) if family else None
    return is_gold, gold_fam


def target_class_for_row(label: dict, is_gold: int) -> str | None:
    if is_gold:
        return None
    return target_class_db(label)


def split_assignment(sha256: str, label: dict, is_gold: int,
                     splits: dict[str, dict], splits_present: bool,
                     existing_split: str | None,
                     existing_temporal: str | None) -> tuple[str | None, str | None]:
    """Only primary, non-gold rows get a split.

    When the split marker exists, the split tool is authoritative: a missing
    split file means NULL (this clears stale assignments). Without the marker
    the importer preserves what was already in the DB.
    """
    status = str(label.get("lbl_sts") or "")
    source = str(label.get("source") or "")
    origin = str(label.get("origin") or "")
    kind = str(label.get("kind") or "")
    benign_ok = (status == "benign" and kind == "exe"
                 and source != "clrheader2023"
                 and origin != "fixture" and source != "fixture")
    allowed = not is_gold and (
        status in {"verified", "verified_other"} or benign_ok
    )
    if not allowed:
        return None, None
    if not splits_present:
        return existing_split, existing_temporal
    row = splits.get(sha256, {})
    return row.get("cluster_split"), row.get("temporal_split")


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


def ensure_evidence_table(conn: sqlite3.Connection) -> None:
    conn.execute(
        "CREATE TABLE IF NOT EXISTS label_evidence ("
        "sha256 TEXT NOT NULL, source TEXT NOT NULL, source_version TEXT NOT NULL, "
        "independence_group TEXT NOT NULL, verdict TEXT NOT NULL, strength TEXT NOT NULL, "
        "scope TEXT, raw TEXT, observed_at TEXT NOT NULL, "
        "PRIMARY KEY (sha256, source, source_version))"
    )
    for column, definition in EVIDENCE_COLUMNS.items():
        ensure_column(conn, "label_evidence", column, definition)
    conn.commit()


def upsert_evidence(conn: sqlite3.Connection, rows: list[dict]) -> None:
    for row in rows:
        conn.execute(
            "INSERT OR REPLACE INTO label_evidence "
            "(sha256, source, source_version, independence_group, verdict, strength, scope, raw, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (row["sha256"], row["source"], row["source_version"],
             row["independence_group"], row["verdict"], row["strength"],
             row["scope"], row["raw"], row["observed_at"]),
        )
    conn.commit()


def read_evidence_rows(evidence_dir: Path, active_shas: set[str]) -> list[dict]:
    if not evidence_dir.is_dir():
        raise RuntimeError(f"missing evidence directory: {evidence_dir}")
    rows = []
    for source_dir in sorted(path for path in evidence_dir.iterdir() if path.is_dir()):
        sha256 = source_dir.name
        if sha256 not in active_shas:
            continue
        for path in sorted(source_dir.glob("*.json")):
            try:
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid evidence JSON in {path}: {exc}") from exc
            if not isinstance(payload, dict) or payload.get("kind") != "evidence":
                raise RuntimeError(f"evidence JSON in {path} has wrong kind")
            if str(payload.get("sha256") or "") != sha256:
                raise RuntimeError(f"evidence sha256 mismatch in {path}")
            fields = payload.get("fields")
            if not isinstance(fields, dict):
                raise RuntimeError(f"evidence JSON in {path} has no fields object")
            source = str(fields.get("source") or "")
            if source != path.stem:
                raise RuntimeError(f"evidence source does not match filename: {path}")
            source_version = str(fields.get("source_version") or "")
            if not source_version:
                raise RuntimeError(f"evidence JSON in {path} has no source_version")
            group = str(fields.get("independence_group") or "")
            if not group:
                raise RuntimeError(f"evidence JSON in {path} has no independence_group")
            verdict = str(fields.get("verdict") or "")
            if verdict != "no_match" and verdict not in FAMILY_VERDICTS:
                raise RuntimeError(f"invalid evidence verdict in {path}: {verdict}")
            strength = str(fields.get("strength") or "")
            if strength not in STRENGTHS:
                raise RuntimeError(f"invalid evidence strength in {path}: {strength}")
            observed_at = str(fields.get("observed_at") or "")
            if not observed_at:
                raise RuntimeError(f"evidence JSON in {path} has no observed_at")
            raw_value = fields.get("raw")
            rows.append({
                "sha256": sha256,
                "source": source,
                "source_version": source_version,
                "independence_group": group,
                "verdict": verdict,
                "strength": strength,
                "scope": persisted_scope(raw_value),
                "raw": json.dumps(raw_value, sort_keys=True),
                "observed_at": observed_at,
            })

    by_sample: dict[str, set[str]] = {}
    for row in rows:
        by_sample.setdefault(row["sha256"], set()).add(row["source"])
    for sha256 in sorted(active_shas):
        missing = set(REQUIRED_EVIDENCE_SOURCES) - by_sample.get(sha256, set())
        if missing:
            raise RuntimeError(
                f"missing evidence for {sha256}: {', '.join(sorted(missing))}"
            )
    return rows


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


def collect_markers(data_dir: Path = DATA_DIR) -> None:
    labels_dir = data_dir / "Labels"
    if labels_dir.is_dir() and not (labels_dir / ".labeler.done").is_file():
        raise RuntimeError(f"missing done marker: {labels_dir / '.labeler.done'}")
    evidence_dir = data_dir / "Evidence"
    if not evidence_dir.is_dir():
        raise RuntimeError(f"missing evidence directory: {evidence_dir}")
    for source in REQUIRED_EVIDENCE_SOURCES:
        marker = evidence_dir / f".{source}.done"
        if not marker.is_file():
            raise RuntimeError(f"missing voter marker: {marker}")
    aggregate_marker = data_dir / "Aggregated" / ".aggregator.done"
    if not aggregate_marker.is_file():
        raise RuntimeError(f"missing done marker: {aggregate_marker}")
    structure_dir = data_dir / "Structure"
    if structure_dir.is_dir() and not (structure_dir / ".done").is_file():
        raise RuntimeError(f"missing done marker: {structure_dir / '.done'}")
    splits_dir = data_dir / "Splits"
    if splits_dir.is_dir() and not (splits_dir / ".done").is_file():
        raise RuntimeError(f"missing done marker: {splits_dir / '.done'}")
    clusters_dir = data_dir / "Clusters"
    if clusters_dir.is_dir() and not (clusters_dir / ".done").is_file():
        raise RuntimeError(f"missing done marker: {clusters_dir / '.done'}")
    for class_dir in (data_dir / "AsyncRAT", data_dir / "OtherMalwares",
                      data_dir / "Benign"):
        if not class_dir.is_dir():
            continue
        # An empty class folder (for example OtherMalwares with no promoted
        # rows yet) must not block the importer.
        if not any(path.is_file() for path in class_dir.rglob("*")):
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

    # Final labels: the aggregator overrides the parser label when present.
    for sha256 in list(labels):
        labels[sha256] = {"fields": load_final_label(sha256, DATA_DIR)}

    active_shas = {
        sha256 for sha256, sample in samples.items()
        if sample["status"] in {"success", "adopted"}
    }
    evidence_rows = read_evidence_rows(EVIDENCE_DIR, active_shas)
    gold_labels = load_gold_labels(DATA_DIR)
    for sha256 in gold_labels:
        if sha256 not in samples:
            raise RuntimeError(f"gold row for unknown sample: {sha256}")
    die_obf: dict[str, str] = {}
    for row in evidence_rows:
        if row["source"] != "detect_it_easy":
            continue
        try:
            raw = json.loads(row["raw"])
        except (TypeError, json.JSONDecodeError):
            continue
        obf_lvl = raw.get("obf_lvl") if isinstance(raw, dict) else None
        if obf_lvl:
            die_obf[row["sha256"]] = str(obf_lvl)

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

    structure: dict[str, dict] = {}
    if STRUCTURE_DIR.is_dir():
        for path in sorted(STRUCTURE_DIR.glob("*.json")):
            payload = read_json(path)
            sha256 = str(payload["sha256"])
            if sha256 not in samples:
                raise RuntimeError(f"structure JSON for unknown sample: {sha256}")
            structure[sha256] = payload["fields"]

    splits: dict[str, dict] = {}
    if SPLITS_DIR.is_dir():
        for path in sorted(SPLITS_DIR.glob("*.json")):
            payload = read_json(path)
            sha256 = str(payload["sha256"])
            if sha256 not in samples:
                raise RuntimeError(f"split JSON for unknown sample: {sha256}")
            splits[sha256] = payload["fields"]

    # Read cluster assignments (mandatory)
    clusters: dict[str, str] = {}
    clusters_dir = DATA_DIR / "Clusters"
    if not (clusters_dir / ".done").is_file():
        raise RuntimeError(f"missing done marker: {clusters_dir / '.done'}")
    json_files = sorted(clusters_dir.glob("*.json"))
    if len(json_files) != len(samples):
        raise RuntimeError(
            f"expected {len(samples)} cluster JSONs, found {len(json_files)}"
        )
    for path in json_files:
        payload = read_json(path)
        sha256 = str(payload["sha256"])
        if sha256 not in samples:
            raise RuntimeError(f"cluster JSON for unknown sample: {sha256}")
        clusters[sha256] = str(payload["fields"].get("cluster_id", ""))
    if len(clusters) != len(samples):
        raise RuntimeError(f"cluster JSONs do not cover all {len(samples)} samples")

    dataset_columns: dict[str, str] = {
        "sha256": "TEXT", "lbl_sts": "TEXT", "sug_fam": "TEXT",
        "obf_lvl": "TEXT", "parser_version": "TEXT", "config": "TEXT",
        "target_class_db": "TEXT",
        "lbl_src": "TEXT", "lbl_reason": "TEXT",
        "is_gold": "INTEGER", "gold_fam": "TEXT",
        "first_seen": "TEXT",
    }
    dataset_columns["cluster_id"] = "TEXT"
    dataset_columns["split"] = "TEXT"
    dataset_columns["split_temporal"] = "TEXT"
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

        for key, value in structure.get(sha256, {}).items():
            column = safe_column(f"structure_{key}")
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
        # Preserve split assignments across importer reruns.  A later split
        # tool owns the value; the importer must not erase it.
        existing_splits = dict(conn_dataset.execute("SELECT sha256, split FROM dataset"))
        existing_temporal = dict(
            conn_dataset.execute("SELECT sha256, split_temporal FROM dataset")
        )
        splits_present = (SPLITS_DIR / ".done").is_file()
        target_shas: dict[str, set[str]] = {
            "AsyncRAT.db": set(), "OtherMalwares.db": set(), "Benign.db": set(),
        }
        ensure_evidence_table(conn_dataset)
        for sha256, sample in samples.items():
            if sample["status"] not in {"success", "adopted"}:
                label = {"lbl_sts": "rejected_hash_mismatch", "sug_fam": "",
                         "obf_lvl": "unknown", "parser_version": "", "config": None}
            else:
                if sha256 not in labels:
                    raise RuntimeError(f"missing label JSON for {sha256}")
                label = labels[sha256]["fields"]
            label["sug_fam"] = canonical_family(label.get("sug_fam", ""))
            is_gold, gold_fam = gold_flags(gold_labels.get(sha256))
            # Gold rows stay in DataSet.db only; they must never reach a class
            # DB or a training split.
            target_class = target_class_for_row(label, is_gold)
            if target_class is not None:
                target_shas[target_class].add(sha256)
            row = {"sha256": sha256, "target_class_db": target_class}
            for key in ("lbl_sts", "sug_fam", "obf_lvl", "parser_version"):
                row[safe_column(key)] = label.get(key, "")
            if sha256 in die_obf:
                row["obf_lvl"] = die_obf[sha256]
            row["cluster_id"] = clusters[sha256]
            row["first_seen"] = sample.get("first_seen") or None
            row["split"], row["split_temporal"] = split_assignment(
                sha256, label, is_gold, splits, splits_present,
                existing_splits.get(sha256), existing_temporal.get(sha256),
            )
            row["lbl_src"] = label.get("lbl_src") or (
                "hand_benign" if label.get("lbl_sts") == "benign" else "parser_only"
            )
            row["lbl_reason"] = label.get("lbl_reason")
            row["is_gold"] = is_gold
            row["gold_fam"] = gold_fam
            config = label.get("config", None)
            row["config"] = json.dumps(config) if isinstance(config, (dict, list)) else config
            for key, value in label.items():
                if key in {"sha256", "lbl_sts", "sug_fam", "obf_lvl", "parser_version", "config"}:
                    continue
                row[safe_column(key)] = value if not isinstance(value, (dict, list)) else json.dumps(value)
            for tool, fields in carved.get(sha256, {}).items():
                for key, value in fields.items():
                    row[safe_column(f"{tool}_{key}")] = value if not isinstance(value, (dict, list)) else json.dumps(value)
            for key, value in structure.get(sha256, {}).items():
                row[safe_column(f"structure_{key}")] = value if not isinstance(value, (dict, list)) else json.dumps(value)
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
        # Remove rows that are no longer active (for example retired DLLs).
        active_shas = set(samples)
        for (sha256,) in list(conn_dataset.execute("SELECT sha256 FROM dataset")):
            if sha256 not in active_shas:
                conn_dataset.execute("DELETE FROM dataset WHERE sha256 = ?", (sha256,))
        for class_name, allowed in target_shas.items():
            class_path = DATA_DIR / class_name
            if not class_path.is_file():
                continue
            conn_class = sqlite3.connect(class_path)
            try:
                exists = conn_class.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='samples'"
                ).fetchone()
                if exists:
                    existing = {row[0] for row in conn_class.execute(
                        "SELECT sha256 FROM samples")}
                    for sha256 in existing - allowed:
                        conn_class.execute(
                            "DELETE FROM samples WHERE sha256 = ?", (sha256,)
                        )
                    conn_class.commit()
            finally:
                conn_class.close()
        # Only human-labelled gold rows must stay out of the class DBs.  Blank
        # gold_status means the row is still a candidate, not a gold row.
        gold_shas = sorted(
            sha256 for sha256, row in gold_labels.items()
            if str(row.get("gold_status") or "").strip()
        )
        if gold_shas:
            placeholders = ",".join("?" for _ in gold_shas)
            for class_name in ("AsyncRAT.db", "OtherMalwares.db", "Benign.db"):
                class_path = DATA_DIR / class_name
                if not class_path.is_file():
                    continue
                conn_class = sqlite3.connect(class_path)
                try:
                    exists = conn_class.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='samples'"
                    ).fetchone()
                    if exists:
                        conn_class.execute(
                            f"DELETE FROM samples WHERE sha256 IN ({placeholders})",
                            gold_shas,
                        )
                        conn_class.commit()
                finally:
                    conn_class.close()
        upsert_evidence(conn_dataset, evidence_rows)
        current_keys = {
            (row["sha256"], row["source"], row["source_version"])
            for row in evidence_rows
        }
        for row in list(conn_dataset.execute(
                "SELECT sha256, source, source_version FROM label_evidence")):
            if tuple(row) not in current_keys:
                conn_dataset.execute(
                    "DELETE FROM label_evidence WHERE sha256=? AND source=? "
                    "AND source_version=?", row,
                )
        conn_dataset.commit()
    finally:
        conn_dataset.close()

    # Markers are consumed idempotently: keep them so a second import (after
    # the split step) does not require running the carvers again.
    print("import complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Shared helpers for label-evidence voters.

Keeps the evidence envelope, rule-set versioning and hit summary in one place.
No voter writes labels or the database.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def write_evidence(out_root: Path, sha256: str, source: str, source_version: str,
                   independence_group: str, verdict: str, strength: str,
                   raw: dict) -> None:
    payload = {
        "schema_version": 1,
        "sha256": sha256,
        "kind": "evidence",
        "producer": f"voter:{source}",
        "fields": {
            "source": source,
            "source_version": source_version,
            "independence_group": independence_group,
            "verdict": verdict,
            "strength": strength,
            "raw": raw,
            "observed_at": utc_now(),
        },
    }
    write_json(out_root / "Evidence" / sha256 / f"{source}.json", payload)


def rules_digest(paths) -> str:
    hasher = hashlib.sha256()
    for path in sorted(Path(path) for path in paths):
        hasher.update(path.name.encode("utf-8") + b"\0" + path.read_bytes())
    return hasher.hexdigest()[:12]


def match_summary(matches) -> dict:
    raw = {"rules": [], "matched_strings": []}
    for match in matches:
        rule = str(getattr(match, "rule", ""))
        if rule and rule not in raw["rules"]:
            raw["rules"].append(rule)
        for string_match in getattr(match, "strings", []):
            offsets = [int(getattr(instance, "offset", 0))
                       for instance in getattr(string_match, "instances", [])]
            raw["matched_strings"].append({
                "rule": rule,
                "identifier": str(getattr(string_match, "identifier", "")),
                "offsets": offsets,
            })
    return raw


def load_label_status(labels_root: Path, sha256: str) -> str:
    path = labels_root / f"{sha256}.json"
    if not path.is_file():
        return "unknown"
    try:
        fields = json.loads(path.read_text(encoding="utf-8")).get("fields", {})
    except (OSError, json.JSONDecodeError):
        return "unknown"
    return str(fields.get("lbl_sts") or "unknown")


def load_cluster(clusters_root: Path, sha256: str) -> str:
    path = clusters_root / f"{sha256}.json"
    if not path.is_file():
        return "unknown"
    try:
        fields = json.loads(path.read_text(encoding="utf-8")).get("fields", {})
    except (OSError, json.JSONDecodeError):
        return "unknown"
    return str(fields.get("cluster_id") or "unknown")


def summarize_hits(hits, labels_root: Path, clusters_root: Path) -> tuple[dict, dict]:
    by_status: dict[str, int] = {}
    by_cluster: dict[str, int] = {}
    for sha256 in hits:
        status = load_label_status(labels_root, sha256)
        by_status[status] = by_status.get(status, 0) + 1
        cluster = load_cluster(clusters_root, sha256)
        by_cluster[cluster] = by_cluster.get(cluster, 0) + 1
    return by_status, by_cluster


def write_marker(evidence_dir: Path, source: str, source_version: str, count: int) -> None:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / f".{source}.done").write_text(
        json.dumps({"producer": f"voter:{source}", "source_version": source_version,
                    "count": count}, sort_keys=True),
        encoding="utf-8",
    )

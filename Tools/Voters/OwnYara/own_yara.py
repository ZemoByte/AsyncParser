#!/usr/bin/env python3
"""Own-YARA voter for AsyncRAT client payloads.

This voter is independent of rat-king-parser and Elastic: the strings are
taken from the AsyncRAT client source and none of them appear in those two
rule sets.  It writes one evidence JSON per sample and never touches labels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yara

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file, write_json  # noqa: E402

DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
DEFAULT_RULES = SCRIPT_DIR / "asyncrat_own.yar"
SOURCE = "own_yara"
GROUP = "yara:own"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def match_raw(matches) -> dict:
    raw = {"rule": "AsyncRAT_Own_Client_Strings", "matched_strings": []}
    if not matches:
        return raw
    match = matches[0]
    raw["rule"] = str(getattr(match, "rule", "AsyncRAT_Own_Client_Strings"))
    raw["tags"] = sorted(str(tag) for tag in getattr(match, "tags", []))
    for string_match in getattr(match, "strings", []):
        instances = []
        for instance in getattr(string_match, "instances", []):
            instances.append(int(getattr(instance, "offset", 0)))
        raw["matched_strings"].append({
            "identifier": str(getattr(string_match, "identifier", "")),
            "offsets": instances,
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


def main() -> int:
    parser = argparse.ArgumentParser(description="Own AsyncRAT YARA voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    rules_path = args.rules.resolve()
    evidence_dir = out_root / "Evidence"
    labels_root = out_root / "Labels"
    clusters_root = out_root / "Clusters"

    if not rules_path.is_file():
        raise RuntimeError(f"YARA rules not found: {rules_path}")
    rules = yara.compile(filepath=str(rules_path))
    rules_hash = hashlib.sha256(rules_path.read_bytes()).hexdigest()[:12]
    source_version = f"own-yara@{rules_hash}"

    hits = []
    total = 0
    for class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        matches = rules.match(str(path))
        verdict = "AsyncRAT" if matches else "no_match"
        raw = match_raw(matches)
        raw["class_dir"] = class_name
        # Own YARA detects the AsyncRAT lineage, including forks.  The
        # aggregator must not treat this as a family-specific vote that
        # contradicts a fork-specific voter.
        raw["scope"] = "lineage"
        payload = {
            "schema_version": 1,
            "sha256": sha256,
            "kind": "evidence",
            "producer": "voter:own_yara",
            "fields": {
                "source": SOURCE,
                "source_version": source_version,
                "independence_group": GROUP,
                "verdict": verdict,
                "strength": "strong" if matches else "weak",
                "raw": raw,
                "observed_at": utc_now(),
            },
        }
        write_json(evidence_dir / sha256 / "own_yara.json", payload)
        total += 1
        if matches:
            hits.append(sha256)

    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / ".own_yara.done").write_text(
        json.dumps({"producer": "voter:own_yara", "source_version": source_version,
                    "count": total}, sort_keys=True),
        encoding="utf-8",
    )

    by_status: dict[str, int] = {}
    by_cluster: dict[str, int] = {}
    for sha256 in hits:
        status = load_label_status(labels_root, sha256)
        by_status[status] = by_status.get(status, 0) + 1
        cluster = load_cluster(clusters_root, sha256)
        by_cluster[cluster] = by_cluster.get(cluster, 0) + 1

    print(f"own_yara: {len(hits)}/{total} hits")
    print(f"hits by lbl_sts: {dict(sorted(by_status.items()))}")
    print(f"hits by cluster_id: {dict(sorted(by_cluster.items()))}")
    print(f"benign hits: {by_status.get('benign', 0)}")
    print(f"rejected_non_dotnet hits: {by_status.get('rejected_non_dotnet', 0)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

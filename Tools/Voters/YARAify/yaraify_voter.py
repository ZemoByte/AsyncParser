#!/usr/bin/env python3
"""YARAify hash-lookup voter.

Requires `YARAIFY_AUTH_KEY` (or --auth-key). Without a key it writes honest
no_match evidence for every sample so the marker exists and the pipeline does
not block. Family-specific rule names are medium evidence; generic matches are
weak. Never prints the key.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file  # noqa: E402
from Tools._voter_common import (  # noqa: E402
    summarize_hits,
    write_evidence,
    write_marker,
)

DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
API_URL = "https://yaraify-api.abuse.ch/api/v1/"
SOURCE = "yaraify"
GROUP = "lookup:yaraify"

RULE_FAMILY = {
    "asyncrat": "AsyncRAT",
    "dcrat": "DcRat",
    "xworm": "XWorm",
    "quasarrat": "QuasarRAT",
    "venomrat": "VenomRAT",
    "njrat": "NjRAT",
    "remcos": "Remcos",
    "xenorat": "XenoRat",
}


def families_for_names(names) -> list[str]:
    families = set()
    for name in names:
        lowered = str(name).lower()
        for needle, family in RULE_FAMILY.items():
            if needle in lowered:
                families.add(family)
    return sorted(families)


def collect_names(payload) -> list[str]:
    names: list[str] = []
    data = payload.get("data") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        data = payload.get("tasks") if isinstance(payload, dict) else None
    if not isinstance(data, list):
        return names
    for item in data:
        if not isinstance(item, dict):
            continue
        signature = item.get("signature")
        if signature:
            names.append(str(signature))
        tasks = item.get("tasks")
        if isinstance(tasks, list):
            for task in tasks:
                if not isinstance(task, dict):
                    continue
                for key in ("rule_name", "description"):
                    if task.get(key):
                        names.append(str(task[key]))
                rules = task.get("yara_rules")
                if isinstance(rules, list):
                    for rule in rules:
                        if isinstance(rule, dict) and rule.get("rule_name"):
                            names.append(str(rule["rule_name"]))
    return names


def lookup(sha256: str, auth_key: str, timeout: int) -> tuple[str, dict]:
    body = json.dumps({"query": "lookup_hash", "search_term": sha256}).encode("utf-8")
    request = urllib.request.Request(
        API_URL, data=body, method="POST",
        headers={"Auth-Key": auth_key, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return "no_match", {"strength": "weak", "raw": {
            "scope": "family", "origin": "yaraify",
            "reason": f"http_error:{exc.code}"}}
    except (urllib.error.URLError, TimeoutError) as exc:
        return "no_match", {"strength": "weak", "raw": {
            "scope": "family", "origin": "yaraify",
            "reason": f"network_error:{exc}"}}
    except json.JSONDecodeError as exc:
        return "no_match", {"strength": "weak", "raw": {
            "scope": "family", "origin": "yaraify",
            "reason": f"json_error:{exc}"}}
    names = collect_names(payload)
    families = families_for_names(names)
    raw = {
        "scope": "lineage" if "AsyncRAT" in families else "family",
        "origin": "yaraify",
        "query_status": payload.get("query_status") if isinstance(payload, dict) else None,
        "rule_names": names[:50],
        "families": families,
    }
    if len(families) == 1:
        strength = "medium"
        verdict = families[0]
    elif len(families) > 1:
        strength = "weak"
        verdict = "no_match"
        raw["reason"] = "multiple_families"
    else:
        strength = "weak"
        verdict = "no_match"
        raw["reason"] = "no_family"
    return verdict, {"strength": strength, "raw": raw}


def main() -> int:
    parser = argparse.ArgumentParser(description="YARAify hash-lookup voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--auth-key", default=os.environ.get("YARAIFY_AUTH_KEY", ""))
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--limit", type=int, default=0,
                        help="0 = all samples")
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    auth_key = str(args.auth_key or "").strip()
    source_version = "yaraify@api_v1"

    hits = []
    total = 0
    for _class_name, path in iter_samples(samples_root):
        if args.limit and total >= args.limit:
            break
        sha256 = sha256_file(path)
        if not auth_key:
            verdict, strength = "no_match", "weak"
            raw = {"scope": "family", "origin": "yaraify",
                   "reason": "auth_key_missing"}
        else:
            verdict, detail = lookup(sha256, auth_key, args.timeout)
            strength = detail.pop("strength", "weak")
            raw = detail["raw"]
        write_evidence(out_root, sha256, SOURCE, source_version, GROUP,
                       verdict, strength, raw)
        total += 1
        if verdict != "no_match":
            hits.append(sha256)
        if auth_key and args.delay:
            time.sleep(args.delay)

    write_marker(out_root / "Evidence", SOURCE, source_version, total)
    by_status, by_cluster = summarize_hits(hits, out_root / "Labels",
                                           out_root / "Clusters")
    print(f"yaraify: {len(hits)}/{total} hits, auth_key_present={bool(auth_key)}")
    print(f"hits by lbl_sts: {dict(sorted(by_status.items()))}")
    print(f"hits by cluster_id: {dict(sorted(by_cluster.items()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

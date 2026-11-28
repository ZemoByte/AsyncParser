#!/usr/bin/env python3
"""YARAify hash-lookup voter.

Uses one abuse.ch key for both services: `YARAIFY_AUTH_KEY` first, then
`MB_AUTH_KEY` (from the environment or the shared `.env`). Without a key it
writes honest no_match evidence for every sample so the marker exists and the
pipeline does not block. Family-specific rule names are medium evidence;
generic matches are weak. Never prints the key.
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
from Tools._label_common import load_final_label  # noqa: E402
from Tools._voter_common import (  # noqa: E402
    evidence_current, summarize_hits, write_evidence, write_marker,
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


def read_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def resolve_auth_key(cli_key: str = "", env_path: Path | None = None) -> str:
    key = str(cli_key or "").strip()
    if key:
        return key
    key = os.environ.get("YARAIFY_AUTH_KEY", "").strip()
    if key:
        return key
    key = os.environ.get("MB_AUTH_KEY", "").strip()
    if key:
        return key
    values = read_env_file(env_path or (ROOT / ".env"))
    return (values.get("YARAIFY_AUTH_KEY")
            or values.get("MB_AUTH_KEY") or "").strip()


def families_for_names(names) -> list[str]:
    families = set()
    for name in names:
        lowered = str(name).lower()
        for needle, family in RULE_FAMILY.items():
            if needle in lowered:
                families.add(family)
    return sorted(families)


def iter_tasks(payload) -> list[dict]:
    """Return the task list from both response shapes."""
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    tasks = None
    if isinstance(data, dict):
        tasks = data.get("tasks")
    elif isinstance(data, list):
        tasks = data
    if not isinstance(tasks, list):
        tasks = payload.get("tasks")
    if not isinstance(tasks, list):
        return []
    return [item for item in tasks if isinstance(item, dict)]


def collect_metadata_signatures(payload) -> list[str]:
    if not isinstance(payload, dict):
        return []
    data = payload.get("data")
    if isinstance(data, dict):
        metadata = data.get("metadata")
        if isinstance(metadata, dict) and metadata.get("signature"):
            return [str(metadata["signature"])]
    return []


def collect_clamav_results(payload) -> list[str]:
    names: list[str] = []
    for task in iter_tasks(payload):
        for value in task.get("clamav_results") or []:
            if isinstance(value, str):
                names.append(value)
    return names


def collect_structured_names(payload) -> list[str]:
    """High-authority names: rule names, families and unpacked rules."""
    names = list(collect_metadata_signatures(payload))
    for task in iter_tasks(payload):
        if task.get("signature"):
            names.append(str(task["signature"]))
        for result in task.get("static_results") or []:
            if not isinstance(result, dict):
                continue
            for key in ("rule_name", "malpedia_family"):
                if result.get(key):
                    names.append(str(result[key]))
        for unpack in task.get("unpack_results") or []:
            if not isinstance(unpack, dict):
                continue
            for match in unpack.get("unpacked_yara_matches") or []:
                if isinstance(match, dict) and match.get("rule_name"):
                    names.append(str(match["rule_name"]))
                elif isinstance(match, str):
                    names.append(match)
        for rule in task.get("yara_rules") or []:
            if isinstance(rule, dict) and rule.get("rule_name"):
                names.append(str(rule["rule_name"]))
            elif isinstance(rule, str):
                names.append(rule)
    return names


def collect_names(payload) -> list[str]:
    """All names for the audit trail (descriptions included)."""
    names = collect_structured_names(payload)
    names.extend(collect_clamav_results(payload))
    for task in iter_tasks(payload):
        for result in task.get("static_results") or []:
            if isinstance(result, dict):
                for key in ("description",):
                    if result.get(key):
                        names.append(str(result[key]))
        for key in ("rule_name", "description"):
            if task.get(key):
                names.append(str(task[key]))
        for rule in task.get("yara_rules") or []:
            if isinstance(rule, dict):
                for key in ("rule_name", "description"):
                    if rule.get(key):
                        names.append(str(rule[key]))
            elif isinstance(rule, str):
                names.append(rule)
    return list(dict.fromkeys(names))


def evaluate_payload(payload) -> tuple[str, dict]:
    """Resolve one family from YARAify evidence.

    Static rule names are authoritative. Curated names from metadata/ClamAV
    only *disambiguate* conflicting static rules when they agree with one of
    them; they never override a single static family.
    """
    names = collect_names(payload)
    structured = set(families_for_names(collect_structured_names(payload)))
    curated = set(families_for_names(
        collect_metadata_signatures(payload) + collect_clamav_results(payload)))
    description = set(families_for_names(names))
    raw = {
        "scope": "lineage" if "AsyncRAT" in description else "family",
        "origin": "yaraify",
        "query_status": payload.get("query_status") if isinstance(payload, dict) else None,
        "rule_names": names[:50],
        "families": sorted(description),
        "structured_families": sorted(structured),
        "curated_families": sorted(curated),
    }
    if structured or curated:
        combined = structured | curated
        if len(combined) == 1:
            raw["resolved_by"] = "static" if structured else "curated"
            return next(iter(combined)), {"strength": "medium", "raw": raw}
        if len(structured) > 1 and len(curated) == 1 and curated <= structured:
            raw["resolved_by"] = "curated_disambiguation"
            return next(iter(curated)), {"strength": "medium", "raw": raw}
        raw["reason"] = "multiple_families"
        return "no_match", {"strength": "weak", "raw": raw}
    if len(description) == 1:
        raw["resolved_by"] = "description"
        return next(iter(description)), {"strength": "medium", "raw": raw}
    if len(description) > 1:
        raw["reason"] = "multiple_families"
        return "no_match", {"strength": "weak", "raw": raw}
    raw["reason"] = "no_family"
    return "no_match", {"strength": "weak", "raw": raw}


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
    return evaluate_payload(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description="YARAify hash-lookup voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--auth-key", default=os.environ.get("YARAIFY_AUTH_KEY", ""))
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--delay", type=float, default=0.25)
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--skip-trivial", action=argparse.BooleanOptionalAction,
                        default=True,
                        help="skip benign/non-.NET without an API call")
    parser.add_argument("--limit", type=int, default=0,
                        help="0 = all samples")
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    auth_key = resolve_auth_key(args.auth_key)
    source_version = "yaraify@api_v1"

    hits = []
    skipped = {"benign": 0, "non_dotnet": 0}
    total = 0
    reused = 0
    for _class_name, path in iter_samples(samples_root):
        if args.limit and total >= args.limit:
            break
        sha256 = sha256_file(path)
        if args.reuse and evidence_current(out_root, sha256, SOURCE,
                                           source_version):
            reused += 1
            total += 1
            continue
        status = ""
        try:
            status = str(load_final_label(sha256, out_root).get("lbl_sts") or "")
        except RuntimeError:
            status = ""
        if args.skip_trivial and status in {"benign", "rejected_non_dotnet"}:
            reason = ("skipped_benign" if status == "benign"
                      else "skipped_non_dotnet")
            existing = None
            evidence_path = out_root / "Evidence" / sha256 / f"{SOURCE}.json"
            if evidence_path.is_file():
                try:
                    existing = json.loads(evidence_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    existing = None
            fields = (existing or {}).get("fields") or {}
            if fields.get("verdict") not in (None, "no_match"):
                total += 1
                continue
            write_evidence(out_root, sha256, SOURCE, source_version, GROUP,
                           "no_match", "weak",
                           {"scope": "family", "origin": "yaraify",
                            "reason": reason, "query_status": "skipped"})
            skipped["benign" if status == "benign" else "non_dotnet"] += 1
            total += 1
            continue
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
    print(f"yaraify: reused={reused} skipped={skipped}")
    print(f"hits by lbl_sts: {dict(sorted(by_status.items()))}")
    print(f"hits by cluster_id: {dict(sorted(by_cluster.items()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

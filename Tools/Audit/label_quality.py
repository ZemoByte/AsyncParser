#!/usr/bin/env python3
"""Automated label-quality audit (not a gold audit).

Read-only DB analysis. It does not fill, infer or merge gold fields.
"""

from __future__ import annotations

import csv
import datetime
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from itertools import combinations
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import load_final_label  # noqa: E402

DATA = ROOT / "Data"
HEADER = "Automated label-quality audit (not a gold audit)"
CLASSES = ("verified", "verified_other", "benign", "unverified")


def classify_evidence(verdicts: dict[str, str]) -> str:
    """Classify the non-empty family votes for one sample."""
    family = {source for source, verdict in verdicts.items()
              if verdict and verdict != "no_match"}
    if not family:
        return "no_family"
    if family == {"malwarebazaar"}:
        return "mb_only"
    if "malwarebazaar" in family:
        return "multi_source"
    return "other_sources"


def classify_conflict(verdicts: dict[str, str],
                      current_family: str) -> str:
    families = [verdict for verdict in verdicts.values()
                if verdict and verdict != "no_match"]
    if not families:
        return "no_family"
    counts = Counter(families)
    highest = max(counts.values())
    leaders = [family for family, count in counts.items()
               if count == highest]
    if len(leaders) > 1:
        return "tie"
    return ("majority_support" if leaders[0] == current_family
            else "majority_different")


def family_pairs(verdicts: dict[str, str]) -> Counter:
    families = sorted({verdict for verdict in verdicts.values()
                       if verdict and verdict != "no_match"})
    pairs = Counter()
    for left, right in combinations(families, 2):
        pairs[f"{left}|{right}"] += 1
    return pairs


def current_family(status: str, sug_fam: str) -> str:
    if status == "verified":
        return "AsyncRAT"
    if status == "benign":
        return "Benign"
    return str(sug_fam or "")


def load_db() -> tuple[list[tuple], list[tuple]]:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    try:
        rows = list(conn.execute(
            "SELECT sha256, lbl_sts, sug_fam, cluster_id, config, obf_lvl "
            "FROM dataset"))
        evidence = list(conn.execute(
            "SELECT sha256, source, verdict, independence_group, scope "
            "FROM label_evidence"))
    finally:
        conn.close()
    return rows, evidence


def config_present(value: str | None) -> bool:
    if not value:
        return False
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return False
    return bool(parsed) and "parse_error" not in parsed


def reason_lineage_only(sha: str) -> bool:
    try:
        fields = load_final_label(sha, DATA)
    except (OSError, RuntimeError):
        return False
    reason = fields.get("lbl_reason")
    if isinstance(reason, str):
        try:
            reason = json.loads(reason)
        except json.JSONDecodeError:
            return False
    return bool(isinstance(reason, dict) and reason.get("lineage_only"))


def summarize(rows: list[tuple], evidence: list[tuple]) -> dict:
    by_sha = defaultdict(list)
    for sha, source, verdict, group, scope in evidence:
        by_sha[sha].append({"source": source, "verdict": verdict,
                            "group": group, "scope": scope})
    classes = {}
    for status in CLASSES:
        selected = [row for row in rows if row[1] == status]
        entries = []
        for sha, status, sug_fam, _cluster, config, obf in selected:
            votes = by_sha.get(sha, [])
            verdicts = {vote["source"]: vote["verdict"] for vote in votes}
            family_votes = {source: verdict for source, verdict in verdicts.items()
                            if verdict and verdict != "no_match"}
            family_scoped = {vote["source"] for vote in votes
                             if vote["scope"] == "family"
                             and vote["verdict"] != "no_match"}
            groups = {vote["group"] for vote in votes
                      if vote["verdict"] != "no_match"}
            entries.append({
                "class": classify_evidence(verdicts),
                "evidence": len(votes),
                "voters": len({vote["source"] for vote in votes}),
                "family_voters": len(family_votes),
                "family_groups": len(groups),
                "config": config_present(config),
                "no_family_scoped": len(family_scoped) == 0,
                "lineage_only": reason_lineage_only(sha),
                "obfuscated": str(obf or "").startswith("obfuscated"),
                "family_verdicts": sorted(set(family_votes.values())),
                "conflict": len(set(family_votes.values())) > 1,
                "current_family": current_family(status, sug_fam),
                "conflict_category": classify_conflict(
                    verdicts, current_family(status, sug_fam)),
                "family_pairs": dict(family_pairs(family_votes)),
            })
        count = len(entries)
        classes[status] = {
            "rows": count,
            "evidence_total": sum(item["evidence"] for item in entries),
            "evidence_mean": (sum(item["evidence"] for item in entries) / count
                              if count else 0.0),
            "voters_mean": (sum(item["voters"] for item in entries) / count
                            if count else 0.0),
            "family_voters_mean": (sum(item["family_voters"] for item in entries)
                                   / count if count else 0.0),
            "family_groups_mean": (sum(item["family_groups"] for item in entries)
                                   / count if count else 0.0),
            "mb_only": sum(1 for item in entries if item["class"] == "mb_only"),
            "multi_source": sum(1 for item in entries
                                if item["class"] == "multi_source"),
            "other_sources": sum(1 for item in entries
                                 if item["class"] == "other_sources"),
            "no_family": sum(1 for item in entries
                             if item["class"] == "no_family"),
            "config_present": sum(1 for item in entries if item["config"]),
            "lineage_only": sum(1 for item in entries if item["lineage_only"]),
            "no_family_scoped_verdict": sum(
                1 for item in entries if item["no_family_scoped"]),
            "obfuscated": sum(1 for item in entries if item["obfuscated"]),
            "conflicts": sum(1 for item in entries if item["conflict"]),
            "majority_support": sum(1 for item in entries
                                    if item["conflict_category"]
                                    == "majority_support"),
            "majority_different": sum(1 for item in entries
                                      if item["conflict_category"]
                                      == "majority_different"),
            "tie": sum(1 for item in entries
                       if item["conflict_category"] == "tie"),
            "no_family": sum(1 for item in entries
                             if item["conflict_category"] == "no_family"),
            "conflict_categories": dict(Counter(
                item["conflict_category"] for item in entries
                if item["conflict"])),
            "top_pairs": {},
        }
        pair_counts = Counter()
        for item in entries:
            pair_counts.update(item.get("family_pairs", {}))
        classes[status]["top_pairs"] = dict(pair_counts.most_common(10))
    return classes
    return classes


def pairwise_agreement(rows: list[tuple], evidence: list[tuple]) -> dict:
    status = {row[0]: row for row in rows}
    by_sha = defaultdict(dict)
    for sha, source, verdict, _group, _scope in evidence:
        if verdict and verdict != "no_match":
            by_sha[sha][source] = verdict
    sources = sorted({source for _sha, source, _verdict, _group, _scope
                      in evidence})
    result = {"plain": {}, "obfuscated": {}}
    for stratum, predicate in (
            ("plain", lambda obf: not str(obf or "").startswith("obfuscated")),
            ("obfuscated", lambda obf: str(obf or "").startswith("obfuscated"))):
        selected = [sha for sha, votes in by_sha.items()
                    if predicate(status[sha][5])]
        for left, right in combinations(sources, 2):
            both = [sha for sha in selected
                    if left in by_sha[sha] and right in by_sha[sha]]
            agree = sum(1 for sha in both
                        if by_sha[sha][left] == by_sha[sha][right])
            result[stratum][f"{left}|{right}"] = {
                "both": len(both),
                "agree": agree,
                "rate": agree / len(both) if both else None,
            }
    return result


def gold_summary(rows: list[tuple], evidence: list[tuple]) -> dict:
    status = {row[0]: row for row in rows}
    by_sha = defaultdict(list)
    for sha, source, verdict, group, scope in evidence:
        by_sha[sha].append({"source": source, "verdict": verdict,
                            "group": group, "scope": scope})
    gold_path = DATA / "Gold" / "gold.csv"
    with gold_path.open(newline="", encoding="utf-8") as handle:
        candidates = list(csv.DictReader(handle))
    entries = []
    for candidate in candidates:
        sha = candidate["sha256"]
        row = status.get(sha)
        votes = by_sha.get(sha, [])
        family = {vote["verdict"] for vote in votes
                  if vote["verdict"] and vote["verdict"] != "no_match"}
        verdicts = {vote["source"]: vote["verdict"] for vote in votes}
        current = current_family(row[1] if row else "",
                                 row[2] if row else "")
        entries.append({
            "sha256": sha,
            "current_status": row[1] if row else "",
            "current_family": row[2] if row else "",
            "evidence": len(votes),
            "voters": sorted({vote["source"] for vote in votes}),
            "family_verdicts": sorted(family),
            "conflict": len(family) > 1,
            "conflict_category": classify_conflict(verdicts, current),
        })
    return {"rows": len(entries),
            "conflicts": sum(1 for entry in entries if entry["conflict"]),
            "entries": entries}


def main() -> int:
    rows, evidence = load_db()
    result = {
        "header": HEADER,
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "classes": summarize(rows, evidence),
        "pairwise_agreement": pairwise_agreement(rows, evidence),
        "gold_candidates": gold_summary(rows, evidence),
        "note": "No gold_status or gold_family is read, filled or inferred.",
    }
    out = DATA / "Audit" / "label_quality.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({
        "header": HEADER,
        "classes": {name: {key: value for key, value in data.items()
                           if key in ("rows", "mb_only", "multi_source",
                                      "config_present", "lineage_only",
                                      "obfuscated", "conflicts")}
                    for name, data in result["classes"].items()},
        "gold": {"rows": result["gold_candidates"]["rows"],
                 "conflicts": result["gold_candidates"]["conflicts"]},
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

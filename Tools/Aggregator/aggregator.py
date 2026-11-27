#!/usr/bin/env python3
"""Aggregate independent label evidence into a final label.

Implements Docs/Plan.md section 4 rules 1-10.  The pure `aggregate()` function
is used by the tests; `main()` only handles files and markers.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import (  # noqa: E402
    FAMILY_VERDICTS,
    LABEL_STATUSES,
    STRENGTHS,
    canonical_family,
    load_gold_labels,
)

DEFAULT_DATA = ROOT / "Data"
STRENGTH_RANK = {"strong": 3, "medium": 2, "weak": 1}
REQUIRED_VOTERS = ("rat_king_parser", "own_yara", "elastic", "malpedia",
                   "malwarebazaar", "detect_it_easy", "yaraify")


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def read_evidence(evidence_dir: Path, sha256: str) -> list[dict]:
    source_dir = evidence_dir / sha256
    if not source_dir.is_dir():
        return []
    rows = []
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
        if not str(fields.get("source_version") or ""):
            raise RuntimeError(f"evidence JSON in {path} has no source_version")
        if not str(fields.get("independence_group") or ""):
            raise RuntimeError(f"evidence JSON in {path} has no independence_group")
        verdict = str(fields.get("verdict") or "")
        if verdict != "no_match":
            canonical_family(verdict)
        if str(fields.get("strength") or "") not in STRENGTHS:
            raise RuntimeError(f"invalid strength in {path}: {fields.get('strength')}")
        if not str(fields.get("observed_at") or ""):
            raise RuntimeError(f"evidence JSON in {path} has no observed_at")
        rows.append(fields)
    return rows


def _vote(evidence: dict) -> dict:
    raw_verdict = str(evidence.get("verdict") or "")
    verdict = "no_match" if raw_verdict == "no_match" else canonical_family(raw_verdict)
    raw = evidence.get("raw")
    scope = "family"
    if isinstance(raw, dict):
        scope = str(raw.get("scope") or "family")
    return {
        "source": str(evidence.get("source") or ""),
        "independence_group": str(evidence.get("independence_group") or ""),
        "verdict": verdict,
        "strength": str(evidence.get("strength") or ""),
        "scope": scope,
    }


def aggregate(label_fields: dict, evidence_rows: list[dict],
              contradiction_min_strength: str = "medium") -> dict:
    """Apply Plan.md section 4 rules 1-10.

    `label_fields` is the parser label (is_dotnet, lbl_sts, sug_fam).
    `evidence_rows` are the voter `fields` objects.
    """
    if contradiction_min_strength not in STRENGTHS:
        raise RuntimeError(f"invalid contradiction_min_strength: {contradiction_min_strength}")
    threshold = STRENGTH_RANK[contradiction_min_strength]

    status = str(label_fields.get("lbl_sts") or "")
    suggested = str(label_fields.get("sug_fam") or "")
    is_dotnet = bool(label_fields.get("is_dotnet"))
    votes = [_vote(evidence) for evidence in evidence_rows]
    reason = {
        "votes": votes,
        "groups": {},
        "contradictions": [],
        "abstentions": sum(1 for vote in votes if vote["verdict"] == "no_match"),
        "evidence_count": len(evidence_rows),
        "contradiction_min_strength": contradiction_min_strength,
    }

    # Rule 8: benign rows are hand-supplied and pass through.
    if status == "benign":
        return {"lbl_sts": "benign", "sug_fam": "Benign",
                "lbl_src": "hand_benign", "lbl_reason": reason}

    # Rule 9: reference archives pass through.
    if status == "reference_only":
        return {"lbl_sts": "reference_only", "sug_fam": suggested,
                "lbl_src": "parser_only", "lbl_reason": reason}

    # Rule 1: no CLR header, regardless of votes.
    if not is_dotnet:
        return {"lbl_sts": "rejected_non_dotnet", "sug_fam": "",
                "lbl_src": "auto_aggregator", "lbl_reason": reason}

    positives = [vote for vote in votes if vote["verdict"] != "no_match"]
    group_families: dict[str, set[str]] = {}
    for vote in positives:
        group_families.setdefault(vote["independence_group"], set()).add(vote["verdict"])

    # Count independent groups per family.  A group contributes only when it
    # names exactly one family and has at least one strong/medium vote.
    group_support: dict[str, set[str]] = {}
    for group, families in group_families.items():
        if len(families) != 1:
            continue
        family = next(iter(families))
        if any(vote["independence_group"] == group
               and vote["verdict"] == family
               and vote["strength"] in {"strong", "medium"}
               for vote in positives):
            group_support.setdefault(family, set()).add(group)

    # Rule 6: contradiction is any family disagreement at or above the
    # configured strength.  Absence (no_match) is not a contradiction.
    # Lineage votes (own YARA/Elastic/Malpedia AsyncRAT) support AsyncRAT but
    # must not contradict a family-specific fork vote.  Only family-scoped
    # votes can contradict or promote a non-AsyncRAT family.
    family_positives = [vote for vote in positives if vote["scope"] != "lineage"]
    family_group_support: dict[str, set[str]] = {}
    for vote in family_positives:
        group = vote["independence_group"]
        families = group_families.get(group, set())
        if len(families) != 1:
            continue
        family = next(iter(families))
        if vote["verdict"] == family and vote["strength"] in {"strong", "medium"}:
            family_group_support.setdefault(family, set()).add(group)
    threshold_families = {
        vote["verdict"]
        for vote in family_positives
        if STRENGTH_RANK[vote["strength"]] >= threshold
    }
    reason["groups"] = {
        family: sorted(groups) for family, groups in sorted(group_support.items())
    }
    if len(threshold_families) > 1:
        reason["contradictions"] = [sorted(threshold_families)]
        non_async = sorted(family for family in threshold_families
                           if family != "AsyncRAT")
        if "AsyncRAT" in threshold_families and len(non_async) == 1:
            # Own-YARA matches AsyncRAT-derived forks; keep the fork family
            # as the suggestion so the clusterer partitions it correctly.
            suggested_family = non_async[0]
        else:
            best = sorted(
                family_group_support,
                key=lambda family: (-len(family_group_support[family]), family),
            )
            if best:
                suggested_family = best[0]
            elif threshold_families:
                suggested_family = sorted(threshold_families)[0]
            else:
                suggested_family = suggested
        return {"lbl_sts": "review", "sug_fam": suggested_family,
                "lbl_src": "auto_aggregator", "lbl_reason": reason}

    # Rule 4: verified AsyncRAT needs two independent groups.
    if len(group_support.get("AsyncRAT", set())) >= 2:
        return {"lbl_sts": "verified", "sug_fam": "",
                "lbl_src": "auto_aggregator", "lbl_reason": reason}

    # Rule 5: verified_other needs two family-scoped groups for one non-AsyncRAT
    # family.  Lineage AsyncRAT votes do not count for or against it.
    other = [
        (family, groups) for family, groups in family_group_support.items()
        if family != "AsyncRAT" and len(groups) >= 2
    ]
    if len(other) == 1:
        family, _groups = other[0]
        return {"lbl_sts": "verified_other", "sug_fam": family,
                "lbl_src": "auto_aggregator", "lbl_reason": reason}
    if len(other) > 1:
        # Defensive: a strong disagreement should already be a contradiction.
        reason["contradictions"] = [sorted(family for family, _ in other)]
        return {"lbl_sts": "review", "sug_fam": sorted(family for family, _ in other)[0],
                "lbl_src": "auto_aggregator", "lbl_reason": reason}

    # Rule 7: one strong/medium group, weak-only, or nothing.
    if len(group_support) == 1:
        family = next(iter(group_support))
        return {"lbl_sts": "unverified", "sug_fam": family,
                "lbl_src": "auto_aggregator", "lbl_reason": reason}
    # A lineage AsyncRAT group plus one family-scoped fork group is not a
    # contradiction; keep the fork as the suggested family for partitioning.
    non_async = [family for family in group_support if family != "AsyncRAT"]
    if len(non_async) == 1:
        return {"lbl_sts": "unverified", "sug_fam": non_async[0],
                "lbl_src": "auto_aggregator", "lbl_reason": reason}
    return {"lbl_sts": "unverified", "sug_fam": "",
            "lbl_src": "auto_aggregator", "lbl_reason": reason}


def apply_gold_override(result: dict, gold_row: dict | None) -> dict:
    """Rule 10: a human gold label overrides the aggregator result."""
    if not gold_row or not gold_row.get("gold_status"):
        return result
    status = str(gold_row["gold_status"])
    if status not in LABEL_STATUSES:
        raise RuntimeError(f"invalid gold status: {status}")
    family = str(gold_row.get("gold_family") or "").strip()
    if status == "verified":
        family = ""
    elif status == "benign":
        family = "Benign"
    elif family:
        family = canonical_family(family)
    if status == "verified_other" and not family:
        raise RuntimeError("gold verified_other requires a gold_family")
    updated = dict(result)
    updated["lbl_sts"] = status
    updated["sug_fam"] = family
    updated["lbl_src"] = "human_gold"
    reason = dict(updated.get("lbl_reason") or {})
    reason["gold_override"] = {"gold_status": status, "gold_family": family}
    updated["lbl_reason"] = reason
    return updated


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate label evidence")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--contradiction-min-strength", default="medium",
                        choices=sorted(STRENGTHS))
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    evidence_dir = data_root / "Evidence"
    labels_dir = data_root / "Labels"
    aggregate_dir = data_root / "Aggregated"

    for voter in REQUIRED_VOTERS:
        marker = evidence_dir / f".{voter}.done"
        if not marker.is_file():
            raise RuntimeError(f"missing voter marker: {marker}")

    label_files = sorted(labels_dir.glob("*.json"))
    if not label_files:
        raise RuntimeError(f"no label JSONs in {labels_dir}")
    gold_labels = load_gold_labels(data_root)

    counts: Counter = Counter()
    families: Counter = Counter()
    for path in label_files:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"invalid label JSON in {path}: {exc}") from exc
        sha256 = str(payload.get("sha256") or "")
        if sha256 != path.stem:
            raise RuntimeError(f"label filename does not match sha256: {path}")
        fields = payload.get("fields")
        if not isinstance(fields, dict):
            raise RuntimeError(f"label JSON in {path} has no fields object")
        evidence = read_evidence(evidence_dir, sha256)
        result = aggregate(fields, evidence, args.contradiction_min_strength)
        result = apply_gold_override(result, gold_labels.get(sha256))
        write_json(aggregate_dir / f"{sha256}.json", {
            "schema_version": 1,
            "sha256": sha256,
            "kind": "aggregate",
            "producer": "aggregator",
            "fields": result,
        })
        counts[result["lbl_sts"]] += 1
        families[result["sug_fam"] or "<none>"] += 1

    aggregate_dir.mkdir(parents=True, exist_ok=True)
    (aggregate_dir / ".aggregator.done").write_text(
        json.dumps({"producer": "aggregator", "count": len(label_files),
                    "contradiction_min_strength": args.contradiction_min_strength},
                   sort_keys=True),
        encoding="utf-8",
    )
    print(f"aggregated {len(label_files)} samples into {aggregate_dir}")
    print(f"lbl_sts: {dict(sorted(counts.items()))}")
    print(f"sug_fam: {dict(sorted(families.items()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

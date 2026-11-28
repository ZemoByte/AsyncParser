#!/usr/bin/env python3
"""Elastic protections-artifacts YARA voter.

Rules are reference material under Reference/Elastic/rules (gitignored).
Elastic License 2.0: local use only; do not redistribute as a hosted service.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yara

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file  # noqa: E402
from Tools._voter_common import (
    evidence_current,  # noqa: E402
    match_summary,
    rules_digest,
    summarize_hits,
    write_evidence,
    write_marker,
)

DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
DEFAULT_RULES = ROOT / "Reference" / "Elastic" / "rules"
SOURCE = "elastic"
GROUP = "yara:elastic"

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


def families_for_rules(rule_names) -> list[str]:
    families = set()
    for name in rule_names:
        lowered = str(name).lower()
        for needle, family in RULE_FAMILY.items():
            if needle in lowered:
                families.add(family)
    return sorted(families)


def main() -> int:
    parser = argparse.ArgumentParser(description="Elastic YARA voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES)
    parser.add_argument("--reuse", action="store_true")
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    rules_dir = args.rules_dir.resolve()
    rule_paths = sorted(rules_dir.glob("*.yar"))
    if not rule_paths:
        raise RuntimeError(f"no Elastic .yar files in {rules_dir}")
    rules = yara.compile(filepaths={path.stem: str(path) for path in rule_paths})
    source_version = f"elastic@{rules_digest(rule_paths)}"

    hits = []
    total = 0
    for _class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        if args.reuse and evidence_current(out_root, sha256, SOURCE,
                                           source_version):
            total += 1
            continue
        matches = rules.match(str(path))
        families = families_for_rules(str(getattr(m, "rule", "")) for m in matches)
        if len(families) == 1:
            verdict = families[0]
            strength = "strong"
        elif len(families) > 1:
            verdict = "no_match"
            strength = "weak"
        else:
            verdict = "no_match"
            strength = "weak"
        raw = match_summary(matches)
        raw["scope"] = "lineage" if "AsyncRAT" in families else "family"
        raw["families"] = families
        if len(families) > 1:
            raw["reason"] = "multiple_families"
        write_evidence(out_root, sha256, SOURCE, source_version, GROUP,
                       verdict, strength, raw)
        total += 1
        if verdict != "no_match":
            hits.append(sha256)

    write_marker(out_root / "Evidence", SOURCE, source_version, total)
    by_status, by_cluster = summarize_hits(hits, out_root / "Labels",
                                           out_root / "Clusters")
    print(f"elastic: {len(hits)}/{total} hits")
    print(f"hits by lbl_sts: {dict(sorted(by_status.items()))}")
    print(f"hits by cluster_id: {dict(sorted(by_cluster.items()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

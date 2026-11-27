#!/usr/bin/env python3
"""Malpedia family-rule YARA voter (white-TLP rules only).

Rules are reference material under Reference/Malpedia/rules (gitignored).
Malpedia white rules are used locally; respect their TLP/licence.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import yara

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file  # noqa: E402
from Tools._voter_common import (  # noqa: E402
    match_summary,
    rules_digest,
    summarize_hits,
    write_evidence,
    write_marker,
)

DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
DEFAULT_RULES = ROOT / "Reference" / "Malpedia" / "rules"
SOURCE = "malpedia"
GROUP = "yara:malpedia"

FAMILY_DIRS = {
    "win.asyncrat": "AsyncRAT",
    "win.dcrat": "DcRat",
    "win.xworm": "XWorm",
    "win.quasar_rat": "QuasarRAT",
    "win.venom": "VenomRAT",
    "win.njrat": "NjRAT",
    "win.remcos": "Remcos",
    "win.xenorat": "XenoRat",
}
RULE_RE = re.compile(r"^\s*rule\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)


def build_rule_families(paths) -> dict[str, str | None]:
    mapping: dict[str, str | None] = {}
    for path in paths:
        family = FAMILY_DIRS.get(path.parent.name)
        if family is None:
            continue
        for name in RULE_RE.findall(path.read_text(encoding="utf-8", errors="replace")):
            if name in mapping and mapping[name] != family:
                mapping[name] = None
            else:
                mapping[name] = family
    return mapping


def main() -> int:
    parser = argparse.ArgumentParser(description="Malpedia YARA voter")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--rules-dir", type=Path, default=DEFAULT_RULES)
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    rules_dir = args.rules_dir.resolve()
    rule_paths = sorted(rules_dir.glob("*/*.yar"))
    if not rule_paths:
        raise RuntimeError(f"no Malpedia .yar files in {rules_dir}")
    rule_families = build_rule_families(rule_paths)
    rules = yara.compile(filepaths={
        str(path.relative_to(rules_dir)): str(path) for path in rule_paths
    })
    source_version = f"malpedia@{rules_digest(rule_paths)}"

    hits = []
    total = 0
    for _class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        matches = rules.match(str(path))
        matched_rules = [str(getattr(m, "rule", "")) for m in matches]
        families = sorted({rule_families.get(rule) for rule in matched_rules
                           if rule_families.get(rule)})
        if len(families) == 1:
            verdict = families[0]
            strength = "strong" if any("_auto" not in rule
                                        for rule in matched_rules) else "medium"
        elif len(families) > 1:
            verdict = "no_match"
            strength = "weak"
        else:
            verdict = "no_match"
            strength = "weak"
        raw = match_summary(matches)
        raw["scope"] = "lineage" if "AsyncRAT" in families else "family"
        raw["families"] = families
        raw["rule_families"] = {rule: rule_families.get(rule) for rule in matched_rules}
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
    print(f"malpedia: {len(hits)}/{total} hits")
    print(f"hits by lbl_sts: {dict(sorted(by_status.items()))}")
    print(f"hits by cluster_id: {dict(sorted(by_cluster.items()))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

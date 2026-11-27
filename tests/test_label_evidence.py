#!/usr/bin/env python3
"""Synthetic tests for the Phase 0.4 label-evidence core.

Run: python3 tests/run_tests.py
No real samples are read.
"""

from __future__ import annotations

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from Tools._label_common import (  # noqa: E402
    canonical_family,
    load_final_label,
    load_gold_labels,
)
from Tools.Aggregator.aggregator import aggregate, apply_gold_override  # noqa: E402
from Tools.Clustering import clusterer  # noqa: E402
from Tools.Importer.importer import (  # noqa: E402
    collect_markers,
    ensure_evidence_table,
    gold_flags,
    persisted_scope,
    target_class_db,
    target_class_for_row,
    upsert_evidence,
)
from Tools.Voters.Elastic.elastic_voter import families_for_rules  # noqa: E402
from Tools.Voters.MalwareBazaar.mb_voter import families_from_tokens  # noqa: E402
from Tools.Voters.YARAify.yaraify_voter import families_for_names  # noqa: E402


def ev(source="voter", group="g1", verdict="AsyncRAT", strength="strong",
       scope="family"):
    return {
        "source": source,
        "source_version": "v1",
        "independence_group": group,
        "verdict": verdict,
        "strength": strength,
        "raw": {"scope": scope},
        "observed_at": "2026-01-01T00:00:00+00:00",
    }


def label(is_dotnet=True, status="unverified", family=""):
    return {"is_dotnet": is_dotnet, "lbl_sts": status, "sug_fam": family}


class AggregatorTests(unittest.TestCase):
    def test_rule1_no_clr_is_rejected(self):
        result = aggregate(label(is_dotnet=False), [ev(group="g1")])
        self.assertEqual(result["lbl_sts"], "rejected_non_dotnet")
        self.assertEqual(result["sug_fam"], "")

    def test_rule2_no_match_abstains(self):
        result = aggregate(label(), [ev(group="g1", verdict="no_match", strength="weak")])
        self.assertEqual(result["lbl_sts"], "unverified")
        self.assertEqual(result["sug_fam"], "")
        self.assertEqual(result["lbl_reason"]["abstentions"], 1)

    def test_rule4_two_independent_groups_verified(self):
        result = aggregate(label(), [ev(group="g1"), ev(group="g2")])
        self.assertEqual(result["lbl_sts"], "verified")
        self.assertEqual(result["sug_fam"], "")
        self.assertEqual(result["lbl_reason"]["groups"], {"AsyncRAT": ["g1", "g2"]})

    def test_rule4_same_group_is_one_vote(self):
        result = aggregate(label(), [ev(group="g1"), ev(group="g1")])
        self.assertEqual(result["lbl_sts"], "unverified")
        self.assertEqual(result["sug_fam"], "AsyncRAT")

    def test_rule7_weak_only_is_unverified(self):
        result = aggregate(label(), [
            ev(group="g1", strength="weak"),
            ev(group="g2", strength="weak"),
        ])
        self.assertEqual(result["lbl_sts"], "unverified")
        self.assertEqual(result["sug_fam"], "")

    def test_rule6_strong_contradiction_is_review(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong"),
            ev(group="g2", verdict="XWorm", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "review")
        self.assertEqual(result["sug_fam"], "XWorm")
        self.assertEqual(result["lbl_reason"]["contradictions"], [["AsyncRAT", "XWorm"]])

    def test_rule6_weak_contradiction_ignored_by_default(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong"),
            ev(group="g3", verdict="AsyncRAT", strength="strong"),
            ev(group="g2", verdict="XWorm", strength="weak"),
        ])
        self.assertEqual(result["lbl_sts"], "verified")

    def test_rule6_strict_weak_contradiction(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong"),
            ev(group="g3", verdict="AsyncRAT", strength="strong"),
            ev(group="g2", verdict="XWorm", strength="weak"),
        ], contradiction_min_strength="weak")
        self.assertEqual(result["lbl_sts"], "review")

    def test_rule5_verified_other(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="XWorm", strength="strong"),
            ev(group="g2", verdict="XWorm", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "verified_other")
        self.assertEqual(result["sug_fam"], "XWorm")

    def test_rule5_mixed_other_and_asyncrat_is_review(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="XWorm", strength="strong"),
            ev(group="g2", verdict="XWorm", strength="strong"),
            ev(group="g3", verdict="AsyncRAT", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "review")

    def test_lineage_asyncrat_counts_for_verified(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong", scope="lineage"),
            ev(group="g2", verdict="AsyncRAT", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "verified")

    def test_lineage_asyncrat_does_not_block_verified_other(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong", scope="lineage"),
            ev(group="g2", verdict="XWorm", strength="strong"),
            ev(group="g3", verdict="XWorm", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "verified_other")
        self.assertEqual(result["sug_fam"], "XWorm")

    def test_lineage_plus_one_fork_is_unverified_fork(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong", scope="lineage"),
            ev(group="g2", verdict="XWorm", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "unverified")
        self.assertEqual(result["sug_fam"], "XWorm")

    def test_lineage_alone_is_unverified_asyncrat(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="AsyncRAT", strength="strong", scope="lineage"),
        ])
        self.assertEqual(result["lbl_sts"], "unverified")
        self.assertEqual(result["sug_fam"], "AsyncRAT")

    def test_review_prefers_family_scoped_family(self):
        result = aggregate(label(), [
            ev(group="own", verdict="AsyncRAT", strength="strong", scope="lineage"),
            ev(group="mb", verdict="AsyncRAT", strength="weak", scope="lineage"),
            ev(group="elastic", verdict="DcRat", strength="strong"),
            ev(group="rat-king", verdict="VenomRAT", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "review")
        self.assertEqual(result["sug_fam"], "DcRat")

    def test_rule8_benign_passthrough(self):
        result = aggregate(label(status="benign", family="Benign"), [ev()])
        self.assertEqual(result["lbl_sts"], "benign")
        self.assertEqual(result["sug_fam"], "Benign")
        self.assertEqual(result["lbl_src"], "hand_benign")

    def test_rule9_reference_passthrough(self):
        result = aggregate(label(status="reference_only", family="AsyncRAT_Reference"), [])
        self.assertEqual(result["lbl_sts"], "reference_only")
        self.assertEqual(result["lbl_src"], "parser_only")

    def test_rule10_gold_is_stub(self):
        # No gold file exists yet; the aggregator must not invent an override.
        fields = label()
        fields["is_gold"] = 1
        fields["gold_fam"] = "AsyncRAT"
        result = aggregate(fields, [])
        self.assertEqual(result["lbl_sts"], "unverified")
        self.assertNotEqual(result["lbl_src"], "human_gold")

    def test_group_with_two_families_is_contradiction(self):
        result = aggregate(label(), [
            ev(source="a", group="g1", verdict="AsyncRAT", strength="strong"),
            ev(source="b", group="g1", verdict="XWorm", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "review")

    def test_lowercase_verdict_is_canonicalised(self):
        result = aggregate(label(), [
            ev(group="g1", verdict="xworm", strength="strong"),
            ev(group="g2", verdict="xworm", strength="strong"),
        ])
        self.assertEqual(result["lbl_sts"], "verified_other")
        self.assertEqual(result["sug_fam"], "XWorm")


class ImporterTests(unittest.TestCase):
    def test_target_class_db_routing(self):
        self.assertEqual(target_class_db({"lbl_sts": "verified", "sug_fam": ""}),
                         "AsyncRAT.db")
        self.assertEqual(target_class_db({"lbl_sts": "verified_other", "sug_fam": "XWorm"}),
                         "OtherMalwares.db")
        self.assertEqual(target_class_db({"lbl_sts": "benign", "sug_fam": "Benign"}),
                         "Benign.db")
        with self.assertRaises(RuntimeError):
            target_class_db({"lbl_sts": "verified_other", "sug_fam": ""})
        with self.assertRaises(RuntimeError):
            target_class_db({"lbl_sts": "verified_other", "sug_fam": "OtherMalware"})

    def test_blank_gold_status_does_not_exclude(self):
        is_gold, gold_fam = gold_flags({"gold_status": "", "gold_family": ""})
        self.assertEqual((is_gold, gold_fam), (0, None))
        label = {"lbl_sts": "verified", "sug_fam": ""}
        self.assertEqual(target_class_for_row(label, is_gold), "AsyncRAT.db")

    def test_filled_gold_status_excludes(self):
        is_gold, gold_fam = gold_flags({
            "gold_status": "verified_other", "gold_family": "XWorm",
        })
        self.assertEqual((is_gold, gold_fam), (1, "XWorm"))
        label = {"lbl_sts": "verified_other", "sug_fam": "XWorm"}
        self.assertIsNone(target_class_for_row(label, is_gold))

    def test_evidence_upsert_is_idempotent(self):
        conn = sqlite3.connect(":memory:")
        try:
            ensure_evidence_table(conn)
            row = {
                "sha256": "a" * 64,
                "source": "rat_king_parser",
                "source_version": "4.2.4",
                "independence_group": "yara:rat-king",
                "verdict": "AsyncRAT",
                "strength": "strong",
                "scope": "lineage",
                "raw": "{}",
                "observed_at": "2026-01-01T00:00:00+00:00",
            }
            upsert_evidence(conn, [row])
            upsert_evidence(conn, [dict(row, strength="medium", verdict="XWorm",
                                      scope="family")])
            count = conn.execute("SELECT COUNT(*) FROM label_evidence").fetchone()[0]
            self.assertEqual(count, 1)
            verdict, strength, scope = conn.execute(
                "SELECT verdict, strength, scope FROM label_evidence"
            ).fetchone()
            self.assertEqual((verdict, strength, scope), ("XWorm", "medium", "family"))
        finally:
            conn.close()

    def test_scope_normalization(self):
        self.assertEqual(persisted_scope({"scope": "lineage"}), "lineage")
        self.assertEqual(persisted_scope({"scope": "family"}), "family")
        self.assertEqual(persisted_scope({"scope": "attribute"}), "family")
        self.assertEqual(persisted_scope(None), "family")

    def test_collect_markers_requires_evidence_and_skips_empty_class(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ("Labels", "Clusters", "Aggregated", "Evidence", "OtherMalwares"):
                (root / name).mkdir()
            (root / "Labels" / ".labeler.done").write_text("done")
            (root / "Clusters" / ".done").write_text("done")
            (root / "Aggregated" / ".aggregator.done").write_text("done")
            with self.assertRaises(RuntimeError):
                collect_markers(root)
            for source in ("rat_king_parser", "own_yara", "elastic", "malpedia",
                           "malwarebazaar", "detect_it_easy", "yaraify"):
                (root / "Evidence" / f".{source}.done").write_text("done")
            collect_markers(root)  # must not raise on the empty OtherMalwares folder

    def test_read_evidence_and_coverage(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sha = "b" * 64
            source_dir = root / sha
            source_dir.mkdir()
            for source in ("rat_king_parser", "own_yara", "elastic", "malpedia",
                           "malwarebazaar", "detect_it_easy", "yaraify"):
                payload = {
                    "schema_version": 1,
                    "sha256": sha,
                    "kind": "evidence",
                    "producer": f"voter:{source}",
                    "fields": ev(source=source, group=f"yara:{source}"),
                }
                (source_dir / f"{source}.json").write_text(json.dumps(payload))
            # read_evidence lives in the aggregator, not the importer.
            from Tools.Aggregator.aggregator import read_evidence as read_agg
            rows = read_agg(root, sha)
            self.assertEqual(len(rows), 7)
            (source_dir / "own_yara.json").unlink()
            with self.assertRaises(RuntimeError):
                from Tools.Importer.importer import read_evidence_rows
                read_evidence_rows(root, {sha})


class FinalLabelTests(unittest.TestCase):
    def _write(self, path, sha, fields):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "schema_version": 1,
            "sha256": sha,
            "kind": "label" if "Labels" in path.parts else "aggregate",
            "producer": "test",
            "fields": fields,
        }))

    def test_aggregate_overrides_label_and_keeps_config(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sha = "c" * 64
            self._write(root / "Labels" / f"{sha}.json", sha, {
                "lbl_sts": "unverified", "sug_fam": "",
                "is_dotnet": True, "config": {"mutex": "x"},
            })
            self._write(root / "Aggregated" / f"{sha}.json", sha, {
                "lbl_sts": "verified_other", "sug_fam": "XWorm",
                "lbl_src": "auto_aggregator", "lbl_reason": {"groups": {}},
            })
            final = load_final_label(sha, data_dir=root)
            self.assertEqual(final["lbl_sts"], "verified_other")
            self.assertEqual(final["sug_fam"], "XWorm")
            self.assertTrue(final["is_dotnet"])
            self.assertEqual(final["config"], {"mutex": "x"})
            self.assertEqual(clusterer.family_of(sha, root / "Labels"), "xworm")

    def test_final_label_falls_back_to_labels(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            sha = "d" * 64
            self._write(root / "Labels" / f"{sha}.json", sha, {
                "lbl_sts": "verified", "sug_fam": "", "is_dotnet": True,
            })
            final = load_final_label(sha, data_dir=root)
            self.assertEqual(final["lbl_sts"], "verified")

    def test_canonical_family(self):
        self.assertEqual(canonical_family("asyncrat"), "AsyncRAT")
        self.assertEqual(canonical_family("XWorm"), "XWorm")
        self.assertEqual(canonical_family(""), "")
        with self.assertRaises(RuntimeError):
            canonical_family("unknown-family")


class GoldAndVoterTests(unittest.TestCase):
    def test_gold_loader_blank_and_filled(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            gold_dir = root / "Gold"
            gold_dir.mkdir()
            (gold_dir / "gold.csv").write_text(
                "sha256,gold_status,gold_family\n"
                f"{'e' * 64},,\n"
                f"{'f' * 64},verified_other,XWorm\n",
                encoding="utf-8",
            )
            gold = load_gold_labels(root)
            self.assertEqual(gold["e" * 64]["gold_status"], "")
            self.assertEqual(gold["f" * 64]["gold_status"], "verified_other")
            self.assertEqual(gold["f" * 64]["gold_family"], "XWorm")

    def test_gold_loader_rejects_duplicate_and_unknown_status(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            gold_dir = root / "Gold"
            gold_dir.mkdir()
            (gold_dir / "gold.csv").write_text(
                "sha256,gold_status,gold_family\n"
                f"{'a' * 64},verified,\n"
                f"{'a' * 64},verified,\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                load_gold_labels(root)
            (gold_dir / "gold.csv").write_text(
                "sha256,gold_status,gold_family\n"
                f"{'b' * 64},not_a_status,\n",
                encoding="utf-8",
            )
            with self.assertRaises(RuntimeError):
                load_gold_labels(root)

    def test_gold_override(self):
        base = aggregate(label(), [ev(group="g1")])
        result = apply_gold_override(base, {
            "gold_status": "verified_other", "gold_family": "XWorm",
        })
        self.assertEqual(result["lbl_sts"], "verified_other")
        self.assertEqual(result["sug_fam"], "XWorm")
        self.assertEqual(result["lbl_src"], "human_gold")
        self.assertIn("gold_override", result["lbl_reason"])

    def test_malwarebazaar_aliases(self):
        self.assertEqual(families_from_tokens(["AsyncRAT"]), ["AsyncRAT"])
        self.assertEqual(families_from_tokens(["Quasar"]), ["QuasarRAT"])
        self.assertEqual(families_from_tokens(["unknown"]), [])

    def test_elastic_rule_name_mapping(self):
        self.assertEqual(
            families_for_rules(["Windows_Trojan_Asyncrat_11a11ba1"]),
            ["AsyncRAT"],
        )
        self.assertEqual(
            families_for_rules(["Windows_Trojan_XWorm_732e6c12"]),
            ["XWorm"],
        )

    def test_yaraify_rule_name_mapping(self):
        self.assertEqual(families_for_names(["MALWARE_Win_AsyncRAT"]), ["AsyncRAT"])
        self.assertEqual(families_for_names(["generic_rule"]), [])


if __name__ == "__main__":
    unittest.main()

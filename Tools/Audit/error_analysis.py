#!/usr/bin/env python3
"""Diagnostic error analysis for the frozen fixup run.

DIAGNOSTIC ONLY — no labels, thresholds or clusters are changed.
"""

from __future__ import annotations

import datetime
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import tlsh

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools.Models import baseline, fixup_eval  # noqa: E402

DATA = ROOT / "Data"
FEATURES = DATA / "Features"
HEADER = "DIAGNOSTIC ONLY — error analysis; not a result"


def db_rows() -> dict:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    try:
        rows = {row[0]: {"status": row[1], "sug_fam": row[2],
                         "cluster": row[3], "obf": str(row[4] or ""),
                         "source": row[5], "kind": row[6],
                         "size": row[7]}
                for row in conn.execute(
                    "SELECT sha256, lbl_sts, sug_fam, cluster_id, obf_lvl, "
                    "source, kind, structure_file_size FROM dataset")}
    finally:
        conn.close()
    return rows


def evidence(sha: str) -> dict:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    try:
        return {row[0]: row[1] for row in conn.execute(
            "SELECT source, verdict FROM label_evidence WHERE sha256=?",
            (sha,))}
    finally:
        conn.close()


def nearest(sha: str, train_shas: list[str], hashes: dict):
    target = hashes.get(sha)
    best_sha, best_distance = "", None
    if not target:
        return best_sha, best_distance
    for candidate_sha in train_shas:
        candidate = hashes.get(candidate_sha)
        if not candidate:
            continue
        try:
            distance = tlsh.diff(target, candidate)
        except Exception:
            continue
        if best_distance is None or distance < best_distance:
            best_sha, best_distance = candidate_sha, distance
    return best_sha, best_distance


def top_features(model, X, row_index: int, names: list[str], count: int = 5):
    contributions = model.predict(X[row_index:row_index + 1],
                                  pred_contrib=True)
    if hasattr(contributions, "toarray"):
        contributions = contributions.toarray()
    values = contributions[0][:-1]
    order = np.argsort(-np.abs(values))[:count]
    return [{"feature": names[index], "contribution": float(values[index])}
            for index in order if abs(values[index]) > 0]


def main() -> int:
    result_json = json.loads((FEATURES / "fixup_results.json").read_text())
    all_data = fixup_eval.load_all()
    full = all_data["full"]
    train, test = full["train"], full["test"]
    rows = db_rows()
    families = fixup_eval.family_map()
    hashes = baseline.tlsh_map(DATA)
    train_shas = [str(sha) for sha in train["sha256"]]
    feature_names = json.loads(
        (FEATURES / "feature_names.json").read_text())["feature_names"]
    vocab = train["vocab_size"]
    names = feature_names[:vocab]

    model = fixup_eval.make_model()
    X_train = fixup_eval.matrix_from_data(train, "capability")
    X_test = fixup_eval.matrix_from_data(test, "capability")
    model.fit(X_train, train["y"])
    test_scores = model.predict_proba(X_test)[:, 1]
    thr95 = result_json["test"]["thresholds_recall95"]["f_capability_uncapped"]
    thr_f1 = result_json["test"]["thresholds"]["f_capability_uncapped"]
    pred95 = fixup_eval.apply_threshold(test_scores, thr95)
    pred_f1 = fixup_eval.apply_threshold(test_scores, thr_f1)

    def error_entry(index: int, score: float, pred: int) -> dict:
        sha = str(test["sha256"][index])
        meta = rows.get(sha, {})
        neighbour, distance = nearest(sha, train_shas, hashes)
        return {
            "sha256": sha,
            "cluster": str(test["groups"][index]),
            "true": "positive" if int(test["y"][index]) == 1 else "benign",
            "family": families.get(sha, "Benign") if int(test["y"][index]) else "Benign",
            "score": float(score),
            "predicted": int(pred),
            "obfuscated": meta.get("obf", "").startswith("obfuscated"),
            "nearest_train_sha": neighbour,
            "nearest_distance": distance,
            "top_features": top_features(model, X_test, index, names),
            "evidence": evidence(sha),
        }

    errors95 = {"false_positive": [], "false_negative": []}
    errors_f1 = {"false_positive": [], "false_negative": []}
    for index, (label, pred, pred_opt, score) in enumerate(
            zip(test["y"], pred95, pred_f1, test_scores)):
        if int(label) == 0 and pred == 1:
            errors95["false_positive"].append(error_entry(index, score, pred))
        if int(label) == 1 and pred == 0:
            errors95["false_negative"].append(error_entry(index, score, pred))
        if int(label) == 0 and pred_opt == 1:
            errors_f1["false_positive"].append(error_entry(index, score, pred_opt))
        if int(label) == 1 and pred_opt == 0:
            errors_f1["false_negative"].append(error_entry(index, score, pred_opt))

    # LOCO misses at the matched 95% threshold.
    loco_misses = []
    for scope in ("loco_verified", "loco_positive"):
        per_fold = result_json[scope]["models"]["f_capability"]["per_fold"]
        for fold, values in per_fold.items():
            if values["recall_95"] is None or values["recall_95"] >= 1:
                continue
            cluster = next(row["positive_cluster"] for row in
                           result_json[scope]["per_fold"]
                           if str(row["fold"]) == str(fold))
            members = [sha for sha, meta in rows.items()
                       if meta["cluster"] == cluster]
            nearest_entries = []
            for sha in members:
                neighbour, distance = nearest(sha, train_shas, hashes)
                nearest_entries.append({
                    "sha256": sha,
                    "obfuscated": rows[sha]["obf"].startswith("obfuscated"),
                    "nearest_train_sha": neighbour,
                    "nearest_distance": distance,
                })
            loco_misses.append({
                "scope": scope,
                "fold": int(fold),
                "cluster": cluster,
                "cluster_size": len(members),
                "recall_95": values["recall_95"],
                "members": nearest_entries,
            })

    # The 2.1d F1-threshold misses (the 3/5 singletons cited in the brief).
    f1_misses = []
    backup_path = DATA / "Audit" / "fixup_results.before_matched.json"
    if backup_path.is_file():
        backup = json.loads(backup_path.read_text())
        for scope in ("loco_verified", "loco_positive"):
            per_fold = backup[scope]["models"]["f_capability"]["per_fold"]
            for fold, values in per_fold.items():
                if values["recall_threshold"] is None or values["recall_threshold"] >= 1:
                    continue
                cluster = next(row["positive_cluster"]
                               for row in backup[scope]["per_fold"]
                               if str(row["fold"]) == str(fold))
                members = [sha for sha, meta in rows.items()
                           if meta["cluster"] == cluster]
                nearest_entries = []
                for sha in members:
                    neighbour, distance = nearest(sha, train_shas, hashes)
                    nearest_entries.append({
                        "sha256": sha,
                        "obfuscated": rows[sha]["obf"].startswith("obfuscated"),
                        "nearest_train_sha": neighbour,
                        "nearest_distance": distance,
                    })
                f1_misses.append({
                    "scope": scope,
                    "fold": int(fold),
                    "cluster": cluster,
                    "cluster_size": len(members),
                    "recall_threshold": values["recall_threshold"],
                    "members": nearest_entries,
                })

    # The old 2.1c positive-only misses (3 verified / 5 positive), for the
    # historical comparison requested in the brief.
    legacy_misses = []
    legacy_path = DATA / "Audit" / "fixup_results.before_methodfix.json"
    if legacy_path.is_file():
        legacy = json.loads(legacy_path.read_text())
        for scope in ("loco_verified", "loco_positive"):
            per_cluster = legacy[scope]["models"]["f_capability"].get(
                "per_cluster_recall", {})
            for cluster, values in per_cluster.items():
                if values.get("recall", 0) >= 1:
                    continue
                members = [sha for sha, meta in rows.items()
                           if meta["cluster"] == cluster]
                nearest_entries = []
                for sha in members:
                    neighbour, distance = nearest(sha, train_shas, hashes)
                    nearest_entries.append({
                        "sha256": sha,
                        "obfuscated": rows[sha]["obf"].startswith("obfuscated"),
                        "nearest_train_sha": neighbour,
                        "nearest_distance": distance,
                    })
                legacy_misses.append({
                    "scope": scope,
                    "cluster": cluster,
                    "cluster_size": len(members),
                    "recall": values.get("recall"),
                    "members": nearest_entries,
                })

    # Stage 2 confusion rows.
    table = fixup_eval.stage2_eligibility()
    eligible = sorted(name for name, item in table.items() if item["eligible"])
    labels = {name: index for index, name in enumerate(eligible)}
    test_mask = np.asarray([families.get(str(sha)) in eligible
                            for sha in test["sha256"]])
    train_mask = np.asarray([families.get(str(sha)) in eligible
                             for sha in train["sha256"]])
    y_train = np.asarray([labels[families[str(sha)]]
                          for sha in train["sha256"][train_mask]])
    y_test = np.asarray([labels[families[str(sha)]]
                         for sha in test["sha256"][test_mask]])
    stage_model = fixup_eval.make_model()
    stage_model.fit(
        train["X"][train_mask][:, :train["vocab_size"]].astype(np.float32),
        y_train)
    stage_pred = stage_model.predict(
        test["X"][test_mask][:, :test["vocab_size"]].astype(np.float32))
    stage_shas = np.asarray(test["sha256"])[test_mask]
    stage_clusters = np.asarray(test["groups"])[test_mask]
    stage_errors = []
    async_anchor = "053fa0de75620861379f9dde8be711f1760f21e09701629d27cf6c3ce0d054e3"
    for sha, cluster, truth, pred in zip(stage_shas, stage_clusters,
                                         y_test, stage_pred):
        if int(truth) == int(pred):
            continue
        neighbour, distance = nearest(str(sha), [async_anchor], hashes)
        stage_errors.append({
            "sha256": str(sha),
            "cluster": str(cluster),
            "true_family": eligible[int(truth)],
            "predicted_family": eligible[int(pred)],
            "nearest_asyncrat_sha": neighbour,
            "nearest_asyncrat_distance": distance,
            "is_00fe40a8": str(cluster).startswith("00fe40a8"),
        })

    # Holdout false positives at the matched capability threshold.
    holdout_matrix = fixup_eval.holdout_features(
        "capability", all_data["policy"]["names"])
    holdout_model = fixup_eval.make_model()
    holdout_model.fit(X_train, train["y"])
    holdout_scores = holdout_model.predict_proba(holdout_matrix)[:, 1]
    holdout_pred = fixup_eval.apply_threshold(holdout_scores, thr95)
    holdout_shas = baseline.holdout_shas(DATA)
    holdout_fp = []
    for sha, score, pred in zip(holdout_shas, holdout_scores, holdout_pred):
        if pred != 1:
            continue
        meta = rows.get(str(sha), {})
        holdout_fp.append({
            "sha256": str(sha),
            "size": meta.get("size"),
            "score": float(score),
            "source": meta.get("source", ""),
            "kind": meta.get("kind", ""),
        })

    # Obfuscated test positives.
    obf_test = []
    for sha, label, score, pred in zip(test["sha256"], test["y"],
                                       test_scores, pred95):
        meta = rows.get(str(sha), {})
        if int(label) != 1 or not meta.get("obf", "").startswith("obfuscated"):
            continue
        obf_test.append({
            "sha256": str(sha),
            "caught_at_95": bool(pred == 1),
            "score": float(score),
        })

    result = {
        "header": HEADER,
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "run_id": result_json.get("run_id"),
        "thresholds": {
            "capability_recall95": float(thr95),
            "capability_f1_optimal": float(thr_f1),
        },
        "test_errors_recall95": errors95,
        "test_errors_f1_optimal": errors_f1,
        "loco_missed_clusters_2_1c_positive_only": legacy_misses,
        "loco_missed_clusters_f1_optimal": f1_misses,
        "loco_missed_clusters_matched95": loco_misses,
        "stage2_errors": stage_errors,
        "holdout_false_positives_95": holdout_fp,
        "obfuscated_test_positives": obf_test,
        "counts": {
            "test_fp_95": len(errors95["false_positive"]),
            "test_fn_95": len(errors95["false_negative"]),
            "test_fp_f1": len(errors_f1["false_positive"]),
            "test_fn_f1": len(errors_f1["false_negative"]),
            "loco_missed_2_1c": len(legacy_misses),
            "loco_missed_f1_optimal": len(f1_misses),
            "loco_missed_matched95": len(loco_misses),
            "stage2_errors": len(stage_errors),
            "holdout_fp_95": len(holdout_fp),
            "obfuscated_positive": len(obf_test),
            "obfuscated_caught_95": sum(1 for row in obf_test
                                        if row["caught_at_95"]),
        },
    }
    out = DATA / "Audit" / "error_analysis.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result["counts"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

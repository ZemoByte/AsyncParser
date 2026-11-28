#!/usr/bin/env python3
"""Phase 4 diagnostics: LOCO, abstention, explainability, CLR baseline, Stage 2.

All outputs are DIAGNOSTIC ONLY: the dataset gate fails and the split is
degenerate. No model is tuned on test; LOCO trains on whole clusters.
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import tlsh  # noqa: E402

from Tools.Models.baseline import (  # noqa: E402
    bootstrap_ci, evaluate_holdout, load_split, tlsh_map,
)
from Tools.Features.build_matrix import STRUCTURAL_FEATURES  # noqa: E402
from Tools._label_common import load_final_label  # noqa: E402

DATA = ROOT / "Data"
FEATURES = DATA / "Features"
SAMPLES = ROOT / "Samples"
THRESHOLD = 100


def load_all():
    train = load_split(FEATURES / "train.npz")
    val = load_split(FEATURES / "val.npz")
    test = load_split(FEATURES / "test.npz")
    from scipy.sparse import vstack
    return {
        "X": vstack([train["X"], val["X"], test["X"]], format="csr"),
        "X_struct": np.vstack([train["X_struct"], val["X_struct"],
                               test["X_struct"]]),
        "y": np.concatenate([train["y"], val["y"], test["y"]]),
        "groups": np.concatenate([train["groups"], val["groups"],
                                  test["groups"]]),
        "sha256": np.concatenate([train["sha256"], val["sha256"],
                                  test["sha256"]]),
        "vocab_size": train["vocab_size"],
        "train_sha": train["sha256"],
    }


def positive_clusters(data: dict) -> list[str]:
    return sorted({group for group, label in zip(data["groups"], data["y"])
                   if int(label) == 1})


def loco_folds(data: dict, positive_only: bool = False) -> list[tuple[str, np.ndarray, np.ndarray]]:
    clusters = (positive_clusters(data) if positive_only
                else sorted(set(data["groups"])))
    folds = []
    for cluster in clusters:
        mask = data["groups"] == cluster
        if not mask.any():
            continue
        folds.append((cluster, np.where(~mask)[0], np.where(mask)[0]))
    return folds


def choose_threshold(values: list[float]) -> int:
    return max(1, int(np.percentile(values, 5))) if values else 1


def template_sentence(references: list[str], nearest_sha: str,
                      nearest_distance: int | None) -> str:
    return (f"references {', '.join(references) or 'no nonzero features'}; "
            f"nearest TLSH sample {nearest_sha[:12] or 'none'} "
            f"(distance {nearest_distance if nearest_distance is not None else 'n/a'})")


def _metrics(y, pred, score) -> dict:
    return {"rows": int(len(y)), "positives": int(np.sum(y)),
            "precision": float(precision_score(y, pred, zero_division=0)),
            "recall": float(recall_score(y, pred, zero_division=0)),
            "f1": float(f1_score(y, pred, zero_division=0)),
            "pr_auc": float(average_precision_score(y, score)) if len(set(y)) == 2 else None,
            "confusion_matrix": confusion_matrix(y, pred, labels=[0, 1]).tolist()}


def make_model(seed=42):
    try:
        import lightgbm as lgb
        return lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05,
                                  num_leaves=31, random_state=seed, n_jobs=4,
                                  verbosity=-1)
    except Exception:
        from sklearn.ensemble import HistGradientBoostingClassifier
        return HistGradientBoostingClassifier(random_state=seed)


def knn_predict(train_idx, test_idx, data, hashes):
    pred, score = [], []
    train_sha = data["sha256"][train_idx]
    train_y = data["y"][train_idx]
    majority = int(Counter(train_y).most_common(1)[0][0])
    for index in test_idx:
        target = hashes.get(str(data["sha256"][index]))
        best_distance, best_label = None, None
        if target:
            for sha, label in zip(train_sha, train_y):
                candidate = hashes.get(str(sha))
                if not candidate:
                    continue
                try:
                    distance = tlsh.diff(target, candidate)
                except Exception:
                    continue
                if best_distance is None or distance < best_distance:
                    best_distance, best_label = distance, int(label)
        pred.append(best_label if best_label is not None else majority)
        score.append(1.0 / (1.0 + best_distance) if best_distance is not None else 0.0)
    return np.asarray(pred), np.asarray(score)


def run_loco(data: dict) -> dict:
    folds = loco_folds(data, positive_only=False)
    hashes = tlsh_map(DATA)
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    obf = {row[0]: ("obfuscated" if str(row[1]).startswith("obfuscated")
                    else "plain")
           for row in conn.execute("SELECT sha256, obf_lvl FROM dataset")}
    conn.close()
    predictions = {name: [] for name in ("full", "capability", "structural", "tlsh_knn")}
    scores = {name: [] for name in predictions}
    truths, groups, per_cluster, obf_labels = [], [], {}, []
    for cluster, train_idx, test_idx in folds:
        y_test = data["y"][test_idx]
        truths.extend(y_test.tolist())
        groups.extend([cluster] * len(test_idx))
        obf_labels.extend(obf.get(str(data["sha256"][index]), "plain")
                          for index in test_idx)
        for name, X in (("full", data["X"]),
                        ("capability", data["X"][:, :data["vocab_size"]]),
                        ("structural", csr_matrix(data["X_struct"]))):
            model = make_model()
            model.fit(X[train_idx], data["y"][train_idx])
            pred = model.predict(X[test_idx])
            score = model.predict_proba(X[test_idx])[:, 1]
            predictions[name].extend(pred.tolist())
            scores[name].extend(score.tolist())
        pred, score = knn_predict(train_idx, test_idx, data, hashes)
        predictions["tlsh_knn"].extend(pred.tolist())
        scores["tlsh_knn"].extend(score.tolist())
        if np.sum(y_test):
            per_cluster[cluster] = {
                "rows": int(len(test_idx)),
                "positives": int(np.sum(y_test)),
                "recall": float(np.mean(
                    np.asarray(predictions["full"])[-len(test_idx):] == 1)),
            }
    y = np.asarray(truths)
    group_array = np.asarray(groups)
    result = {}
    for name in predictions:
        metrics = _metrics(y, np.asarray(predictions[name]), np.asarray(scores[name]))
        metrics["ci"] = bootstrap_ci(y, np.asarray(predictions[name]),
                                     np.asarray(scores[name]), group_array)
        strata = {}
        for stratum in ("plain", "obfuscated"):
            mask = np.asarray(obf_labels) == stratum
            if mask.any():
                strata[stratum] = _metrics(
                    y[mask], np.asarray(predictions[name])[mask],
                    np.asarray(scores[name])[mask])
        metrics["obfuscation"] = strata
        result[name] = metrics
    return {"folds": len(folds),
            "positive_folds": len({group for group, label
                                   in zip(data["groups"], data["y"])
                                   if int(label) == 1}),
            "per_cluster": per_cluster, "models": result}


def abstention(data: dict, calibrate: bool = False) -> dict:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    rows = list(conn.execute("SELECT sha256, lbl_sts FROM dataset"))
    conn.close()
    counts = {}
    for sha, _status in rows:
        total = 0
        for kind in ("TypeRef", "MemberRef"):
            for cls in ("AsyncRAT", "OtherMalwares", "Benign"):
                path = DATA / cls / kind / f"{sha}.json"
                if path.is_file():
                    total += len(json.loads(path.read_text())["fields"]["values"])
        counts[sha] = total
    train_positive = [counts[str(sha)] for sha, y in
                      zip(data["train_sha"], data["y"][:len(data["train_sha"])])
                      if int(y) == 1]
    threshold = choose_threshold(train_positive)
    per_class = defaultdict(lambda: [0, 0])
    for sha, status in rows:
        per_class[status][0] += 1
        if counts.get(sha, 0) < threshold:
            per_class[status][1] += 1
    rates = {label: {"rows": total,
                     "abstained": skipped,
                     "rate": skipped / total if total else 0.0}
             for label, (total, skipped) in sorted(per_class.items())}
    return {"threshold": threshold,
            "train_positive_counts": train_positive,
            "rates": rates,
            "note": "threshold is the 5th percentile of combined TypeRef+MemberRef "
                    "counts on training positives"}


def explainability(data: dict, top: int = 5) -> dict:
    model = make_model()
    model.fit(data["X"], data["y"])
    names = json.loads((FEATURES / "feature_names.json").read_text())
    feature_names = names["feature_names"]
    booster = getattr(model, "booster_", None)
    if booster is not None:
        gains = booster.feature_importance(importance_type="gain")
        importance = sorted(
            ({"feature": feature_names[i], "gain": float(gain)}
             for i, gain in enumerate(gains)),
            key=lambda item: -item["gain"])[:20]
        candidates = [index for index in range(len(data["y"]))
                      if int(data["y"][index]) == 1
                      and data["X"][index].getnnz() > 0][:top]
        if not candidates:
            candidates = list(range(min(top, len(data["y"]))))
        contributions = model.predict(data["X"][candidates], pred_contrib=True)
        if hasattr(contributions, "toarray"):
            contributions = contributions.toarray()
    else:
        importance = []
        contributions = np.zeros((top, len(feature_names) + 1))
    hashes = tlsh_map(DATA)
    train_sha = [str(sha) for sha in data["sha256"][:len(data["train_sha"])]]
    examples = []
    for position, index in enumerate(candidates):
        sha = str(data["sha256"][index])
        row = contributions[position][:-1]
        top_features = sorted(
            ({"feature": feature_names[i], "contribution": float(value)}
             for i, value in enumerate(row)),
            key=lambda item: -abs(item["contribution"]))[:10]
        target = hashes.get(sha)
        nearest_sha, nearest_distance = "", None
        if target:
            for candidate_sha in train_sha:
                if candidate_sha == sha:
                    continue
                candidate = hashes.get(candidate_sha)
                if not candidate:
                    continue
                try:
                    distance = tlsh.diff(target, candidate)
                except Exception:
                    continue
                if nearest_distance is None or distance < nearest_distance:
                    nearest_distance, nearest_sha = distance, candidate_sha
        references = [item["feature"] for item in top_features[:2]
                      if abs(item["contribution"]) > 0]
        template = template_sentence(references, nearest_sha, nearest_distance)
        examples.append({"sha256": sha, "top_features": top_features,
                         "nearest_train_sha": nearest_sha,
                         "nearest_distance": nearest_distance,
                         "template": template})
    return {"shap": booster is not None,
            "importance": importance, "examples": examples}


def stage2_decision(votes: list[str], nearest_family: str,
                    distance: int | None, threshold: int = 100) -> str:
    families = Counter(votes)
    confident = [family for family, count in families.items() if count >= 2]
    if len(confident) == 1:
        family = confident[0]
        support = families[family]
        if family in {"QuasarRAT", "DcRat"}:
            # Tiny families need explicit confidence (3+ voters and a close
            # nearest known sample); otherwise abstain.
            if (support >= 3 and nearest_family == family
                    and distance is not None and distance <= threshold):
                return family
            return "abstain"
        if nearest_family == family and distance is not None and distance <= threshold:
            return family
        if family in {"XWorm", "VenomRAT"} and nearest_family in {"", family}:
            return family
    if nearest_family in {"XWorm", "VenomRAT"} and len(confident) <= 1:
        return nearest_family
    return "abstain"


def stage2(data: dict) -> dict:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    rows = list(conn.execute(
        "SELECT sha256, lbl_sts, sug_fam, cluster_id FROM dataset "
        "WHERE lbl_sts='verified_other'"))
    conn.close()
    hashes = tlsh_map(DATA)
    train_sha = data["sha256"][:len(data["train_sha"])]
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    family_by_sha = {row[0]: ("AsyncRAT" if row[1] == "verified"
                              else (row[2] or "unknown"))
                     for row in conn.execute(
                         "SELECT sha256, lbl_sts, sug_fam FROM dataset "
                         "WHERE lbl_sts IN ('verified','verified_other')")}
    conn.close()
    decisions, truths = [], []
    for sha, status, family, cluster in rows:
        evidence = DATA / "Aggregated" / f"{sha}.json"
        votes = []
        if evidence.is_file():
            fields = json.loads(evidence.read_text())["fields"]
            reason = fields.get("lbl_reason")
            if isinstance(reason, str):
                try:
                    reason = json.loads(reason)
                except json.JSONDecodeError:
                    reason = {}
            for groups in (reason or {}).get("groups", {}):
                if groups != "AsyncRAT":
                    votes.extend([groups] * len(reason["groups"][groups]))
        target = hashes.get(sha)
        nearest_family, nearest_distance = "", None
        if target:
            for candidate_sha in train_sha:
                candidate = hashes.get(str(candidate_sha))
                if not candidate:
                    continue
                try:
                    distance = tlsh.diff(target, candidate)
                except Exception:
                    continue
                if nearest_distance is None or distance < nearest_distance:
                    nearest_distance = distance
                    nearest_family = family_by_sha.get(str(candidate_sha), "unknown")
        decisions.append(stage2_decision(votes, nearest_family, nearest_distance))
        truths.append(family or "unknown")
    matrix = {}
    for truth, decision in zip(truths, decisions):
        matrix.setdefault(truth, Counter())[decision] += 1
    return {"rows": len(rows),
            "abstained": sum(1 for d in decisions if d == "abstain"),
            "confusion": {k: dict(v) for k, v in matrix.items()},
            "note": "rules/kNN only; no trained family model"}


def clr_features(path: Path) -> dict | None:
    try:
        import dnfile
        pe = dnfile.dnPE(str(path))
    except Exception:
        return None
    if pe.net is None or pe.net.mdtables is None:
        return None
    md = pe.net.mdtables
    def count(name):
        table = getattr(md, name, None)
        return len(table) if table else 0
    streams = getattr(pe.net.metadata, "streams", {}) if pe.net.metadata else {}
    return {
        "has_resources": int(bool(count("ManifestResource"))),
        "has_moduleref": int(bool(count("ModuleRef"))),
        "has_implmap": int(bool(count("ImplMap"))),
        "has_typeref": int(bool(count("TypeRef"))),
        "has_methoddef": int(bool(count("MethodDef"))),
        "has_memberref": int(bool(count("MemberRef"))),
        "has_event": int(bool(count("Event"))),
        "has_manifestresource": int(bool(count("ManifestResource"))),
        "module_rows": count("Module"),
        "assembly_rows": count("Assembly"),
        "typeref_rows": count("TypeRef"),
        "methoddef_rows": count("MethodDef"),
        "memberref_rows": count("MemberRef"),
        "streams": len(streams) if streams else 0,
        "table_presence": sum(1 for name in ("TypeRef", "MemberRef",
                                             "AssemblyRef", "ImplMap",
                                             "ModuleRef", "ManifestResource")
                              if count(name) > 0),
    }


def clr_baseline(data: dict) -> dict:
    paths = {}
    for sha in data["sha256"]:
        for cls in ("AsyncRAT", "OtherMalwares", "Benign"):
            candidate = SAMPLES / cls / f"{sha}.exe"
            if candidate.is_file():
                paths[str(sha)] = candidate
                break
    rows = []
    for sha in data["sha256"]:
        features = clr_features(paths.get(str(sha), Path("/nonexistent")))
        rows.append(features or {})
    keys = sorted({key for row in rows for key in row})
    X = np.asarray([[row.get(key, 0) for key in keys] for row in rows], dtype=float)
    folds = loco_folds(data, positive_only=False)
    preds, scores, truths, groups = [], [], [], []
    for cluster, train_idx, test_idx in folds:
        model = LogisticRegression(max_iter=2000)
        model.fit(X[train_idx], data["y"][train_idx])
        preds.extend(model.predict(X[test_idx]).tolist())
        scores.extend(model.predict_proba(X[test_idx])[:, 1].tolist())
        truths.extend(data["y"][test_idx].tolist())
        groups.extend([cluster] * len(test_idx))
    metrics = _metrics(np.asarray(truths), np.asarray(preds), np.asarray(scores))
    metrics["ci"] = bootstrap_ci(np.asarray(truths), np.asarray(preds),
                                 np.asarray(scores), np.asarray(groups))
    return {"features": keys, "metrics": metrics}


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 4 diagnostics")
    parser.add_argument("--calibrate", action="store_true")
    parser.add_argument("--loco-all", action="store_true")
    args = parser.parse_args()
    data = load_all()
    loco = run_loco(data)
    abst = abstention(data, args.calibrate)
    explain = explainability(data)
    stage = stage2(data)
    clr = clr_baseline(data)
    model = make_model()
    model.fit(data["X"], data["y"])
    vocab = json.loads((FEATURES / "feature_names.json").read_text())
    holdout = evaluate_holdout(model, DATA, vocab["feature_names"][:vocab["vocab_size"]])
    result = {"header": "DIAGNOSTIC ONLY — dataset gate failed",
              "loco": loco, "abstention": abst, "explainability": explain,
              "stage2": stage, "clr_header": clr, "holdout": holdout}
    (FEATURES / "phase4_results.json").write_text(
        json.dumps(result, indent=2), encoding="utf-8")
    (FEATURES / "abstention.json").write_text(
        json.dumps(abst, indent=2), encoding="utf-8")
    if args.calibrate:
        print(json.dumps(abst["rates"], indent=2))
        print("threshold", abst["threshold"])
    print("loco", {name: {k: round(v, 3) for k, v in metrics.items()
                           if k in ("precision", "recall", "f1", "pr_auc") and v is not None}
                   for name, metrics in loco["models"].items()})
    print("abstention", abst["threshold"], abst["rates"])
    print("stage2", stage)
    print("holdout", holdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

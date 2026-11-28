#!/usr/bin/env python3
"""Stage 1 baselines with cluster-level bootstrap confidence intervals."""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import tlsh
from scipy.sparse import csr_matrix, hstack
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score, confusion_matrix, f1_score,
    precision_recall_fscore_support, precision_score, recall_score,
    roc_auc_score,
)

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except Exception:  # pragma: no cover - fallback documented
    HAS_LIGHTGBM = False

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_FEATURES = ROOT / "Data" / "Features"
DEFAULT_DATA = ROOT / "Data"
SEED = 42

from Tools._label_common import lineage_only_verified, load_final_label  # noqa: E402
from Tools._gate import evaluate_gate  # noqa: E402
from Tools.Features.build_matrix import (  # noqa: E402
    STRUCTURAL_FEATURES,
    load_carved,
    load_structure,
)


def load_split(path: Path) -> dict:
    data = np.load(path, allow_pickle=False)
    X = csr_matrix(
        (data["X_data"], data["X_indices"], data["X_indptr"]),
        shape=tuple(int(x) for x in data["X_shape"]),
    )
    return {
        "X": X,
        "X_struct": data["X_struct"],
        "y": data["y"].astype(int),
        "groups": np.asarray([str(x) for x in data["groups"]]),
        "sha256": np.asarray([str(x) for x in data["sha256"]]),
        "vocab_size": int(data["vocab_size"][0]),
    }


def metrics(y_true, y_pred, y_score) -> dict:
    labels = [0, 1]
    result = {
        "rows": int(len(y_true)),
        "positives": int(np.sum(y_true)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
    }
    if len(set(y_true)) == 2:
        result["pr_auc"] = float(average_precision_score(y_true, y_score))
    else:
        result["pr_auc"] = None
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    result["per_class"] = {
        str(label): {"precision": float(precision[index]),
                     "recall": float(recall[index]),
                     "f1": float(f1[index]),
                     "support": int(support[index])}
        for index, label in enumerate(labels)
    }
    return result


def bootstrap_ci(y_true, y_pred, y_score, groups, iterations=200, seed=SEED) -> dict:
    rng = np.random.default_rng(seed)
    unique = sorted(set(groups))
    if not unique:
        return {}
    positions = {group: np.where(groups == group)[0] for group in unique}
    collected = {"precision": [], "recall": [], "f1": [], "pr_auc": [],
                 "roc_auc": []}
    for _ in range(iterations):
        chosen = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([positions[group] for group in chosen])
        yt, yp, ys = y_true[indices], y_pred[indices], y_score[indices]
        collected["precision"].append(precision_score(yt, yp, zero_division=0))
        collected["recall"].append(recall_score(yt, yp, zero_division=0))
        collected["f1"].append(f1_score(yt, yp, zero_division=0))
        if len(set(yt)) == 2:
            collected["pr_auc"].append(average_precision_score(yt, ys))
            collected["roc_auc"].append(roc_auc_score(yt, ys))
    return {
        key: [float(np.mean(values)), float(np.percentile(values, 2.5)),
              float(np.percentile(values, 97.5))]
        for key, values in collected.items() if values
    }


def distance_score(distance: float | None) -> float:
    """Higher score for closer TLSH neighbours; no neighbour -> 0."""
    if distance is None:
        return 0.0
    return 1.0 / (1.0 + float(distance))


def tlsh_predict(train: dict, test: dict) -> tuple[np.ndarray, np.ndarray]:
    hashes = {}
    for path in (ROOT / "Data" / "Clusters").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        hashes[payload["sha256"]] = payload["fields"].get("tlsh")
    majority = int(Counter(train["y"]).most_common(1)[0][0])
    predictions = []
    scores = []
    for sha in test["sha256"]:
        target = hashes.get(sha)
        best = None
        best_distance = None
        if target:
            for train_sha, train_y in zip(train["sha256"], train["y"]):
                candidate = hashes.get(train_sha)
                if not candidate:
                    continue
                try:
                    distance = tlsh.diff(target, candidate)
                except Exception:
                    continue
                if best_distance is None or distance < best_distance:
                    best_distance = distance
                    best = int(train_y)
        predictions.append(best if best is not None else majority)
        scores.append(distance_score(best_distance))
    return np.asarray(predictions), np.asarray(scores)


def gate_status(data_root: Path) -> bool:
    return bool(evaluate_gate(data_root)["overall"])


def run_model(name: str, model, train: dict, test: dict) -> dict:
    model.fit(train["X"], train["y"])
    predictions = model.predict(test["X"])
    if hasattr(model, "predict_proba"):
        scores = model.predict_proba(test["X"])[:, 1]
    else:
        scores = predictions.astype(float)
    result = metrics(test["y"], predictions, scores)
    result["ci"] = bootstrap_ci(test["y"], predictions, scores, test["groups"])
    return {"name": name, "metrics": result}


def run_loco(train: dict) -> dict:
    """Leave-one-cluster-out diagnostic, only for very small train sets."""
    truths, predictions, scores = [], [], []
    for cluster in sorted(set(train["groups"])):
        mask = train["groups"] == cluster
        if len(set(train["y"][~mask])) < 2:
            continue
        if HAS_LIGHTGBM:
            model = lgb.LGBMClassifier(
                n_estimators=100, learning_rate=0.05, num_leaves=15,
                random_state=SEED, n_jobs=4, verbosity=-1,
            )
        else:
            model = HistGradientBoostingClassifier(random_state=SEED)
        model.fit(train["X"][~mask], train["y"][~mask])
        predictions.extend(model.predict(train["X"][mask]).tolist())
        scores.extend(model.predict_proba(train["X"][mask])[:, 1].tolist())
        truths.extend(train["y"][mask].tolist())
    if not truths:
        return {"triggered": True, "rows": 0}
    result = metrics(np.asarray(truths), np.asarray(predictions),
                     np.asarray(scores))
    result["triggered"] = True
    return result


def holdout_shas(data_root: Path) -> list[str]:
    conn = sqlite3.connect(f"file:{data_root / 'DataSet.db'}?mode=ro", uri=True)
    try:
        shas = [row[0] for row in conn.execute(
            "SELECT sha256 FROM dataset WHERE lbl_sts = 'benign'"
        )]
    finally:
        conn.close()
    return [sha for sha in shas
            if str(load_final_label(sha, data_root).get("source")) == "clrheader2023"]


def evaluate_holdout(model, data_root: Path, vocab: list[str]) -> dict:
    shas = holdout_shas(data_root)
    if not shas:
        return {"rows": 0, "predicted_positive": 0, "fpr": None}
    carved, _ = load_carved(data_root)
    structure = load_structure(data_root)
    vocab_index = {item: index for index, item in enumerate(vocab)}
    rows, cols = [], []
    dense = []
    for row_index, sha in enumerate(shas):
        for values in carved.get(sha, {}).values():
            for item in values:
                column = vocab_index.get(item)
                if column is not None:
                    rows.append(row_index)
                    cols.append(column)
        fields = structure.get(sha)
        if fields is None:
            raise RuntimeError(f"missing structure JSON for holdout sample {sha}")
        dense.append([
            float(fields.get(name.replace("structure_", "", 1), 0.0) or 0.0)
            for name in STRUCTURAL_FEATURES
        ])
    presence = csr_matrix(
        (np.ones(len(rows), dtype=np.int8), (rows, cols)),
        shape=(len(shas), len(vocab)),
    )
    X = hstack([presence, csr_matrix(np.asarray(dense, dtype=np.float32))],
               format="csr")
    predictions = model.predict(X)
    positive = int(np.sum(predictions == 1))
    return {"model": "lightgbm_full", "rows": len(shas),
            "predicted_positive": positive,
            "fpr": positive / len(shas) if shas else None}


def tlsh_map(data_root: Path) -> dict[str, str]:
    hashes: dict[str, str] = {}
    for path in (data_root / "Clusters").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        value = payload.get("fields", {}).get("tlsh")
        if value:
            hashes[payload["sha256"]] = value
    return hashes


def cluster_diagnostics(train: dict, test: dict, predictions,
                        data_root: Path) -> list[dict]:
    """Per test cluster: recall and nearest train cluster by TLSH."""
    hashes = tlsh_map(data_root)
    train_hashes = [(sha, int(label), str(group)) for sha, label, group
                    in zip(train["sha256"], train["y"], train["groups"])
                    if int(label) == 1]
    by_cluster: dict[str, list[int]] = {}
    for index, (label, group) in enumerate(zip(test["y"], test["groups"])):
        by_cluster.setdefault(str(group), []).append(index)
    diagnostics = []
    for cluster, indices in sorted(by_cluster.items()):
        labels = {int(test["y"][index]) for index in indices}
        recall = float(np.mean([predictions[index] == 1 for index in indices]))
        best_distance = None
        best_cluster = ""
        for index in indices:
            target = hashes.get(str(test["sha256"][index]))
            if not target:
                continue
            for sha, _label, train_cluster in train_hashes:
                candidate = hashes.get(sha)
                if not candidate:
                    continue
                try:
                    distance = tlsh.diff(target, candidate)
                except Exception:
                    continue
                if best_distance is None or distance < best_distance:
                    best_distance = distance
                    best_cluster = train_cluster
        diagnostics.append({
            "cluster_id": cluster,
            "rows": len(indices),
            "labels": sorted(labels),
            "recall": recall if 1 in labels else None,
            "nearest_train_cluster": best_cluster,
            "nearest_train_tlsh_distance": best_distance,
            "leakage": best_distance is not None and best_distance <= 100,
        })
    return diagnostics


def validity_report(train: dict, test: dict, results: list[dict],
                    loco: dict, data_root: Path) -> dict:
    test_positives = int(np.sum(test["y"] == 1))
    test_clusters = {str(group) for group, label
                     in zip(test["groups"], test["y"]) if int(label) == 1}
    f1 = {item["name"]: item["metrics"]["f1"] for item in results}
    full_f1 = f1.get("lightgbm_full", f1.get("hist_gradient_fallback"))
    structural_f1 = f1.get("lightgbm_structural_only")
    structural_confound = (full_f1 is not None and structural_f1 is not None
                           and structural_f1 >= full_f1 - 0.02)
    marker = data_root / "Splits" / ".done"
    split_degenerate = False
    if marker.is_file():
        split_degenerate = bool(json.loads(
            marker.read_text(encoding="utf-8")).get("degenerate"))
    positive_clusters = len({
        group for group, label in zip(train["groups"], train["y"]) if label == 1
    })
    loco_inspect = bool(loco.get("triggered")
                        and loco.get("f1") == 1.0
                        and positive_clusters < 10)
    loco_empty = bool(loco.get("triggered") and loco.get("positives", 0) == 0)
    reasons = []
    if test_positives < 20:
        reasons.append(f"test_positives={test_positives} < 20")
    if len(test_clusters) < 5:
        reasons.append(f"test_positive_clusters={len(test_clusters)} < 5")
    if split_degenerate:
        reasons.append("cluster split is degenerate")
    if structural_confound:
        reasons.append("structural confound: structural-only F1 is within 0.02")
    if loco_inspect:
        reasons.append("LOCO F1=1.0 with fewer than 10 positive clusters")
    if loco_empty:
        reasons.append("LOCO has no positive rows (single positive cluster)")
    return {
        "test_positives": test_positives,
        "test_positive_clusters": len(test_clusters),
        "structural_confound": structural_confound,
        "loco_inspect": loco_inspect,
        "loco_empty": loco_empty,
        "split_degenerate": split_degenerate,
        "train_positive_clusters": positive_clusters,
        "not_a_result": bool(reasons),
        "reasons": reasons,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Stage 1 baselines")
    parser.add_argument("--features", type=Path, default=DEFAULT_FEATURES)
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    train = load_split(args.features / "train.npz")
    val = load_split(args.features / "val.npz")
    test = load_split(args.features / "test.npz")
    gate_ok = gate_status(args.data_root)

    results = []
    majority = Counter(train["y"]).most_common(1)[0][0]
    predictions = np.full(len(test["y"]), majority, dtype=int)
    scores = np.full(len(test["y"]), float(majority))
    results.append({"name": "majority", "metrics": metrics(
        test["y"], predictions, scores)})
    results[-1]["metrics"]["ci"] = bootstrap_ci(
        test["y"], predictions, scores, test["groups"])

    logistic = LogisticRegression(max_iter=2000, random_state=args.seed)
    logistic.fit(train["X_struct"], train["y"])
    pred = logistic.predict(test["X_struct"])
    score = logistic.predict_proba(test["X_struct"])[:, 1]
    results.append({"name": "logistic_structural", "metrics": metrics(
        test["y"], pred, score)})
    results[-1]["metrics"]["ci"] = bootstrap_ci(
        test["y"], pred, score, test["groups"])

    pred, score = tlsh_predict(train, test)
    results.append({"name": "tlsh_knn", "metrics": metrics(
        test["y"], pred, score)})
    results[-1]["metrics"]["ci"] = bootstrap_ci(
        test["y"], pred, score, test["groups"])

    full_model = None
    full_predictions = None
    if HAS_LIGHTGBM:
        model = lgb.LGBMClassifier(
            n_estimators=200, learning_rate=0.05, num_leaves=31,
            random_state=args.seed, n_jobs=4, verbosity=-1,
        )
        results.append(run_model("lightgbm_full", model, train, test))
        full_model = model
        full_predictions = model.predict(test["X"])
        capability = lgb.LGBMClassifier(
            n_estimators=200, learning_rate=0.05, num_leaves=31,
            random_state=args.seed, n_jobs=4, verbosity=-1,
        )
        train_cap = {**train, "X": train["X"][:, :train["vocab_size"]]}
        test_cap = {**test, "X": test["X"][:, :test["vocab_size"]]}
        results.append(run_model("lightgbm_capability_only", capability,
                                 train_cap, test_cap))
        structural = lgb.LGBMClassifier(
            n_estimators=200, learning_rate=0.05, num_leaves=31,
            random_state=args.seed, n_jobs=4, verbosity=-1,
        )
        train_struct = {**train, "X": train["X_struct"]}
        test_struct = {**test, "X": test["X_struct"]}
        results.append(run_model("lightgbm_structural_only", structural,
                                 train_struct, test_struct))
    else:
        model = HistGradientBoostingClassifier(random_state=args.seed)
        results.append(run_model("hist_gradient_fallback", model, train, test))
        full_model = model
        full_predictions = model.predict(test["X"])

    train_clusters = len(set(train["groups"]))
    positive_clusters = len({
        group for group, label in zip(train["groups"], train["y"]) if label == 1
    })
    loco = (run_loco(train) if positive_clusters < 10
            else {"triggered": False, "positive_clusters": positive_clusters})
    feature_info = json.loads((args.features / "feature_names.json").read_text())
    vocab = feature_info["feature_names"][:feature_info["vocab_size"]]
    holdout = (evaluate_holdout(full_model, args.data_root, vocab)
               if full_model is not None else {"rows": 0, "fpr": None})
    validity = validity_report(train, test, results, loco, args.data_root)
    diagnostics = (cluster_diagnostics(train, test, full_predictions,
                                       args.data_root)
                   if full_predictions is not None else [])
    header = ("DIAGNOSTIC ONLY — dataset gate failed; not a result"
              if not gate_ok else "Stage 1 result")
    if validity["not_a_result"]:
        header = "DIAGNOSTIC ONLY — split/validity checks failed; not a result"
    lineage = lineage_only_verified(args.data_root)
    payload = {"header": header, "gate_pass": gate_ok,
               "lineage_only_verified": {
                   "count": len(lineage),
                   "shas": [item["sha256"] for item in lineage]},
               "primary_diagnostic": "loco" if positive_clusters < 10 else "split",
               "validity": validity, "cluster_diagnostics": diagnostics,
               "loco": loco, "holdout": holdout, "models": results}
    print(json.dumps(payload, indent=2))
    (args.features / "baseline_results.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

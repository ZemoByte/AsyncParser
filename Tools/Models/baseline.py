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
    collected = {"precision": [], "recall": [], "f1": [], "pr_auc": []}
    for _ in range(iterations):
        chosen = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([positions[group] for group in chosen])
        yt, yp, ys = y_true[indices], y_pred[indices], y_score[indices]
        collected["precision"].append(precision_score(yt, yp, zero_division=0))
        collected["recall"].append(recall_score(yt, yp, zero_division=0))
        collected["f1"].append(f1_score(yt, yp, zero_division=0))
        if len(set(yt)) == 2:
            collected["pr_auc"].append(average_precision_score(yt, ys))
    return {
        key: [float(np.mean(values)), float(np.percentile(values, 2.5)),
              float(np.percentile(values, 97.5))]
        for key, values in collected.items() if values
    }


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
        scores.append(float(best if best is not None else majority))
    return np.asarray(predictions), np.asarray(scores)


def gate_status(data_root: Path) -> bool:
    conn = sqlite3.connect(f"file:{data_root / 'DataSet.db'}?mode=ro", uri=True)
    try:
        rows = list(conn.execute(
            "SELECT sha256, lbl_sts, target_class_db, cluster_id FROM dataset"
        ))
    finally:
        conn.close()
    by_class = {}
    for class_name in ("AsyncRAT.db", "Benign.db"):
        selected = [row for row in rows if row[2] == class_name]
        clusters = Counter(row[3] for row in selected)
        largest = max(clusters.values()) if clusters else 0
        share = 100.0 * largest / len(selected) if selected else 100.0
        by_class[class_name] = len(clusters) >= 10 and share <= 50.0
    # Stage 2 uses sug_fam from the aggregate labels plus the cluster from DataSet.
    cluster_by_sha = {row[0]: row[3] for row in rows}
    family_clusters: dict[str, set[str]] = {}
    for path in (data_root / "Aggregated").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        fields = payload["fields"]
        if fields.get("lbl_sts") == "verified_other" and fields.get("sug_fam"):
            cluster_id = cluster_by_sha.get(payload.get("sha256", ""), "")
            if cluster_id:
                family_clusters.setdefault(fields["sug_fam"], set()).add(cluster_id)
    stage2 = sum(1 for clusters in family_clusters.values() if len(clusters) >= 2) >= 2
    return all(by_class.values()) and stage2


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
    header = "DIAGNOSTIC ONLY — dataset gate failed; not a result" \
        if not gate_ok else "Stage 1 result"

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

    if HAS_LIGHTGBM:
        model = lgb.LGBMClassifier(
            n_estimators=200, learning_rate=0.05, num_leaves=31,
            random_state=args.seed, n_jobs=4, verbosity=-1,
        )
        results.append(run_model("lightgbm_full", model, train, test))
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

    train_clusters = len(set(train["groups"]))
    loco = (run_loco(train) if train_clusters < 10
            else {"triggered": False, "train_clusters": train_clusters})
    payload = {"header": header, "gate_pass": gate_ok,
               "loco": loco, "models": results}
    print(json.dumps(payload, indent=2))
    (args.features / "baseline_results.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

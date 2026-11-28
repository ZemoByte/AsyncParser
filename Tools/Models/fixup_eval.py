#!/usr/bin/env python3
"""Fixup diagnostics with a harmonized operating point and mixed LOCO.

DIAGNOSTIC ONLY — the dataset gate fails and no output here is a result.
Every threshold is fitted on train (or fold-train) only; test labels never
choose a threshold.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import sqlite3
import sys
import uuid
from collections import Counter
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix, hstack, vstack
from sklearn.metrics import (
    confusion_matrix, f1_score, precision_recall_fscore_support,
    roc_auc_score,
)
from sklearn.model_selection import GroupKFold, train_test_split

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools.Features.build_matrix import (  # noqa: E402
    STRUCTURAL_FEATURES, load_carved, load_structure, select_structural_names,
)
from Tools.Models import baseline  # noqa: E402
from Tools._gate import evaluate_gate  # noqa: E402
from Tools._versions import FEATURE_SCHEMA_VERSION  # noqa: E402

DATA = ROOT / "Data"
FEATURES = DATA / "Features"
POLICY_DIR = FEATURES / "policy"
HEADER = "DIAGNOSTIC ONLY — dataset gate failed; not a result."
SEED = 42
CAP_ROWS = 10
OOF_FOLDS = 5
THRESHOLD_SOURCE = "train_oof_groupkfold"
STAGE2_NOTE = ("diagnostic 2-family LightGBM on {rows} test rows; "
               "eligibility is P2; not a result.")


def script_sha256() -> str:
    return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


def build_run_metadata() -> dict:
    return {
        "generated_at": datetime.datetime.now(
            datetime.timezone.utc).isoformat(timespec="seconds"),
        "script_sha256": script_sha256(),
        "run_id": uuid.uuid4().hex,
        "oof_folds": OOF_FOLDS,
        "threshold_source": THRESHOLD_SOURCE,
    }


def make_model():
    if not baseline.HAS_LIGHTGBM:
        raise RuntimeError("LightGBM is not available; refusing the fallback")
    import lightgbm as lgb
    return lgb.LGBMClassifier(n_estimators=200, learning_rate=0.05,
                              num_leaves=31, random_state=SEED, n_jobs=4,
                              verbosity=-1)


def load_all() -> dict:
    data = {}
    for name, directory in (("full", FEATURES), ("policy", POLICY_DIR)):
        data[name] = {split: baseline.load_split(directory / f"{split}.npz")
                      for split in ("train", "val", "test")}
        data[name]["names"] = json.loads(
            (directory / "feature_names.json").read_text())["structural_names"]
    return data


def subset(data: dict, mask: np.ndarray) -> dict:
    return {
        "X": data["X"][mask],
        "X_struct": data["X_struct"][mask],
        "y": data["y"][mask],
        "groups": data["groups"][mask],
        "sha256": data["sha256"][mask],
        "vocab_size": data["vocab_size"],
    }


def cap_largest_positive(data: dict, max_rows: int = CAP_ROWS,
                         seed: int = SEED) -> tuple[dict, dict]:
    counts = Counter(str(group) for group, label
                     in zip(data["groups"], data["y"]) if int(label) == 1)
    before = {"rows": int(len(data["y"])),
              "positives": int(np.sum(data["y"]))}
    if not counts:
        return data, {"cluster": None, "removed": 0, "before": before,
                      "after": before}
    largest, size = sorted(counts.items(), key=lambda item: (-item[1],
                                                             item[0]))[0]
    if size <= max_rows:
        return data, {"cluster": largest, "removed": 0, "before": before,
                      "after": before}
    indices = np.where((data["groups"] == largest)
                       & (data["y"] == 1))[0]
    rng = np.random.default_rng(seed)
    keep = np.sort(rng.choice(indices, size=max_rows, replace=False))
    remove = np.setdiff1d(indices, keep)
    mask = np.ones(len(data["y"]), dtype=bool)
    mask[remove] = False
    capped = subset(data, mask)
    after = {"rows": int(len(capped["y"])),
             "positives": int(np.sum(capped["y"]))}
    return capped, {"cluster": largest, "cluster_size_before": int(size),
                    "removed": int(len(remove)), "before": before,
                    "after": after, "seed": seed}


def matrix_for(data: dict, kind: str, policy_struct=None,
               all_struct=None) -> csr_matrix:
    vocab = data["vocab_size"]
    if kind == "capability":
        return data["X"][:, :vocab].astype(np.float32)
    if kind == "structural":
        return csr_matrix(policy_struct if policy_struct is not None
                          else data["X_struct"])
    if kind == "capability_policy":
        return hstack([data["X"][:, :vocab].astype(np.float32),
                       csr_matrix(policy_struct)], format="csr")
    if kind == "capability_all":
        return hstack([data["X"][:, :vocab].astype(np.float32),
                       csr_matrix(all_struct)], format="csr")
    raise ValueError(kind)


def matrix_from_data(data: dict, kind: str) -> csr_matrix:
    if kind == "capability":
        return matrix_for(data, "capability")
    if kind == "structural":
        return matrix_for(data, "structural", data["X_struct"])
    if kind == "capability_policy":
        return matrix_for(data, "capability_policy", data["X_struct"])
    if kind == "capability_all":
        return matrix_for(data, "capability_all", None, data["X_struct"])
    raise ValueError(kind)


def cluster_folds(groups: np.ndarray,
                  n_splits: int = OOF_FOLDS) -> list[tuple[np.ndarray, np.ndarray]]:
    splitter = GroupKFold(n_splits=n_splits)
    placeholder = np.zeros(len(groups), dtype=np.int8)
    return [(train, test) for train, test in
            splitter.split(placeholder, groups=groups)]


def oof_scores(train: dict, kind: str,
               cap: bool = False) -> np.ndarray:
    """Grouped OOF scores on train only; clusters never cross folds."""
    y = train["y"]
    groups = train["groups"]
    X = matrix_from_data(train, kind)
    scores = np.zeros(len(y), dtype=float)
    for fold_train, fold_test in cluster_folds(groups):
        if cap:
            mask = np.zeros(len(y), dtype=bool)
            mask[fold_train] = True
            capped, _ = cap_largest_positive(subset(train, mask))
            X_train = matrix_from_data(capped, kind)
            model = make_model()
            model.fit(X_train, capped["y"])
        else:
            model = make_model()
            model.fit(X[fold_train], y[fold_train])
        scores[fold_test] = model.predict_proba(X[fold_test])[:, 1]
    return scores


def threshold_for_f1(y: np.ndarray, score: np.ndarray) -> float:
    best_threshold, best_f1 = float(np.max(score)), -1.0
    for threshold in np.unique(score):
        value = f1_score(y, (score >= threshold).astype(int), zero_division=0)
        if value > best_f1:
            best_f1, best_threshold = value, float(threshold)
    return best_threshold


def threshold_on_train(y_train: np.ndarray,
                       scores_train: np.ndarray) -> float:
    """Choose the F1-maximizing threshold using training rows only."""
    return threshold_for_f1(np.asarray(y_train), np.asarray(scores_train))


def apply_threshold(scores: np.ndarray, threshold: float) -> np.ndarray:
    return (np.asarray(scores) >= float(threshold)).astype(int)


def threshold_at_recall(y: np.ndarray, scores: np.ndarray,
                        target: float) -> float:
    """Highest threshold whose train recall is at least target."""
    y = np.asarray(y)
    scores = np.asarray(scores)
    positives = scores[y == 1]
    if len(positives) == 0:
        return float(np.min(scores)) if len(scores) else 0.5
    threshold = float(np.min(scores))
    for candidate in np.unique(scores)[::-1]:
        pred = scores >= candidate
        recall = float(np.mean(pred[y == 1]))
        if recall >= target:
            threshold = float(candidate)
            break
    return threshold


def metric_block(y: np.ndarray, pred: np.ndarray, score: np.ndarray,
                 groups: np.ndarray) -> dict:
    metrics = baseline.metrics(y, pred, score)
    metrics["roc_auc"] = (float(roc_auc_score(y, score))
                          if len(set(y)) == 2 else None)
    metrics["ci"] = baseline.bootstrap_ci(y, pred, score, groups)
    return metrics


def scored_block(y_test: np.ndarray, scores_test: np.ndarray,
                 threshold_oof: float, threshold_in_sample: float,
                 threshold_recall95: float, threshold_recall90: float,
                 groups: np.ndarray) -> dict:
    at_half = metric_block(y_test, apply_threshold(scores_test, 0.5),
                           scores_test, groups)
    at_oof = metric_block(y_test, apply_threshold(scores_test, threshold_oof),
                          scores_test, groups)
    at_in = metric_block(
        y_test, apply_threshold(scores_test, threshold_in_sample),
        scores_test, groups)
    at95 = metric_block(y_test, apply_threshold(scores_test,
                                                 threshold_recall95),
                        scores_test, groups)
    at90 = metric_block(y_test, apply_threshold(scores_test,
                                                 threshold_recall90),
                        scores_test, groups)
    return {
        "threshold_oof": float(threshold_oof),
        "threshold_in_sample": float(threshold_in_sample),
        "threshold_recall95": float(threshold_recall95),
        "threshold_recall90": float(threshold_recall90),
        "threshold_source": THRESHOLD_SOURCE,
        "at_0.5": at_half,
        "at_oof": at_oof,
        "at_in_sample": at_in,
        "at_recall_95": at95,
        "at_recall_90": at90,
        "f1_at_0.5": at_half["f1"],
        "f1_at_oof": at_oof["f1"],
        "f1_at_in_sample": at_in["f1"],
        "recall_at_95": at95["recall"],
        "f1_at_recall_95": at95["f1"],
        "recall_at_90": at90["recall"],
        "f1_at_recall_90": at90["f1"],
        "pr_auc": at_oof["pr_auc"],
        "roc_auc": at_oof["roc_auc"],
        "ci": at_oof["ci"],
    }


def evaluate_model(train: dict, test: dict, kind: str,
                   cap_model: bool = False,
                   cap_oof: bool = False) -> dict:
    fit_data = cap_largest_positive(train)[0] if cap_model else train
    model = make_model()
    model.fit(matrix_from_data(fit_data, kind), fit_data["y"])
    scores_test = model.predict_proba(matrix_from_data(test, kind))[:, 1]
    scores_in = model.predict_proba(matrix_from_data(fit_data, kind))[:, 1]
    threshold_in = threshold_on_train(fit_data["y"], scores_in)
    oof = oof_scores(train, kind, cap=cap_oof)
    threshold_oof = threshold_on_train(train["y"], oof)
    threshold_95 = threshold_at_recall(train["y"], oof, 0.95)
    threshold_90 = threshold_at_recall(train["y"], oof, 0.90)
    return scored_block(test["y"], scores_test, threshold_oof, threshold_in,
                        threshold_95, threshold_90, test["groups"])


def holdout_features(kind: str, policy_names: list[str]) -> csr_matrix:
    shas = baseline.holdout_shas(DATA)
    carved, _ = load_carved(DATA)
    structure = load_structure(DATA)
    names = policy_names if kind in ("structural", "capability_policy") \
        else list(STRUCTURAL_FEATURES)
    vocab_size = json.loads(
        (FEATURES / "feature_names.json").read_text())["vocab_size"]
    vocab_list = json.loads(
        (FEATURES / "feature_names.json").read_text())["feature_names"][:vocab_size]
    index = {item: pos for pos, item in enumerate(vocab_list)}
    rows, cols, dense = [], [], []
    for row, sha in enumerate(shas):
        for values in carved.get(sha, {}).values():
            for item in values:
                column = index.get(item)
                if column is not None:
                    rows.append(row)
                    cols.append(column)
        fields = structure.get(sha)
        if fields is None:
            raise RuntimeError(f"missing structure JSON for holdout {sha}")
        dense.append([float(fields.get(name.replace("structure_", "", 1), 0.0)
                            or 0.0) for name in names])
    presence = csr_matrix((np.ones(len(rows), dtype=np.int8), (rows, cols)),
                          shape=(len(shas), len(vocab_list)))
    dense_matrix = csr_matrix(np.asarray(dense, dtype=np.float32))
    if kind == "capability":
        return presence.astype(np.float32)
    if kind == "structural":
        return dense_matrix
    if kind == "structural_all":
        return dense_matrix
    return hstack([presence.astype(np.float32), dense_matrix], format="csr")


def holdout_groups() -> np.ndarray:
    shas = baseline.holdout_shas(DATA)
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    try:
        clusters = {row[0]: row[1] for row in conn.execute(
            "SELECT sha256, cluster_id FROM dataset")}
    finally:
        conn.close()
    return np.asarray([str(clusters.get(sha, "")) for sha in shas])


def bootstrap_fpr(pred: np.ndarray, groups: np.ndarray,
                  iterations: int = 200, seed: int = SEED) -> list[float] | None:
    unique = sorted(set(str(group) for group in groups))
    if not unique:
        return None
    rng = np.random.default_rng(seed)
    positions = {group: np.where(groups == group)[0] for group in unique}
    values = []
    for _ in range(iterations):
        chosen = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([positions[group] for group in chosen])
        values.append(float(np.mean(pred[indices])))
    return [float(np.mean(values)), float(np.percentile(values, 2.5)),
            float(np.percentile(values, 97.5))]


def holdout_entry(scores: np.ndarray, thresholds: dict,
                  groups: np.ndarray) -> dict:
    predictions = {
        "at_0.5": apply_threshold(scores, 0.5),
        "at_oof": apply_threshold(scores, thresholds["oof"]),
        "at_in_sample": apply_threshold(scores, thresholds["in_sample"]),
        "at_recall_95": apply_threshold(scores, thresholds["recall95"]),
        "at_recall_90": apply_threshold(scores, thresholds["recall90"]),
    }
    result = {
        "rows": int(len(scores)),
        "threshold_oof": float(thresholds["oof"]),
        "threshold_in_sample": float(thresholds["in_sample"]),
        "threshold_recall95": float(thresholds["recall95"]),
        "threshold_recall90": float(thresholds["recall90"]),
        "threshold_source": THRESHOLD_SOURCE,
        "main": "at_recall_95",
    }
    for name, pred in predictions.items():
        result[name] = {
            "predicted_positive": int(np.sum(pred)),
            "fpr": float(np.mean(pred)),
            "ci": bootstrap_fpr(pred, groups),
        }
    return result


def run_test_suite(all_data: dict, cap_info: dict) -> dict:
    full = all_data["full"]
    policy = all_data["policy"]
    train, val, test = full["train"], full["val"], full["test"]
    p_train, p_test = policy["train"], policy["test"]
    names_all = full["names"]

    majority_label = int(Counter(train["y"]).most_common(1)[0][0])
    majority_pred = np.full(len(test["y"]), majority_label)
    majority_score = majority_pred.astype(float)
    majority = metric_block(test["y"], majority_pred, majority_score,
                            test["groups"])

    index_implmap = names_all.index("structure_implmap_count")
    index_size = names_all.index("structure_file_size")
    implmap_train = train["X_struct"][:, index_implmap]
    implmap_test = test["X_struct"][:, index_implmap]
    implmap_threshold = threshold_on_train(train["y"], implmap_train)
    implmap_95 = threshold_at_recall(train["y"], implmap_train, 0.95)
    implmap_90 = threshold_at_recall(train["y"], implmap_train, 0.90)
    implmap = scored_block(test["y"], implmap_test, implmap_threshold,
                           implmap_threshold, implmap_95, implmap_90,
                           test["groups"])

    size_train = -train["X_struct"][:, index_size]
    size_test = -test["X_struct"][:, index_size]
    size_threshold = threshold_on_train(train["y"], size_train)
    size_95 = threshold_at_recall(train["y"], size_train, 0.95)
    size_90 = threshold_at_recall(train["y"], size_train, 0.90)
    filesize = scored_block(test["y"], size_test, size_threshold,
                            size_threshold, size_95, size_90,
                            test["groups"])
    filesize["direction"] = "smaller file size scores higher"

    knn_pred, knn_score = baseline.tlsh_predict(train, test)
    knn = metric_block(test["y"], knn_pred, knn_score, test["groups"])

    structural = evaluate_model(p_train, p_test, "structural")
    structural_all = evaluate_model(train, test, "structural")
    capability = evaluate_model(train, test, "capability")
    capability_capped = evaluate_model(train, test, "capability",
                                        cap_model=True, cap_oof=True)
    policy_model = evaluate_model(p_train, p_test, "capability_policy")
    all_model = evaluate_model(train, test, "capability_all")

    combined = {key: np.concatenate([train[key], val[key], test[key]])
                for key in ("y", "groups", "sha256")}
    X_all = vstack([train["X"], val["X"], test["X"]], format="csr")
    X_cap = X_all[:, :train["vocab_size"]].astype(np.float32)
    train_idx, test_idx = train_test_split(
        np.arange(len(combined["y"])), test_size=0.30,
        stratify=combined["y"], random_state=SEED)
    random_train = {
        "X": X_cap[train_idx],
        "y": combined["y"][train_idx],
        "groups": combined["groups"][train_idx],
        "sha256": combined["sha256"][train_idx],
        "vocab_size": train["vocab_size"],
    }
    random_model = make_model()
    random_model.fit(random_train["X"], random_train["y"])
    random_in_scores = random_model.predict_proba(random_train["X"])[:, 1]
    random_scores = random_model.predict_proba(X_cap[test_idx])[:, 1]
    random_oof = oof_scores(random_train, "capability")
    random_threshold_oof = threshold_on_train(random_train["y"], random_oof)
    random_threshold_in = threshold_on_train(random_train["y"],
                                              random_in_scores)
    random_95 = threshold_at_recall(random_train["y"], random_oof, 0.95)
    random_90 = threshold_at_recall(random_train["y"], random_oof, 0.90)
    random_metrics = scored_block(
        combined["y"][test_idx], random_scores, random_threshold_oof,
        random_threshold_in, random_95, random_90,
        combined["groups"][test_idx])

    thresholds = {
        "b_implmap_only": implmap_threshold,
        "c_file_size_only_diagnostic": size_threshold,
        "e_structural_policy": structural["threshold_oof"],
        "e2_structural_all_diagnostic": structural_all["threshold_oof"],
        "f_capability_uncapped": capability["threshold_oof"],
        "g_capability_capped": capability_capped["threshold_oof"],
        "h_capability_policy": policy_model["threshold_oof"],
        "i_capability_all": all_model["threshold_oof"],
    }
    thresholds_in_sample = {
        "b_implmap_only": implmap_threshold,
        "c_file_size_only_diagnostic": size_threshold,
        "e_structural_policy": structural["threshold_in_sample"],
        "e2_structural_all_diagnostic": structural_all["threshold_in_sample"],
        "f_capability_uncapped": capability["threshold_in_sample"],
        "g_capability_capped": capability_capped["threshold_in_sample"],
        "h_capability_policy": policy_model["threshold_in_sample"],
        "i_capability_all": all_model["threshold_in_sample"],
    }
    thresholds_recall95 = {
        "b_implmap_only": implmap_95,
        "c_file_size_only_diagnostic": size_95,
        "e_structural_policy": structural["threshold_recall95"],
        "e2_structural_all_diagnostic": structural_all["threshold_recall95"],
        "f_capability_uncapped": capability["threshold_recall95"],
        "g_capability_capped": capability_capped["threshold_recall95"],
        "h_capability_policy": policy_model["threshold_recall95"],
        "i_capability_all": all_model["threshold_recall95"],
    }
    thresholds_recall90 = {
        "b_implmap_only": implmap_90,
        "c_file_size_only_diagnostic": size_90,
        "e_structural_policy": structural["threshold_recall90"],
        "e2_structural_all_diagnostic": structural_all["threshold_recall90"],
        "f_capability_uncapped": capability["threshold_recall90"],
        "g_capability_capped": capability_capped["threshold_recall90"],
        "h_capability_policy": policy_model["threshold_recall90"],
        "i_capability_all": all_model["threshold_recall90"],
    }
    models = {
        "a_majority": {"kind": "fixed", "metrics": majority},
        "b_implmap_only": {"kind": "scored", **implmap},
        "c_file_size_only_diagnostic": {"kind": "scored", **filesize},
        "d_tlsh_knn": {"kind": "fixed", "metrics": knn},
        "e_structural_policy": {"kind": "scored", **structural},
        "e2_structural_all_diagnostic": {"kind": "scored", **structural_all},
        "f_capability_uncapped": {"kind": "scored", **capability},
        "g_capability_capped": {"kind": "scored", **capability_capped},
        "h_capability_policy": {"kind": "scored", **policy_model},
        "i_capability_all": {"kind": "scored", **all_model},
        "j_random_split_leaky": {"kind": "scored_leaky", **random_metrics},
    }
    return {
        "test_rows": int(len(test["y"])),
        "test_positives": int(np.sum(test["y"])),
        "test_clusters": int(len(set(test["groups"]))),
        "operating_point": ("train OOF 5-fold GroupKFold by cluster; "
                            "0.5 is the fixed reference; in-sample threshold "
                            "is the overfit sensitivity column"),
        "oof_folds": OOF_FOLDS,
        "threshold_source": THRESHOLD_SOURCE,
        "thresholds": thresholds,
        "thresholds_in_sample": thresholds_in_sample,
        "thresholds_recall95": thresholds_recall95,
        "thresholds_recall90": thresholds_recall90,
        "models": models,
        "policy_ablation": {
            "structural_policy": structural,
            "structural_all_diagnostic": structural_all,
            "capability_policy": policy_model,
            "capability_all_diagnostic": all_model,
        },
        "random_split_gap_f1": (models["j_random_split_leaky"]["f1_at_oof"]
                                - capability["f1_at_oof"]),
        "cap": cap_info,
    }


def loco_clusters(groups, labels, families: dict[str, str],
                  positive_only: bool) -> list[str]:
    return sorted({str(group) for group, label_value, sha
                   in zip(groups, labels, families)
                   if int(label_value) == 1
                   and (not positive_only
                        or families.get(str(sha)) == "AsyncRAT")})


def mixed_loco_folds(groups: np.ndarray, labels: np.ndarray,
                     positive_clusters: list[str],
                     benign_clusters: list[str]) -> list[dict]:
    """Hold out one positive cluster and its round-robin benign clusters."""
    folds = []
    count = len(positive_clusters)
    for index, positive in enumerate(positive_clusters):
        held_benign = [benign for position, benign
                       in enumerate(benign_clusters)
                       if position % count == index]
        held = {positive, *held_benign}
        test_mask = np.isin(groups, list(held))
        folds.append({
            "fold": index,
            "positive_cluster": positive,
            "benign_clusters": sorted(held_benign),
            "test_index": np.where(test_mask)[0],
            "train_index": np.where(~test_mask)[0],
        })
    assigned = sorted(cluster for fold in folds
                      for cluster in fold["benign_clusters"])
    if assigned != sorted(benign_clusters):
        raise RuntimeError("benign clusters are not held out exactly once")
    for fold in folds:
        overlap = set(groups[fold["test_index"]]) & set(
            groups[fold["train_index"]])
        if overlap:
            raise RuntimeError(f"held-out clusters leak into fold-train: "
                               f"{sorted(overlap)}")
    return folds


def add_fpr_block(metrics: dict, pred: np.ndarray, y: np.ndarray,
                  groups: np.ndarray) -> dict:
    if np.any(y == 0):
        metrics["fpr"] = float(np.mean(pred[y == 0] == 1))
        metrics["fpr_ci"] = bootstrap_fpr(pred[y == 0], groups[y == 0])
    else:
        metrics["fpr"] = None
        metrics["fpr_ci"] = None
    return metrics


def run_loco(all_data: dict, positive_only: bool, label: str,
             run_id: str = "") -> dict:
    full = all_data["full"]
    policy = all_data["policy"]
    train, val, test = full["train"], full["val"], full["test"]
    combined = {key: np.concatenate([train[key], val[key], test[key]])
                for key in ("y", "groups", "sha256")}
    X_all = vstack([train["X"], val["X"], test["X"]], format="csr")
    struct_policy = np.vstack([policy["train"]["X_struct"],
                               policy["val"]["X_struct"],
                               policy["test"]["X_struct"]])
    struct_all = np.vstack([train["X_struct"], val["X_struct"],
                            test["X_struct"]])
    base = {"X": X_all, "X_struct": struct_policy,
            "y": combined["y"], "groups": combined["groups"],
            "sha256": combined["sha256"],
            "vocab_size": train["vocab_size"]}
    positive_families = family_map()
    positive_clusters = loco_clusters(
        base["groups"], base["y"],
        {str(sha): positive_families.get(str(sha), "")
         for sha in base["sha256"]}, positive_only)
    by_cluster = {}
    for group, label_value in zip(base["groups"], base["y"]):
        by_cluster.setdefault(str(group), set()).add(int(label_value))
    benign_clusters = sorted(cluster for cluster, values
                             in by_cluster.items() if values == {0})
    mixed_clusters = sorted(cluster for cluster, values
                            in by_cluster.items() if len(values) > 1)
    folds = mixed_loco_folds(base["groups"], base["y"], positive_clusters,
                             benign_clusters)
    model_names = ("a_majority", "b_implmap_only", "c_file_size_only",
                   "d_tlsh_knn", "e_structural_policy", "f_capability",
                   "g_capability_capped", "h_capability_policy",
                   "i_capability_all")
    truths, groups = [], []
    pred_half = {name: [] for name in model_names}
    pred95 = {name: [] for name in model_names}
    pred90 = {name: [] for name in model_names}
    scores = {name: [] for name in model_names}
    fold_rows = []

    for fold in folds:
        train_index = fold["train_index"]
        test_index = fold["test_index"]
        y_test = base["y"][test_index]
        truths.extend(y_test.tolist())
        groups.extend(base["groups"][test_index].tolist())
        fold_entry = {"fold": fold["fold"],
                      "positive_cluster": fold["positive_cluster"],
                      "benign_clusters": fold["benign_clusters"],
                      "test_rows": int(len(test_index)),
                      "positive_rows": int(np.sum(y_test)),
                      "benign_rows": int(np.sum(y_test == 0)),
                      "models": {}}
        for name, half, score, matched95, thr95, matched90, thr90 in loco_predictions(
                base, train_index, test_index, struct_policy, struct_all):
            pred_half[name].extend(half.tolist())
            pred95[name].extend(matched95.tolist())
            pred90[name].extend(matched90.tolist())
            scores[name].extend(score.tolist())
            positive_mask = y_test == 1
            benign_mask = y_test == 0
            fold_entry["models"][name] = {
                "threshold_95": (None if thr95 is None else float(thr95)),
                "threshold_90": (None if thr90 is None else float(thr90)),
                "recall_95": (float(np.mean(matched95[positive_mask] == 1))
                              if positive_mask.any() else None),
                "fpr_95": (float(np.mean(matched95[benign_mask] == 1))
                           if benign_mask.any() else None),
                "recall_90": (float(np.mean(matched90[positive_mask] == 1))
                              if positive_mask.any() else None),
                "fpr_90": (float(np.mean(matched90[benign_mask] == 1))
                           if benign_mask.any() else None),
                "recall_0.5": (float(np.mean(half[positive_mask] == 1))
                               if positive_mask.any() else None),
                "fpr_0.5": (float(np.mean(half[benign_mask] == 1))
                            if benign_mask.any() else None),
            }
        fold_rows.append(fold_entry)

    y = np.asarray(truths)
    group_array = np.asarray(groups)
    probability_models = {"e_structural_policy", "f_capability",
                          "g_capability_capped", "h_capability_policy",
                          "i_capability_all"}
    models = {}
    for name in model_names:
        entry = {"comparable_at_0.5": name in probability_models}
        for point, predictions in (("at_0.5", pred_half),
                                   ("at_recall_95", pred95),
                                   ("at_recall_90", pred90)):
            metrics = metric_block(y, np.asarray(predictions[name]),
                                   np.asarray(scores[name]), group_array)
            add_fpr_block(metrics, np.asarray(predictions[name]), y,
                          group_array)
            entry[point] = metrics
        for target in ("95", "90"):
            thresholds = [row["models"][name][f"threshold_{target}"]
                          for row in fold_rows
                          if row["models"][name][f"threshold_{target}"] is not None]
            fprs = [row["models"][name][f"fpr_{target}"] for row in fold_rows
                    if row["models"][name][f"fpr_{target}"] is not None]
            recalls = [row["models"][name][f"recall_{target}"]
                       for row in fold_rows
                       if row["models"][name][f"recall_{target}"] is not None]
            entry[f"threshold_range_{target}"] = (
                [min(thresholds), max(thresholds)] if thresholds else None)
            entry[f"fpr_range_{target}"] = (
                [min(fprs), max(fprs)] if fprs else None)
            entry[f"recall_range_{target}"] = (
                [min(recalls), max(recalls)] if recalls else None)
        entry["per_fold"] = {str(row["fold"]): row["models"][name]
                             for row in fold_rows}
        models[name] = entry
    return {
        "scope": label,
        "kind": "mixed_positive_and_benign",
        "primary": "at_recall_95",
        "sensitivity": "at_recall_90",
        "reference": "at_0.5 (probability models only)",
        "run_id": run_id,
        "folds": len(positive_clusters),
        "positive_clusters": len(positive_clusters),
        "benign_clusters": len(benign_clusters),
        "mixed_clusters": mixed_clusters,
        "rows": int(len(truths)),
        "positives": int(np.sum(y)),
        "negatives": int(np.sum(y == 0)),
        "per_fold": fold_rows,
        "models": models,
    }


def loco_predictions(base: dict, train_index: np.ndarray,
                     test_index: np.ndarray, struct_policy, struct_all):
    train = {"X": base["X"][train_index], "y": base["y"][train_index],
             "groups": base["groups"][train_index],
             "sha256": base["sha256"][train_index],
             "vocab_size": base["vocab_size"],
             "X_struct": struct_policy[train_index]}
    test = {"X": base["X"][test_index], "y": base["y"][test_index],
            "groups": base["groups"][test_index],
            "sha256": base["sha256"][test_index],
            "vocab_size": base["vocab_size"],
            "X_struct": struct_policy[test_index]}
    p_train = {**train}
    p_test = {**test}
    all_train = {**train, "X_struct": struct_all[train_index]}
    all_test = {**test, "X_struct": struct_all[test_index]}

    majority = int(Counter(train["y"]).most_common(1)[0][0])
    majority_pred = np.full(len(test["y"]), majority)
    yield ("a_majority", majority_pred, majority_pred.astype(float),
           majority_pred, None, majority_pred, None)

    implmap_index = list(STRUCTURAL_FEATURES).index("structure_implmap_count")
    implmap_train = np.asarray(struct_all[train_index][:, implmap_index])
    implmap_test = np.asarray(struct_all[test_index][:, implmap_index])
    thr95 = threshold_at_recall(train["y"], implmap_train, 0.95)
    thr90 = threshold_at_recall(train["y"], implmap_train, 0.90)
    yield ("b_implmap_only", apply_threshold(implmap_test, 0.5), implmap_test,
           apply_threshold(implmap_test, thr95), thr95,
           apply_threshold(implmap_test, thr90), thr90)

    size_index = list(STRUCTURAL_FEATURES).index("structure_file_size")
    size_train = -np.asarray(struct_all[train_index][:, size_index])
    size_test = -np.asarray(struct_all[test_index][:, size_index])
    thr95 = threshold_at_recall(train["y"], size_train, 0.95)
    thr90 = threshold_at_recall(train["y"], size_train, 0.90)
    yield ("c_file_size_only", apply_threshold(size_test, 0.5), size_test,
           apply_threshold(size_test, thr95), thr95,
           apply_threshold(size_test, thr90), thr90)

    knn_pred, knn_score = baseline.tlsh_predict(train, test)
    yield ("d_tlsh_knn", knn_pred, knn_score, knn_pred, None, knn_pred, None)

    for name, train_data, test_data, kind in (
            ("e_structural_policy", p_train, p_test, "structural"),
            ("f_capability", train, test, "capability"),
            ("h_capability_policy", p_train, p_test, "capability_policy"),
            ("i_capability_all", all_train, all_test, "capability_all")):
        X_train = matrix_from_data(train_data, kind)
        X_test = matrix_from_data(test_data, kind)
        model = make_model()
        model.fit(X_train, train_data["y"])
        train_scores = model.predict_proba(X_train)[:, 1]
        score = model.predict_proba(X_test)[:, 1]
        thr95 = threshold_at_recall(train_data["y"], train_scores, 0.95)
        thr90 = threshold_at_recall(train_data["y"], train_scores, 0.90)
        yield (name, apply_threshold(score, 0.5), score,
               apply_threshold(score, thr95), thr95,
               apply_threshold(score, thr90), thr90)

    capped, _ = cap_largest_positive(train)
    model = make_model()
    X_capped = matrix_from_data(capped, "capability")
    X_test = matrix_from_data(test, "capability")
    model.fit(X_capped, capped["y"])
    train_scores = model.predict_proba(X_capped)[:, 1]
    score = model.predict_proba(X_test)[:, 1]
    thr95 = threshold_at_recall(capped["y"], train_scores, 0.95)
    thr90 = threshold_at_recall(capped["y"], train_scores, 0.90)
    yield ("g_capability_capped", apply_threshold(score, 0.5), score,
           apply_threshold(score, thr95), thr95,
           apply_threshold(score, thr90), thr90)


def family_map() -> dict[str, str]:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    try:
        return {row[0]: ("AsyncRAT" if row[1] == "verified"
                         else str(row[2] or ""))
                for row in conn.execute(
                    "SELECT sha256, lbl_sts, sug_fam FROM dataset "
                    "WHERE lbl_sts IN ('verified','verified_other')")}
    finally:
        conn.close()


def is_eligible(rows: int, clusters: int) -> bool:
    return rows >= 20 and clusters >= 10


def stage2_eligibility() -> dict:
    families = family_map()
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    clusters = {row[0]: (row[1], row[2]) for row in conn.execute(
        "SELECT sha256, cluster_id, split FROM dataset")}
    conn.close()
    by_family = {}
    for sha, family in families.items():
        if not family:
            continue
        entry = by_family.setdefault(family, {"rows": 0, "clusters": set(),
                                              "test_rows": 0,
                                              "test_clusters": set()})
        entry["rows"] += 1
        cluster, split = clusters.get(sha, (None, None))
        if cluster:
            entry["clusters"].add(cluster)
        if split == "test":
            entry["test_rows"] += 1
            if cluster:
                entry["test_clusters"].add(cluster)
    table = {}
    for family, entry in sorted(by_family.items()):
        table[family] = {
            "rows": entry["rows"],
            "clusters": len(entry["clusters"]),
            "eligible": is_eligible(entry["rows"], len(entry["clusters"])),
            "test_rows": entry["test_rows"],
            "test_clusters": len(entry["test_clusters"]),
            "low_support": len(entry["test_clusters"]) < 5,
        }
    return table


def bootstrap_macro_f1(y_true: np.ndarray, y_pred: np.ndarray,
                       groups: np.ndarray, labels: list[int],
                       iterations: int = 200, seed: int = SEED) -> list[float] | None:
    unique = sorted(set(str(group) for group in groups))
    if not unique:
        return None
    rng = np.random.default_rng(seed)
    positions = {group: np.where(groups == group)[0] for group in unique}
    values = []
    for _ in range(iterations):
        chosen = rng.choice(unique, size=len(unique), replace=True)
        indices = np.concatenate([positions[group] for group in chosen])
        values.append(float(f1_score(y_true[indices], y_pred[indices],
                                     labels=labels, average="macro",
                                     zero_division=0)))
    return [float(np.mean(values)), float(np.percentile(values, 2.5)),
            float(np.percentile(values, 97.5))]


def stage2_metrics(all_data: dict, table: dict) -> dict:
    eligible = sorted(name for name, row in table.items() if row["eligible"])
    if len(eligible) < 2:
        return {"eligible": eligible,
                "note": "fewer than two eligible families"}
    full = all_data["full"]
    train, test = full["train"], full["test"]
    families = family_map()
    train_mask = np.asarray([families.get(str(sha)) in eligible
                             for sha in train["sha256"]])
    test_mask = np.asarray([families.get(str(sha)) in eligible
                            for sha in test["sha256"]])
    labels = {name: index for index, name in enumerate(eligible)}
    y_train = np.asarray([labels[families[str(sha)]]
                          for sha in train["sha256"][train_mask]])
    y_test = np.asarray([labels[families[str(sha)]]
                         for sha in test["sha256"][test_mask]])
    groups = np.asarray(test["groups"])[test_mask]
    model = make_model()
    model.fit(train["X"][train_mask][:, :train["vocab_size"]].astype(np.float32),
              y_train)
    pred = model.predict(
        test["X"][test_mask][:, :test["vocab_size"]].astype(np.float32))
    matrix = confusion_matrix(y_test, pred, labels=list(range(len(eligible))))
    precision, recall, f1, support = precision_recall_fscore_support(
        y_test, pred, labels=list(range(len(eligible))), zero_division=0)
    macro = float(f1_score(y_test, pred, labels=list(range(len(eligible))),
                           average="macro", zero_division=0))
    return {
        "eligible": eligible,
        "test_rows": int(len(y_test)),
        "test_true": {name: int(np.sum(y_test == index))
                      for name, index in labels.items()},
        "test_predicted": {name: int(np.sum(pred == index))
                           for name, index in labels.items()},
        "confusion_matrix": {"labels": eligible,
                             "rows_true_cols_pred": matrix.tolist()},
        "per_class": {name: {"precision": float(precision[index]),
                             "recall": float(recall[index]),
                             "f1": float(f1[index]),
                             "support": int(support[index])}
                      for name, index in labels.items()},
        "macro_f1": macro,
        "macro_f1_ci": bootstrap_macro_f1(y_test, pred, groups,
                                         list(range(len(eligible)))),
        "low_support": {name: table[name]["low_support"] for name in eligible},
        "note": STAGE2_NOTE.format(rows=len(y_test)),
    }


def main() -> int:
    all_data = load_all()
    gate = evaluate_gate(DATA)
    metadata = build_run_metadata()
    report = {"header": HEADER, "gate": gate,
              "feature_schema_version": FEATURE_SCHEMA_VERSION,
              "policy_features": select_structural_names("policy"),
              "d2": "not run: awaiting D2 approval", **metadata,
              "operating_point": ("main test table uses a grouped OOF "
                                  "train threshold; 0.5 is the fixed "
                                  "reference")}
    _, cap_info = cap_largest_positive(all_data["full"]["train"])
    report["cap"] = cap_info

    test_suite = run_test_suite(all_data, cap_info)
    test_suite["run_id"] = metadata["run_id"]
    report["test"] = test_suite

    holdout_matrix_cap = holdout_features("capability",
                                          all_data["policy"]["names"])
    holdout_matrix_policy = holdout_features("capability_policy",
                                             all_data["policy"]["names"])
    holdout_matrix_struct = holdout_features("structural",
                                             all_data["policy"]["names"])
    holdout_matrix_struct_all = holdout_features(
        "structural_all", all_data["policy"]["names"])
    holdout_matrix_all = holdout_features("capability_all",
                                          all_data["policy"]["names"])
    holdout_y = holdout_groups()
    holdout = {}
    specs = (
        ("capability_uncapped", all_data["full"]["train"], "capability",
         None, holdout_matrix_cap, "f_capability_uncapped"),
        ("capability_capped",
         cap_largest_positive(all_data["full"]["train"])[0], "capability",
         None, holdout_matrix_cap, "g_capability_capped"),
        ("capability_policy", all_data["policy"]["train"],
         "capability_policy", all_data["policy"]["train"]["X_struct"],
         holdout_matrix_policy, "h_capability_policy"),
        ("structural_policy", all_data["policy"]["train"], "structural",
         all_data["policy"]["train"]["X_struct"], holdout_matrix_struct,
         "e_structural_policy"),
        ("structural_all_diagnostic", all_data["full"]["train"], "structural",
         all_data["full"]["train"]["X_struct"], holdout_matrix_struct_all,
         "e2_structural_all_diagnostic"),
        ("capability_all", all_data["full"]["train"], "capability_all",
         all_data["full"]["train"]["X_struct"], holdout_matrix_all,
         "i_capability_all"),
    )
    for name, train_data, kind, struct, matrix, model_name in specs:
        X_train = matrix_for(train_data, kind, struct, struct)
        model = make_model()
        model.fit(X_train, train_data["y"])
        scores = model.predict_proba(matrix)[:, 1]
        thresholds = {
            "oof": test_suite["thresholds"][model_name],
            "in_sample": test_suite["thresholds_in_sample"][model_name],
            "recall95": test_suite["thresholds_recall95"][model_name],
            "recall90": test_suite["thresholds_recall90"][model_name],
        }
        holdout[name] = holdout_entry(scores, thresholds, holdout_y)
        for key, value in thresholds.items():
            if holdout[name][f"threshold_{key}"] != value:
                raise RuntimeError(f"holdout threshold drift for {name}: {key}")

    names_all = all_data["full"]["names"]
    train_all = all_data["full"]["train"]
    vocab = train_all["vocab_size"]
    implmap_index = names_all.index("structure_implmap_count")
    size_index = names_all.index("structure_file_size")
    implmap_scores = np.asarray(
        holdout_matrix_all[:, vocab + implmap_index].todense()).ravel()
    size_scores = -np.asarray(
        holdout_matrix_all[:, vocab + size_index].todense()).ravel()
    for name, scores, key in (
            ("implmap_only", implmap_scores, "b_implmap_only"),
            ("file_size_only_diagnostic", size_scores,
             "c_file_size_only_diagnostic")):
        thresholds = {
            "oof": test_suite["thresholds"][key],
            "in_sample": test_suite["thresholds_in_sample"][key],
            "recall95": test_suite["thresholds_recall95"][key],
            "recall90": test_suite["thresholds_recall90"][key],
        }
        holdout[name] = holdout_entry(scores, thresholds, holdout_y)
        for threshold_key, value in thresholds.items():
            if holdout[name][f"threshold_{threshold_key}"] != value:
                raise RuntimeError(
                    f"holdout threshold drift for {name}: {threshold_key}")
    holdout["file_size_only_diagnostic"]["direction"] = (
        "smaller file size scores higher")
    holdout["implmap_only"]["note"] = (
        "raw P/Invoke count; the 0.5 row is not a meaningful operating point")
    holdout["file_size_only_diagnostic"]["note"] = (
        "negative bytes; the 0.5 row is not a meaningful operating point")
    report["holdout"] = holdout

    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    obf = {row[0]: str(row[1]) for row in conn.execute(
        "SELECT sha256, obf_lvl FROM dataset")}
    conn.close()
    test_obf = Counter()
    for sha in all_data["full"]["test"]["sha256"]:
        level = obf.get(str(sha), "plain")
        test_obf["obfuscated" if level.startswith("obfuscated") else "plain"] += 1
    positives = sum(
        1 for sha, label in zip(all_data["full"]["test"]["sha256"],
                                all_data["full"]["test"]["y"])
        if int(label) == 1
        and obf.get(str(sha), "").startswith("obfuscated"))
    report["obfuscated_test"] = {"counts": dict(test_obf),
                                 "obfuscated_positives": positives,
                                 "metrics_skipped": positives < 20}

    table = stage2_eligibility()
    report["stage2"] = {"eligibility": table,
                        "metrics": stage2_metrics(all_data, table),
                        "run_id": metadata["run_id"]}
    report["holdout"]["run_id"] = metadata["run_id"]

    report["loco_verified"] = run_loco(all_data, True,
                                       "verified_asyncrat",
                                       run_id=metadata["run_id"])
    report["loco_positive"] = run_loco(all_data, False,
                                       "verified_and_other",
                                       run_id=metadata["run_id"])

    (FEATURES / "fixup_results.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps({
        "gate_overall": gate["overall"],
        "capability": {
            "f1_0.5": round(test_suite["models"]["f_capability_uncapped"]["f1_at_0.5"], 3),
            "f1_oof": round(test_suite["models"]["f_capability_uncapped"]["f1_at_oof"], 3),
            "threshold_oof": round(test_suite["thresholds"]["f_capability_uncapped"], 3),
            "threshold_in_sample": round(test_suite["thresholds_in_sample"]["f_capability_uncapped"], 3),
            "pr_auc": round(test_suite["models"]["f_capability_uncapped"]["pr_auc"], 3),
            "roc_auc": round(test_suite["models"]["f_capability_uncapped"]["roc_auc"], 3),
        },
        "implmap": {
            "f1_0.5": round(test_suite["models"]["b_implmap_only"]["f1_at_0.5"], 3),
            "f1_oof": round(test_suite["models"]["b_implmap_only"]["f1_at_oof"], 3),
            "threshold_oof": round(test_suite["thresholds"]["b_implmap_only"], 3),
            "threshold_in_sample": round(test_suite["thresholds_in_sample"]["b_implmap_only"], 3),
            "pr_auc": round(test_suite["models"]["b_implmap_only"]["pr_auc"], 3),
            "roc_auc": round(test_suite["models"]["b_implmap_only"]["roc_auc"], 3),
        },
        "loco_verified": {"folds": report["loco_verified"]["folds"],
                          "benign_clusters": report["loco_verified"]["benign_clusters"],
                          "mixed": report["loco_verified"]["mixed_clusters"]},
        "loco_positive": {"folds": report["loco_positive"]["folds"],
                          "benign_clusters": report["loco_positive"]["benign_clusters"],
                          "mixed": report["loco_positive"]["mixed_clusters"]},
        "stage2_note": report["stage2"]["metrics"]["note"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

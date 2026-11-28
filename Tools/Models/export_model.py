#!/usr/bin/env python3
"""Export the frozen capability and AsyncRAT-vs-XWorm models.

Reads the frozen train matrix and metadata. Writes only Data/Models/.
"""

from __future__ import annotations

import datetime
import json
import sys
from pathlib import Path

import joblib
import numpy as np

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools.Models import baseline, fixup_eval  # noqa: E402

DATA = ROOT / "Data"
FEATURES = DATA / "Features"
MODELS = DATA / "Models"
THRESHOLD = 0.559


def save_artifact(path: Path, model, metadata: dict) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"model": model, **metadata}
    joblib.dump(payload, path)
    return payload


def train_capability(train: dict, vocab_size: int):
    model = fixup_eval.make_model()
    model.fit(train["X"][:, :vocab_size], train["y"])
    return model


def train_family(train: dict, vocab_size: int):
    families = fixup_eval.family_map()
    table = fixup_eval.stage2_eligibility()
    eligible = sorted(name for name, row in table.items() if row["eligible"])
    if eligible != ["AsyncRAT", "XWorm"]:
        raise RuntimeError(f"unexpected eligible families: {eligible}")
    mask = np.asarray([families.get(str(sha)) in eligible
                       for sha in train["sha256"]])
    labels = {name: index for index, name in enumerate(eligible)}
    y = np.asarray([labels[families[str(sha)]]
                    for sha in train["sha256"][mask]])
    model = fixup_eval.make_model()
    model.fit(train["X"][mask][:, :vocab_size], y)
    return model, eligible, int(mask.sum()), y


def main() -> int:
    train = baseline.load_split(FEATURES / "train.npz")
    feature_info = json.loads((FEATURES / "feature_names.json").read_text())
    vocab_size = int(feature_info["vocab_size"])
    feature_names = feature_info["feature_names"][:vocab_size]
    abstention = json.loads((FEATURES / "abstention.json").read_text())
    run = json.loads((FEATURES / "fixup_results.json").read_text())
    trained_at = datetime.datetime.now(
        datetime.timezone.utc).isoformat(timespec="seconds")
    MODELS.mkdir(parents=True, exist_ok=True)

    capability = train_capability(train, vocab_size)
    capability_payload = save_artifact(MODELS / "capability.joblib", capability, {
        "schema": "capability_model_v1",
        "model_type": "lightgbm",
        "vocab_size": vocab_size,
        "feature_names": feature_names,
        "threshold": THRESHOLD,
        "threshold_exact": run["test"]["thresholds"]["f_capability_uncapped"],
        "threshold_source": "train OOF, frozen Phase 5 run",
        "abstain_threshold": int(abstention["threshold"]),
        "abstain_source": "Data/Features/abstention.json",
        "run_id": run["run_id"],
        "script_sha256": run["script_sha256"],
        "trained_at": trained_at,
        "feature_policy": "capability",
        "training_rows": int(len(train["y"])),
        "positive_rows": int(np.sum(train["y"])),
    })

    family, classes, rows, _y = train_family(train, vocab_size)
    family_payload = save_artifact(
        MODELS / "family_asyncrat_xworm.joblib", family, {
        "schema": "family_model_v1",
        "model_type": "lightgbm",
        "vocab_size": vocab_size,
        "feature_names": feature_names,
        "classes": classes,
        "diagnostic": True,
        "n_train": rows,
        "n_test": 29,
        "note": "diagnostic AsyncRAT vs XWorm only; not a family model",
        "run_id": run["run_id"],
        "script_sha256": run["script_sha256"],
        "trained_at": trained_at,
        "feature_policy": "capability",
    })
    print(json.dumps({
        "capability": str(MODELS / "capability.joblib"),
        "family": str(MODELS / "family_asyncrat_xworm.joblib"),
        "vocab_size": vocab_size,
        "threshold": THRESHOLD,
        "abstain_threshold": capability_payload["abstain_threshold"],
        "run_id": run["run_id"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

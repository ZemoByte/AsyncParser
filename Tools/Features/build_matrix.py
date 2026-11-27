#!/usr/bin/env python3
"""Build the Stage 1 vocabulary and sparse feature matrices.

Primary rows: verified/verified_other positives and benign EXEs whose origin
is not fixture. Vocabulary is fitted on the TRAIN cluster split only.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

import numpy as np
from scipy.sparse import csr_matrix

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools.Splits.split import read_rows  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
DEFAULT_OUT = ROOT / "Data" / "Features"
DEFAULT_VOCAB = ROOT / "Docs" / "vocab.json"
TOOLS = ("ImportTable", "TypeRef", "MemberRef", "AssemblyRef", "ImplMap")
STRUCTURAL_FEATURES = (
    "structure_type_count", "structure_method_count", "structure_typeref_count",
    "structure_memberref_count", "structure_implmap_count",
    "structure_importtable_count", "structure_resource_count",
    "structure_section_count", "structure_file_size",
    "structure_entropy_max", "structure_entropy_mean",
)
SEED = 42


def load_carved(data_root: Path) -> tuple[dict[str, dict[str, set[str]]], int]:
    carved: dict[str, dict[str, set[str]]] = defaultdict(dict)
    for class_name in ("AsyncRAT", "OtherMalwares", "Benign"):
        for tool in TOOLS:
            directory = data_root / class_name / tool
            if not directory.is_dir():
                continue
            for path in directory.glob("*.json"):
                payload = json.loads(path.read_text(encoding="utf-8"))
                fields = payload.get("fields", {})
                values = fields.get("values", [])
                if isinstance(values, list):
                    carved[payload["sha256"]][tool] = set(map(str, values))
    return carved, len(carved)


def load_structure(data_root: Path) -> dict[str, dict]:
    result = {}
    directory = data_root / "Structure"
    if not directory.is_dir():
        return result
    for path in directory.glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        result[payload["sha256"]] = payload.get("fields", {})
    return result


def read_splits(data_root: Path) -> dict[str, str]:
    result = {}
    for path in (data_root / "Splits").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        result[payload["sha256"]] = payload["fields"]["cluster_split"]
    return result


def build_vocab(train_rows: list[dict],
                carved: dict[str, dict[str, set[str]]],
                min_clusters: int) -> tuple[list[str], dict[str, int]]:
    cluster_values: dict[str, set[str]] = defaultdict(set)
    for row in train_rows:
        sha = row["sha256"]
        for values in carved.get(sha, {}).values():
            cluster_values[row["cluster_id"]].update(values)
    counts = defaultdict(int)
    for values in cluster_values.values():
        for item in values:
            counts[item] += 1
    kept = {item: count for item, count in counts.items()
            if count >= min_clusters}
    return sorted(kept), dict(sorted(kept.items()))


def structural_row(structure: dict, sha: str) -> list[float]:
    fields = structure.get(sha)
    if fields is None:
        raise RuntimeError(f"missing structure JSON for primary sample {sha}")
    row = []
    for name in STRUCTURAL_FEATURES:
        value = fields.get(name.replace("structure_", "", 1), 0.0)
        try:
            number = float(value)
        except (TypeError, ValueError):
            number = 0.0
        row.append(number)
    return row


def build_arrays(rows: list[dict], splits: dict[str, str],
                 carved: dict[str, dict[str, set[str]]],
                 structure: dict[str, dict], vocab: list[str]) -> dict:
    ordered = sorted(rows, key=lambda row: row["sha256"])
    sha_list = [row["sha256"] for row in ordered]
    missing_split = [sha for sha in sha_list if sha not in splits]
    if missing_split:
        raise RuntimeError(f"missing split for {len(missing_split)} primary rows")
    vocab_index = {item: index for index, item in enumerate(vocab)}
    presence_rows = []
    presence_cols = []
    structural = []
    y = []
    groups = []
    for row_index, row in enumerate(ordered):
        sha = row["sha256"]
        for values in carved.get(sha, {}).values():
            for item in values:
                column = vocab_index.get(item)
                if column is not None:
                    presence_rows.append(row_index)
                    presence_cols.append(column)
        structural.append(structural_row(structure, sha))
        y.append(1 if row["label"] == "positive" else 0)
        groups.append(row["cluster_id"])
    presence = csr_matrix(
        (np.ones(len(presence_rows), dtype=np.int8),
         (presence_rows, presence_cols)),
        shape=(len(ordered), len(vocab)),
    )
    dense = np.asarray(structural, dtype=np.float32)
    if not np.isfinite(dense).all():
        raise RuntimeError("non-finite structural value")
    return {
        "sha256": np.asarray(sha_list),
        "presence": presence,
        "structural": dense,
        "y": np.asarray(y, dtype=np.int8),
        "groups": np.asarray(groups),
        "split": np.asarray([splits[sha] for sha in sha_list]),
    }


def save_split(path: Path, arrays: dict, vocab_size: int) -> None:
    presence = arrays["presence"]
    dense = arrays["structural"]
    from scipy.sparse import hstack
    combined = hstack([presence, csr_matrix(dense)], format="csr")
    np.savez_compressed(
        path,
        X_data=combined.data,
        X_indices=combined.indices,
        X_indptr=combined.indptr,
        X_shape=np.asarray(combined.shape, dtype=np.int64),
        X_struct=dense,
        y=arrays["y"],
        groups=arrays["groups"],
        sha256=arrays["sha256"],
        vocab_size=np.asarray([vocab_size], dtype=np.int64),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Stage 1 feature matrices")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--vocab-out", type=Path, default=DEFAULT_VOCAB)
    parser.add_argument("--min-clusters", type=int, default=3)
    parser.add_argument("--seed", type=int, default=SEED)
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    rows, _missing_date = read_rows(data_root)
    if not rows:
        raise RuntimeError("no primary rows")
    carved, carved_count = load_carved(data_root)
    structure = load_structure(data_root)
    splits = read_splits(data_root)
    if not splits:
        raise RuntimeError("no split JSONs; run Tools/Splits/split.py first")

    train_rows = [row for row in rows if splits.get(row["sha256"]) == "train"]
    vocab, vocab_counts = build_vocab(train_rows, carved, args.min_clusters)
    arrays = build_arrays(rows, splits, carved, structure, vocab)

    args.out.mkdir(parents=True, exist_ok=True)
    for split in ("train", "val", "test"):
        mask = arrays["split"] == split
        subset = {
            "sha256": arrays["sha256"][mask],
            "presence": arrays["presence"][mask],
            "structural": arrays["structural"][mask],
            "y": arrays["y"][mask],
            "groups": arrays["groups"][mask],
            "split": arrays["split"][mask],
        }
        save_split(args.out / f"{split}.npz", subset, len(vocab))

    feature_names = vocab + list(STRUCTURAL_FEATURES)
    args.vocab_out.parent.mkdir(parents=True, exist_ok=True)
    args.vocab_out.write_text(json.dumps({
        "min_clusters": args.min_clusters,
        "train_clusters": len({row["cluster_id"] for row in train_rows}),
        "items": vocab_counts,
    }, indent=2, sort_keys=True), encoding="utf-8")
    (args.out / "feature_names.json").write_text(json.dumps({
        "feature_names": feature_names,
        "vocab_size": len(vocab),
        "structural_names": list(STRUCTURAL_FEATURES),
    }, indent=2), encoding="utf-8")
    metadata = {
        "rows": len(rows),
        "positives": int(arrays["y"].sum()),
        "clusters": len({row["cluster_id"] for row in rows}),
        "vocab_size": len(vocab),
        "seed": args.seed,
        "min_clusters": args.min_clusters,
        "carved_samples": carved_count,
        "splits": {
            split: {
                "rows": int((arrays["split"] == split).sum()),
                "positives": int(arrays["y"][arrays["split"] == split].sum()),
                "clusters": len({row["cluster_id"] for row in rows
                                 if splits.get(row["sha256"]) == split}),
            }
            for split in ("train", "val", "test")
        },
    }
    (args.out / "metadata.json").write_text(json.dumps(metadata, indent=2),
                                             encoding="utf-8")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

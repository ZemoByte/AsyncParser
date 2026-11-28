#!/usr/bin/env python3
"""Read-only CLI parity check on 30 known samples.

This does not modify data, labels, splits or gold. Samples are parsed
statically by the CLI; they are never executed.
"""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
from pathlib import Path

import joblib
import numpy as np
from scipy.sparse import csr_matrix

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools.Models import predict  # noqa: E402

DATA = ROOT / "Data"
SAMPLES = ROOT / "Samples"
HEADER = "CLI parity — diagnostic only; not a detector result"
TOOLS = ("TypeRef", "MemberRef", "AssemblyRef", "ImplMap", "ImportTable")
CLASS_DIRS = {"AsyncRAT.db": "AsyncRAT",
              "OtherMalwares.db": "OtherMalwares",
              "Benign.db": "Benign"}


def db_rows() -> list[dict]:
    conn = sqlite3.connect(f"file:{DATA / 'DataSet.db'}?mode=ro", uri=True)
    try:
        return [{"sha256": row[0], "status": row[1], "family": row[2],
                 "cluster": row[3], "split": row[4], "source": row[5],
                 "class_db": row[6],
                 "cluster_size": row[7]}
                for row in conn.execute(
                    "SELECT d.sha256, d.lbl_sts, d.sug_fam, d.cluster_id, "
                    "d.split, d.source, d.target_class_db, "
                    "(SELECT COUNT(*) FROM dataset x "
                    " WHERE x.cluster_id=d.cluster_id) "
                    "FROM dataset d")]
    finally:
        conn.close()


def sample_path(row: dict) -> Path | None:
    class_dir = CLASS_DIRS.get(row["class_db"])
    if class_dir:
        candidate = SAMPLES / class_dir / f"{row['sha256']}.exe"
        if candidate.is_file():
            return candidate
    for class_dir in CLASS_DIRS.values():
        candidate = SAMPLES / class_dir / f"{row['sha256']}.exe"
        if candidate.is_file():
            return candidate
        directory = SAMPLES / class_dir
        if not directory.is_dir():
            continue
        for possible in directory.iterdir():
            if possible.is_file() and predict.sha256_file(possible) == row["sha256"]:
                return possible
    return None


def cached_vector(row: dict, index: dict, tools: tuple) -> tuple[csr_matrix, int]:
    values = set()
    typeref = 0
    memberref = 0
    for tool in tools:
        path = None
        for class_dir in CLASS_DIRS.values():
            candidate = DATA / class_dir / tool / f"{row['sha256']}.json"
            if candidate.is_file():
                path = candidate
                break
        if path is None:
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        items = payload.get("fields", {}).get("values", [])
        if tool == "TypeRef":
            typeref = len(items)
        if tool == "MemberRef":
            memberref = len(items)
        values.update(str(item) for item in items)
    columns = sorted(index[value] for value in values if value in index)
    X = csr_matrix((np.ones(len(columns), dtype=np.float32),
                    (np.zeros(len(columns), dtype=np.int64), columns)),
                   shape=(1, len(index)))
    return X, typeref + memberref


def select_30(rows: list[dict]) -> list[dict]:
    async_rows = sorted((row for row in rows if row["status"] == "verified"),
                        key=lambda row: row["sha256"])
    big = "053fa0de75620861379f9dde8be711f1760f21e09701629d27cf6c3ce0d054e3"
    in_big = [row for row in async_rows if row["cluster"] == big][:5]
    out_big = []
    seen = set()
    for row in async_rows:
        if row["cluster"] == big or row["cluster"] in seen:
            continue
        seen.add(row["cluster"])
        out_big.append(row)
        if len(out_big) == 5:
            break
    benign = sorted((row for row in rows if row["status"] == "benign"),
                    key=lambda row: row["sha256"])
    primary = [row for row in benign
               if row["source"] != "clrheader2023"][:5]
    holdout = [row for row in benign
               if row["source"] == "clrheader2023"][:5]
    other = sorted((row for row in rows if row["status"] == "verified_other"),
                   key=lambda row: (row["family"], row["sha256"]))
    xworm = [row for row in other if row["family"] == "XWorm"][:5]
    others = [row for row in other if row["family"] != "XWorm"][:5]
    selected = in_big + out_big + primary + holdout + xworm + others
    if len(selected) != 30:
        raise RuntimeError(f"selected {len(selected)} samples, expected 30")
    return selected


def run_cli(path: Path) -> tuple[dict | None, str | None, int]:
    command = [sys.executable, str(ROOT / "Tools" / "Models" / "predict.py"),
               "--file", str(path), "--json"]
    proc = subprocess.run(command, text=True, capture_output=True)
    if proc.returncode not in (0, 1, 2):
        return None, f"unexpected exit {proc.returncode}", proc.returncode
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None, "CLI did not return JSON", proc.returncode
    return payload, None, proc.returncode


def main() -> int:
    rows = db_rows()
    selected = select_30(rows)
    artifact = joblib.load(DATA / "Models" / "capability.joblib")
    family = joblib.load(DATA / "Models" / "family_asyncrat_xworm.joblib")
    feature_info = json.loads((DATA / "Features" / "feature_names.json").read_text())
    names = feature_info["feature_names"][:feature_info["vocab_size"]]
    index = {name: position for position, name in enumerate(names)}
    references = predict.load_family_references()
    results = []
    summary = {"samples": 0, "matches": 0, "mismatches": 0,
               "abstentions": 0, "raw_parse_checked": 0,
               "parse_failures": 0}
    for row in selected:
        path = sample_path(row)
        sha8 = row["sha256"][:8]
        record = {"sha8": sha8, "class": row["status"],
                  "family": ("AsyncRAT" if row["status"] == "verified"
                             else (row["family"] or "Benign")),
                  "split": row["split"], "cluster": row["cluster"][:8],
                  "cluster_size": row["cluster_size"]}
        if path is None:
            record["parse_failure"] = "sample path not found"
            summary["parse_failures"] += 1
            results.append(record)
            continue
        payload, error, returncode = run_cli(path)
        record["returncode"] = returncode
        if error or payload is None:
            record["parse_failure"] = error or "no output"
            summary["parse_failures"] += 1
            results.append(record)
            continue
        summary["raw_parse_checked"] += 1
        cached_X, refs = cached_vector(row, index, TOOLS)
        record["typeref_memberref"] = refs
        record["above_abstain"] = refs >= int(artifact["abstain_threshold"])
        try:
            cli_X, cli_refs, _structure = predict.extract(path, artifact)
        except predict.Abstain as exc:
            record["abstain"] = str(exc)
            summary["abstentions"] += 1
            if payload["stage1"]["status"] != "abstain":
                record["mismatch"] = "CLI scored but raw extraction abstained"
                summary["mismatches"] += 1
            results.append(record)
            continue
        raw_difference = abs(cli_X - cached_X)
        record["feature_mismatches"] = int(raw_difference.nnz)
        if record["feature_mismatches"] == 0 and cli_refs == refs:
            summary["matches"] += 1
        else:
            record["mismatch"] = "feature vector mismatch"
            summary["mismatches"] += 1
        if payload["stage1"]["status"] == "scored":
            cached_score = float(artifact["model"].predict_proba(cached_X)[0, 1])
            cli_score = float(payload["stage1"]["score"])
            record["score_delta"] = abs(cached_score - cli_score)
            if record["score_delta"] > 1e-6:
                record["mismatch"] = "score mismatch"
                summary["mismatches"] += 1
        else:
            summary["abstentions"] += 1
        record["stage1"] = payload["stage1"].get("status")
        record["stage2"] = payload.get("stage2", {}).get("status")
        record["family_scope"] = payload.get("family_scope")
        if record["family"] in ("AsyncRAT", "XWorm"):
            if payload.get("stage2", {}).get("status") != "scored":
                record["stage2_mismatch"] = "expected eligible family score"
        elif record["family"] not in ("Benign",):
            if payload.get("stage2", {}).get("status") != "abstain":
                record["stage2_mismatch"] = "expected family abstain"
        results.append(record)
    summary["samples"] = len(selected)
    summary["matches"] = sum(
        1 for row in results
        if not row.get("parse_failure") and not row.get("abstain")
        and not row.get("mismatch") and not row.get("stage2_mismatch"))
    summary["mismatches"] = sum(
        1 for row in results
        if row.get("mismatch") or row.get("stage2_mismatch"))
    summary["abstentions"] = sum(1 for row in results if row.get("abstain"))
    summary["parse_failures"] = sum(1 for row in results
                                   if row.get("parse_failure"))
    result = {"header": HEADER, "summary": summary, "rows": results,
              "note": "sha8 only; no C2 or config values; static parsing only"}
    out = DATA / "Audit" / "cli_parity.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

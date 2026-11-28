#!/usr/bin/env python3
"""Static single-EXE diagnostic prototype.

NOT VALIDATED. Reads one file, never executes or uploads it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path

import dnfile
import joblib
import numpy as np
import pefile
import tlsh
from scipy.sparse import csr_matrix

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools.ImportTable.import_table import carve as carve_imports  # noqa: E402
from Tools.MemberRef.member_ref import carve as carve_memberref  # noqa: E402
from Tools.TypeRef.type_ref import carve as carve_typeref  # noqa: E402
from Tools.AssemblyRef.assembly_ref import carve as carve_assemblyref  # noqa: E402
from Tools.ImplMap.impl_map import carve as carve_implmap  # noqa: E402
from Tools.Structure.structure import carve as carve_structure  # noqa: E402

BANNER = ("NOT VALIDATED — dataset gate failed; research prototype; "
          "not a detector.")
DEFAULT_MODEL = ROOT / "Data" / "Models" / "capability.joblib"
DEFAULT_FAMILY = ROOT / "Data" / "Models" / "family_asyncrat_xworm.joblib"
FAMILY_REASON = ("only AsyncRAT vs XWorm is modeled; other families are not")
FAMILY_SCOPE = ("AsyncRAT", "XWorm")
FAMILY_DISTANCE = 100


class Abstain(Exception):
    """Raised when the prototype must abstain."""


class InputError(Exception):
    """Raised when the input cannot be read or scored."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_static(path: Path) -> None:
    data = path.read_bytes()
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except Exception as exc:
        raise Abstain(f"parse_failure: {exc}") from exc
    try:
        dn = dnfile.dnPE(str(path))
    except Exception as exc:
        raise Abstain(f"parse_failure: {exc}") from exc
    if dn.net is None or dn.net.mdtables is None:
        raise Abstain("rejected_non_dotnet")


def extract(path: Path, artifact: dict) -> tuple[csr_matrix, int, dict]:
    parse_static(path)
    values = set()
    typeref = carve_typeref(path)
    memberref = carve_memberref(path)
    values.update(typeref)
    values.update(memberref)
    values.update(carve_assemblyref(path))
    values.update(carve_implmap(path))
    values.update(carve_imports(path))
    structure = carve_structure(path)
    combined = len(typeref) + len(memberref)
    if combined < int(artifact["abstain_threshold"]):
        raise Abstain(
            f"too_few_typeref_memberref ({combined} < "
            f"{artifact['abstain_threshold']})")
    index = {name: position
             for position, name in enumerate(artifact["feature_names"])}
    columns = sorted(index[value] for value in values if value in index)
    X = csr_matrix(
        (np.ones(len(columns), dtype=np.float32),
         (np.zeros(len(columns), dtype=np.int64), columns)),
        shape=(1, int(artifact["vocab_size"])),
    )
    return X, combined, structure


def load_family_references(data_root: Path = ROOT / "Data") -> list[dict]:
    db = data_root / "DataSet.db"
    if not db.is_file():
        return []
    conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        families = {row[0]: ("AsyncRAT" if row[1] == "verified"
                             else (row[2] or ""))
                    for row in conn.execute(
                        "SELECT sha256, lbl_sts, sug_fam FROM dataset "
                        "WHERE lbl_sts IN ('verified','verified_other')")}
    finally:
        conn.close()
    references = []
    for path in (data_root / "Clusters").glob("*.json"):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        family = families.get(str(payload.get("sha256") or ""))
        digest = payload.get("fields", {}).get("tlsh")
        if family and digest:
            references.append({"sha256": str(payload["sha256"]),
                               "family": family, "tlsh": digest})
    return references


def nearest_reference(path: Path, references: list[dict]) -> dict | None:
    if not references:
        return None
    try:
        target = tlsh.hash(path.read_bytes())
    except Exception:
        return None
    best = None
    for reference in references:
        try:
            distance = tlsh.diff(target, reference["tlsh"])
        except Exception:
            continue
        if best is None or distance < best["distance"]:
            best = {"sha256": reference["sha256"],
                    "family": reference["family"], "distance": distance}
    return best


def family_eligible(reference: dict | None) -> bool:
    return (reference is not None
            and reference.get("family") in FAMILY_SCOPE
            and reference.get("distance") is not None
            and reference["distance"] <= FAMILY_DISTANCE)


def load_artifact(path: Path) -> dict:
    try:
        artifact = joblib.load(path)
    except (OSError, ValueError, EOFError) as exc:
        raise InputError(f"cannot load model {path}: {exc}") from exc
    if not isinstance(artifact, dict) or "model" not in artifact:
        raise InputError(f"invalid model artifact: {path}")
    return artifact


def family_stage(artifact: dict, X: csr_matrix) -> dict:
    model = artifact["model"]
    probabilities = model.predict_proba(X)[0]
    classes = list(artifact.get("classes") or [])
    by_name = {name: float(probabilities[index])
               for index, name in enumerate(classes)}
    predicted = classes[int(np.argmax(probabilities))]
    return {"status": "scored", "AsyncRAT": by_name.get("AsyncRAT"),
            "XWorm": by_name.get("XWorm"), "predicted": predicted,
            "note": "diagnostic, n=29"}


def evaluate(path: Path, artifact: dict, family_artifact: dict | None,
             references: list[dict] | None = None) -> dict:
    try:
        sha = sha256_file(path)
    except OSError as exc:
        raise InputError(f"read/hash failed: {exc}") from exc
    result = {"validated": False, "gate": "FAIL", "sha256": sha,
              "stage1": {"status": "abstain"}, "stage2": {"status": "abstain"},
              "abstain": None}
    try:
        X, combined, structure = extract(path, artifact)
    except Abstain as exc:
        result["stage1"] = {"status": "abstain", "reason": str(exc)}
        result["stage2"] = {"status": "abstain", "reason": "stage 1 abstained"}
        result["abstain"] = str(exc)
        result["references"] = None
        return result
    score = float(artifact["model"].predict_proba(X)[0, 1])
    threshold = float(artifact["threshold"])
    predicted = "RAT" if score >= threshold else "benign"
    result["stage1"] = {
        "status": "scored", "score": score, "threshold": threshold,
        "predicted": predicted,
    }
    result["references"] = {"typeref_memberref": combined,
                            "abstain_threshold": artifact["abstain_threshold"]}
    reference = nearest_reference(path, references or [])
    if reference:
        result["family_scope"] = {
            "nearest_family": reference["family"],
            "nearest_sha8": reference["sha256"][:8],
            "distance": reference["distance"],
        }
    if predicted != "RAT":
        result["stage2"] = {"status": "abstain", "reason": FAMILY_REASON}
    elif family_artifact is None:
        result["stage2"] = {"status": "abstain",
                            "reason": "family artifact not found"}
    elif not family_eligible(reference):
        result["stage2"] = {
            "status": "abstain",
            "reason": ("nearest known family is outside AsyncRAT/XWorm; "
                       "other families are not modeled"),
        }
    else:
        result["stage2"] = family_stage(family_artifact, X)
    return result


def render_text(result: dict) -> str:
    lines = [BANNER]
    stage1 = result["stage1"]
    if stage1["status"] == "scored":
        lines.append(f"stage1: score={stage1['score']:.6f} "
                     f"threshold={stage1['threshold']:.3f} "
                     f"predicted={stage1['predicted']}")
    else:
        lines.append(f"stage1: abstain ({stage1['reason']})")
    stage2 = result["stage2"]
    if stage2["status"] == "scored":
        lines.append(f"stage2: AsyncRAT={stage2['AsyncRAT']:.6f} "
                     f"XWorm={stage2['XWorm']:.6f} "
                     f"predicted={stage2['predicted']} "
                     f"({stage2['note']})")
    else:
        lines.append(f"family abstain: {stage2['reason']}")
    if result.get("abstain"):
        lines.append(f"abstain: {result['abstain']}")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Static diagnostic prototype")
    parser.add_argument("--file", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--model", type=Path, default=DEFAULT_MODEL)
    parser.add_argument("--family-model", type=Path, default=DEFAULT_FAMILY)
    args = parser.parse_args()
    try:
        artifact = load_artifact(args.model)
        family = (load_artifact(args.family_model)
                  if args.family_model.is_file() else None)
        references = load_family_references()
        result = evaluate(args.file, artifact, family, references)
    except (InputError, OSError) as exc:
        payload = {"banner": BANNER, "validated": False, "gate": "FAIL",
                   "sha256": None, "stage1": {"status": "error"},
                   "stage2": {"status": "error"}, "abstain": None,
                   "error": str(exc)}
        if args.json:
            print(json.dumps(payload, indent=2))
        else:
            print(BANNER)
            print(f"error: {exc}")
        return 1
    payload = {"banner": BANNER, **result}
    if args.json:
        print(json.dumps(payload, indent=2))
    else:
        print(render_text(result))
    return 0 if result["stage1"]["status"] == "scored" else 2


if __name__ == "__main__":
    raise SystemExit(main())

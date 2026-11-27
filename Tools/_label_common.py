#!/usr/bin/env python3
"""Shared label vocabulary and final-label loader.

One map lives here so the labeler, aggregator, clusterer and importer cannot
drift apart.  `load_final_label` returns the aggregated label when it exists,
merged over the parser label so downstream fields such as `is_dotnet` and
`config` survive.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "Data"

FAMILY_MAP = {
    "asyncrat": "AsyncRAT",
    "dcrat": "DcRat",
    "njrat": "NjRAT",
    "remcos": "Remcos",
    "quasarrat": "QuasarRAT",
    "venomrat": "VenomRAT",
    "xworm": "XWorm",
    "xenorat": "XenoRat",
    "othermalware": "OtherMalware",
    "benign": "Benign",
    "no match": "",
    "": "",
}

# Families that a voter may name.  OtherMalware and Benign are not family
# verdicts; benign rows are passed through by the aggregator.
FAMILY_VERDICTS = frozenset({
    "AsyncRAT", "DcRat", "NjRAT", "Remcos",
    "QuasarRAT", "VenomRAT", "XWorm", "XenoRat",
})

STRENGTHS = frozenset({"strong", "medium", "weak"})


def canonical_family(raw) -> str:
    """Map a raw parser/voter family string to the fixed vocabulary.

    Empty input maps to "" (no family).  Unknown values are rejected; the
    caller decides whether that is a parse error or a hard failure.
    """
    value = str(raw or "").strip()
    if not value:
        return ""
    canonical = FAMILY_MAP.get(value.lower())
    if canonical is None:
        raise RuntimeError(f"unknown suggested family: {value}")
    return canonical


def _read_envelope(path: Path, sha256: str) -> dict:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid JSON in {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"JSON in {path} is not an object")
    if str(payload.get("sha256") or "") != sha256:
        raise RuntimeError(f"sha256 mismatch in {path}")
    fields = payload.get("fields")
    if not isinstance(fields, dict):
        raise RuntimeError(f"missing fields object in {path}")
    return fields


def load_final_label(sha256: str, data_dir: Path | None = None) -> dict:
    """Return the final label fields for one sample.

    The aggregated label, when present, overrides the parser label field by
    field.  The merge is deliberate: the aggregator does not need to repeat
    `is_dotnet`, `config` or `obf_lvl`, and the clusterer still needs them.
    """
    base = Path(data_dir) if data_dir is not None else DATA_DIR
    label_path = base / "Labels" / f"{sha256}.json"
    aggregate_path = base / "Aggregated" / f"{sha256}.json"

    fields: dict = {}
    if label_path.is_file():
        fields.update(_read_envelope(label_path, sha256))
    if aggregate_path.is_file():
        fields.update(_read_envelope(aggregate_path, sha256))
    if not fields:
        raise RuntimeError(
            f"missing final label for {sha256}: looked for {label_path} and {aggregate_path}"
        )
    return fields

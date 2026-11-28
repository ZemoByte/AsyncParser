#!/usr/bin/env python3
"""Carve MemberRef (external method/field) references from .NET samples."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import dnfile

import json

from Tools._versions import CARVER_SCHEMA_VERSION  # noqa: E402
from Tools.Pipeline.reuse import can_reuse, output_version  # noqa: E402
from Tools._carver_common import is_dotnet, iter_samples, sha256_file, write_json, write_marker

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
KIND = "MemberRef"


def _type_name(row) -> str:
    if row is None:
        return ""
    if hasattr(row, "TypeNamespace") and hasattr(row, "TypeName"):
        namespace = str(getattr(row, "TypeNamespace", "") or "")
        name = str(getattr(row, "TypeName", "") or "")
        return f"{namespace}.{name}" if namespace else name
    if hasattr(row, "Name"):
        return str(getattr(row, "Name", "") or "")
    return ""


def carve(path: Path) -> list[str]:
    if not is_dotnet(path):
        return []
    try:
        pe = dnfile.dnPE(str(path))
    except Exception as exc:
        digest = sha256_file(path)
        sys.stderr.write(f"WARNING: {KIND} parse failed for {path} "
                         f"({digest}): {exc}\n")
        return []
    if pe.net is None or pe.net.mdtables is None:
        return []
    values = set()
    for item in pe.net.mdtables.MemberRef or []:
        class_row = getattr(getattr(item, "Class", None), "row", None)
        if class_row is None or type(class_row).__name__ not in {"TypeRefRow", "ModuleRefRow"}:
            continue
        type_name = _type_name(class_row)
        member_name = str(getattr(item, "Name", "") or "")
        if type_name and member_name:
            values.add(f"{type_name}::{member_name}")
    return sorted(values)


def main() -> int:
    parser = argparse.ArgumentParser(description="Carve MemberRef references")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--reuse", action="store_true")
    parser.add_argument("--refresh", action="store_true")
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    processed = 0
    reused = 0
    old_versions = set()
    classes = set()
    for class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        out_path = out_root / class_name / KIND / f"{sha256}.json"
        if args.reuse and not args.refresh and out_path.is_file():
            try:
                existing = json.loads(out_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                existing = None
            ok, _reason = can_reuse(existing, sha256, CARVER_SCHEMA_VERSION)
            if ok:
                reused += 1
                classes.add(class_name)
                continue
            if existing is not None:
                old_versions.add(str(output_version(existing)))
        values = carve(path)
        if values or is_dotnet(path):
            payload = {
                "schema_version": 1,
                "sha256": sha256,
                "kind": KIND,
                "producer": "member_ref",
                "fields": {"values": values,
                           "producer_version": CARVER_SCHEMA_VERSION},
            }
            write_json(out_path, payload)
            processed += 1
        classes.add(class_name)
    if old_versions:
        print(f"schema changed {sorted(old_versions)[0]}->{CARVER_SCHEMA_VERSION}: "
              f"reran {processed + reused} samples (not only new)")
    print(f"carved {processed} samples (reused {reused}) into {out_root}")
    for class_name in sorted(classes):
        write_marker(out_root / class_name / KIND)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

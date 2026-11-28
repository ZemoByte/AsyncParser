#!/usr/bin/env python3
"""Carve the native PE import table from .NET samples."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import dnfile
import pefile

import json

from Tools._versions import CARVER_SCHEMA_VERSION  # noqa: E402
from Tools.Pipeline.reuse import can_reuse, output_version  # noqa: E402
from Tools._carver_common import is_dotnet, iter_samples, sha256_file, write_json, write_marker

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
KIND = "ImportTable"


def carve(path: Path) -> list[str]:
    if not is_dotnet(path):
        return []
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
    except Exception as exc:
        digest = sha256_file(path)
        sys.stderr.write(f"WARNING: {KIND} PE parse failed for {path} "
                         f"({digest}): {exc}\n")
        return []
    values = set()
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
        dll = ""
        try:
            dll = entry.dll.decode("ascii", "replace").rstrip("\x00")
        except Exception:
            dll = str(entry.dll)
        for imp in getattr(entry, "imports", []) or []:
            name = ""
            if getattr(imp, "name", None):
                try:
                    name = imp.name.decode("ascii", "replace")
                except Exception:
                    name = str(imp.name)
            elif getattr(imp, "ordinal", None) is not None:
                name = f"ord_{imp.ordinal}"
            if dll and name:
                values.add(f"{dll}!{name}")
    try:
        pe.close()
    except Exception as exc:
        sys.stderr.write(f"WARNING: {KIND} close failed for {path}: {exc}\n")
    return sorted(values)


def main() -> int:
    parser = argparse.ArgumentParser(description="Carve ImplMap references")
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
                "producer": "import_table",
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

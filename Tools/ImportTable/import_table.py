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
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    processed = 0
    classes = set()
    for class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        values = carve(path)
        if values or is_dotnet(path):
            payload = {
                "schema_version": 1,
                "sha256": sha256,
                "kind": KIND,
                "producer": "import_table",
                "fields": {"values": values},
            }
            write_json(out_root / class_name / KIND / f"{sha256}.json", payload)
            processed += 1
        classes.add(class_name)
    for class_name in sorted(classes):
        write_marker(out_root / class_name / KIND)
    print(f"carved {processed} samples into {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

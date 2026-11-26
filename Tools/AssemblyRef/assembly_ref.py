#!/usr/bin/env python3
"""Carve AssemblyRef (external assembly) references from .NET samples."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import dnfile

from Tools._carver_common import is_dotnet, iter_samples, sha256_file, write_json, write_marker

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_OUT = ROOT / "Data"
KIND = "AssemblyRef"


def carve(path: Path) -> list[str]:
    if not is_dotnet(path):
        return []
    try:
        pe = dnfile.dnPE(str(path))
    except Exception:
        return []
    if pe.net is None or pe.net.mdtables is None:
        return []
    values = set()
    for item in pe.net.mdtables.AssemblyRef or []:
        name = str(getattr(item, "Name", "") or "")
        if name:
            values.add(name)
    return sorted(values)


def main() -> int:
    parser = argparse.ArgumentParser(description="Carve AssemblyRef references")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    out_root = args.out.resolve()
    processed = 0
    for class_name, path in iter_samples(samples_root):
        sha256 = sha256_file(path)
        values = carve(path)
        if values or is_dotnet(path):
            payload = {
                "schema_version": 1,
                "sha256": sha256,
                "kind": KIND,
                "producer": "assembly_ref",
                "fields": {"values": values},
            }
            write_json(out_root / class_name / KIND / f"{sha256}.json", payload)
            processed += 1
        write_marker(out_root / class_name / KIND)
    print(f"carved {processed} samples into {out_root}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

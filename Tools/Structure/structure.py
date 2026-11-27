#!/usr/bin/env python3
"""Static structural counts for .NET samples.

Writes Data/Structure/<sha256>.json. No sample is executed or loaded as code.
"""

from __future__ import annotations

import sys
from pathlib import Path

import dnfile
import pefile

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._carver_common import iter_samples, sha256_file, write_json, write_marker
from Tools._pe import is_dotnet

KIND = "Structure"


def _table_len(metadata, name: str) -> int:
    table = getattr(metadata, name, None)
    if table is None:
        return 0
    try:
        return len(table)
    except TypeError:
        return sum(1 for _ in table)


def _count_resources(node) -> int:
    entries = getattr(node, "entries", None)
    if not entries:
        return 0
    total = 0
    for entry in entries:
        directory = getattr(entry, "directory", None)
        if directory is not None:
            total += _count_resources(directory)
        if getattr(entry, "data", None) is not None:
            total += 1
    return total


def carve(path: Path) -> dict:
    fields = {
        "type_count": 0,
        "method_count": 0,
        "typeref_count": 0,
        "memberref_count": 0,
        "implmap_count": 0,
        "importtable_count": 0,
        "resource_count": 0,
        "section_count": 0,
        "file_size": path.stat().st_size,
        "entropy_max": 0.0,
        "entropy_mean": 0.0,
    }
    try:
        pe = dnfile.dnPE(str(path))
        metadata = getattr(getattr(pe, "net", None), "mdtables", None)
        if metadata is not None:
            fields["type_count"] = _table_len(metadata, "TypeDef")
            fields["method_count"] = _table_len(metadata, "MethodDef")
            fields["typeref_count"] = _table_len(metadata, "TypeRef")
            fields["memberref_count"] = _table_len(metadata, "MemberRef")
            fields["implmap_count"] = _table_len(metadata, "ImplMap")
    except Exception as exc:
        fields["parse_error"] = f"dnfile: {exc}"[:500]

    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        fields["section_count"] = len(pe.sections)
        entropies = [section.get_entropy() for section in pe.sections]
        if entropies:
            fields["entropy_max"] = round(max(entropies), 6)
            fields["entropy_mean"] = round(sum(entropies) / len(entropies), 6)
        fields["importtable_count"] = sum(
            len(entry.imports) for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
        )
        resource = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        fields["resource_count"] = _count_resources(resource) if resource else 0
    except Exception as exc:
        fields["pe_parse_error"] = f"pefile: {exc}"[:500]
    return fields


def main() -> int:
    out_root = ROOT / "Data"
    processed = 0
    for _class_name, path in iter_samples(ROOT / "Samples"):
        if not is_dotnet(path):
            continue
        sha256 = sha256_file(path)
        payload = {
            "schema_version": 1,
            "sha256": sha256,
            "kind": KIND,
            "producer": "structure",
            "fields": carve(path),
        }
        write_json(out_root / KIND / f"{sha256}.json", payload)
        processed += 1
    write_marker(out_root / KIND)
    print(f"structured {processed} .NET samples into {out_root / KIND}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

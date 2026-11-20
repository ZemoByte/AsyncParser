#!/usr/bin/env python3
"""Structured .NET assembly inventory via dnfile metadata tables.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/assembly_metadata.py <assembly>
"""

import argparse
import json
import sys
from pathlib import Path

import dnfile


def collect_metadata(pe_path: Path) -> dict:
    pe = dnfile.dnPE(str(pe_path))
    try:
        meta = {
            "filename": pe_path.name,
            "assemblyIdentity": None,
            "mvid": None,
            "referencedAssemblies": [],
            "typeInventory": [],
            "methodInventory": [],
            "moduleReferences": [],
            "pinvokeEntries": [],
            "customAttributeCount": 0,
        }

        if pe.net is None:
            meta["reason"] = "no CLR metadata"
            return meta

        md = pe.net.mdtables

        if md.Module and md.Module.rows:
            meta["mvid"] = str(md.Module.rows[0].Mvid)

        if md.Assembly and md.Assembly.rows:
            a = md.Assembly.rows[0]
            meta["assemblyIdentity"] = {
                "name": str(a.Name),
                "version": f"{a.MajorVersion}.{a.MinorVersion}."
                           f"{a.BuildNumber}.{a.RevisionNumber}",
            }

        if md.AssemblyRef:
            for ref in md.AssemblyRef.rows:
                meta["referencedAssemblies"].append({
                    "name": str(ref.Name),
                    "version": f"{ref.MajorVersion}.{ref.MinorVersion}."
                               f"{ref.BuildNumber}.{ref.RevisionNumber}",
                })

        if md.TypeDef:
            for t in md.TypeDef.rows:
                meta["typeInventory"].append({
                    "name": str(t.TypeName),
                    "namespace": str(t.TypeNamespace),
                })

        if md.MethodDef:
            for m in md.MethodDef.rows:
                meta["methodInventory"].append({"name": str(m.Name)})

        if md.ModuleRef:
            for mod in md.ModuleRef.rows:
                meta["moduleReferences"].append({"name": str(mod.Name)})

        if md.ImplMap:
            for impl in md.ImplMap.rows:
                dll = None
                if impl.ImportScope is not None and getattr(impl.ImportScope, "row", None):
                    dll = str(getattr(impl.ImportScope.row, "Name", None))
                method = None
                if impl.MemberForwarded is not None and getattr(impl.MemberForwarded, "row", None):
                    method = str(getattr(impl.MemberForwarded.row, "Name", None))
                meta["pinvokeEntries"].append({
                    "methodName": method,
                    "dllName": dll,
                    "importName": str(impl.ImportName) if impl.ImportName else None,
                })

        if md.CustomAttribute:
            meta["customAttributeCount"] = len(md.CustomAttribute.rows)

        return meta
    finally:
        pe.close()


def main():
    ap = argparse.ArgumentParser(description="Extract structured assembly metadata")
    ap.add_argument("sample", help="Path to .NET assembly/exe")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(collect_metadata(src), indent=2))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Obfuscator fingerprinting from dnfile metadata tables.

Looks at TypeRef/TypeDef names, CustomAttribute type names, and resource names.
Identifies common protectors (ConfuserEx, .NET Reactor, SmartAssembly, etc.).

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/protector_detect.py <assembly>
"""

import argparse
import json
import re
import sys
from pathlib import Path

import dnfile

OBFUSCATOR_PATTERNS = {
    "confuserex": {
        "names": [r"confuserex", r"confuser\."],
    },
    "dot_net_reactor": {
        "names": [r"reactor", r"\brt_"],
    },
    "smartassembly": {
        "names": [r"smartassembly", r"smartassembly\."],
    },
    "dotfuscator": {
        "names": [r"dotfuscator"],
    },
    "agile_dotnet": {
        "names": [r"agile\.net", r"agiledotnet"],
    },
}


def _match_obfuscators(text, evidence_list, detected):
    low = text.lower()
    evidence_list.append(text)
    for obf, patterns in OBFUSCATOR_PATTERNS.items():
        for pat in patterns["names"]:
            if re.search(pat, low):
                if obf not in detected:
                    detected.append(obf)


def detect_obfuscator(pe_path):
    pe = dnfile.dnPE(str(pe_path))
    try:
        evidence = {
            "type_names": [],
            "attribute_names": [],
            "resource_names": [],
            "detected_obfuscators": [],
        }
        detected = evidence["detected_obfuscators"]

        if pe.net is None:
            return {
                "filename": str(pe_path),
                "primary_obfuscator": "unknown",
                "all_detected": ["none"],
                "evidence": evidence,
                "reason": "no CLR metadata",
            }

        md = pe.net.mdtables
        if md.TypeDef:
            for row in md.TypeDef.rows:
                name = f"{row.TypeNamespace}.{row.TypeName}".strip(".")
                if name:
                    _match_obfuscators(name, evidence["type_names"], detected)
        if md.TypeRef:
            for row in md.TypeRef.rows:
                name = f"{row.TypeNamespace}.{row.TypeName}".strip(".")
                if name:
                    _match_obfuscators(name, evidence["type_names"], detected)
        if md.CustomAttribute:
            for row in md.CustomAttribute.rows:
                name = str(row.Type) if row.Type is not None else ""
                if name:
                    _match_obfuscators(name, evidence["attribute_names"], detected)
        if pe.net.resources:
            for res in pe.net.resources:
                name = str(res.name) if res.name else ""
                if name:
                    _match_obfuscators(name, evidence["resource_names"], detected)

        # Cap evidence lists for readable JSON
        for key in ("type_names", "attribute_names", "resource_names"):
            evidence[key] = evidence[key][:50]

        return {
            "filename": str(pe_path),
            "primary_obfuscator": detected[0] if detected else "unknown",
            "all_detected": detected if detected else ["none"],
            "evidence": evidence,
        }
    finally:
        pe.close()


def main():
    ap = argparse.ArgumentParser(description="Detect .NET obfuscator from metadata")
    ap.add_argument("sample", help="Path to .NET assembly/exe")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)

    print(json.dumps(detect_obfuscator(src), indent=2))


if __name__ == "__main__":
    main()

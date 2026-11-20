#!/usr/bin/env python3
"""Flag suspicious .NET / P/Invoke API names from metadata tables.

Usage:
  Tools/.venv/bin/python Tools/Static/DotNet/suspicious_api.py <assembly>
"""

import argparse
import json
import sys
from pathlib import Path

import dnfile

SUSPICIOUS_APIS = {
    "recon": {
        "weight": 3,
        "apis": ["GetSystemInfo", "GetUserName", "GetComputerName", "IsDebuggerPresent"],
    },
    "injection": {
        "weight": 10,
        "apis": ["WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
                 "NtMapViewOfSection", "RtlCreateUserThread"],
    },
    "persistence": {
        "weight": 5,
        "apis": ["RegSetValue", "CreateService", "SetWindowsHook"],
    },
    "crypto_network": {
        "weight": 2,
        "apis": ["InternetOpen", "HttpSendRequest", "CryptDecrypt", "PasswordDeriveBytes"],
    },
}


def _collect_names(pe):
    names = set()
    if pe.net is None:
        return names
    md = pe.net.mdtables
    if md.MethodDef:
        for row in md.MethodDef.rows:
            names.add(str(row.Name))
    if md.MemberRef:
        for row in md.MemberRef.rows:
            names.add(str(row.Name))
    if md.ImplMap:
        for row in md.ImplMap.rows:
            if row.ImportName:
                names.add(str(row.ImportName))
            if row.MemberForwarded is not None and getattr(row.MemberForwarded, "row", None):
                n = getattr(row.MemberForwarded.row, "Name", None)
                if n:
                    names.add(str(n))
    return names


def detect_suspicious_apis(pe_path):
    pe = dnfile.dnPE(str(pe_path))
    try:
        names = _collect_names(pe)
        found = []
        categories = []
        score = 0

        for category, data in SUSPICIOUS_APIS.items():
            matched = []
            for api in data["apis"]:
                for name in names:
                    if api.lower() in name.lower():
                        matched.append(api)
                        found.append({"api": api, "category": category, "matched": name})
                        score += data["weight"]
                        break
            if matched:
                categories.append(category)

        if score >= 20:
            risk = "critical"
        elif score >= 10:
            risk = "high"
        elif score >= 5:
            risk = "medium"
        else:
            risk = "low"

        return {
            "filename": str(pe_path),
            "risk_level": risk,
            "severity_score": score,
            "categories": categories,
            "found_apis": found,
            "name_count": len(names),
        }
    finally:
        pe.close()


def main():
    ap = argparse.ArgumentParser(description="Detect suspicious .NET/PInvoke APIs")
    ap.add_argument("sample", help="Path to .NET assembly/exe")
    args = ap.parse_args()

    src = Path(args.sample)
    if not src.is_file():
        print("ERROR: not a file", file=sys.stderr)
        sys.exit(1)

    result = detect_suspicious_apis(src)
    print(json.dumps(result, indent=2))
    if result["risk_level"] in ("critical", "high"):
        print(f"WARNING: {result['risk_level']} risk (score={result['severity_score']})")


if __name__ == "__main__":
    main()

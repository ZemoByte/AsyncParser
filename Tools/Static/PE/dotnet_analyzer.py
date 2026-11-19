#!/usr/bin/env python3
"""Static format gate & .NET analyzer: pefile + dnfile on one PE sample.

Usage:
  Tools/.venv/bin/python Tools/Static/PE/dotnet_analyzer.py <path_to_exe>

Output format states:
  - invalid        -> not a PE at all
  - native         -> valid PE, no CLR directory (native executable)
  - dotnet         -> valid PE with CLR directory, dnfile parsed OK
  - dotnet_parse_failed -> valid PE with CLR directory, but dnfile threw
"""

import sys
import os

try:
    import pefile
except ImportError:
    print("ERROR: pefile not installed. Run: Tools/.venv/bin/python -m pip install pefile")
    sys.exit(1)

try:
    import dnfile
except ImportError:
    print("ERROR: dnfile not installed. Run: Tools/.venv/bin/python -m pip install dnfile")
    sys.exit(1)


def analyze_pe(path):
    """Run pefile on the sample. Returns a dict of findings."""
    result = {"pe_valid": False, "machine": None, "has_clr": False,
              "sections": [], "imports": []}
    pe = None
    try:
        pe = pefile.PE(path)
        result["pe_valid"] = True
        result["machine"] = hex(pe.FILE_HEADER.Machine)
        try:
            clr_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]
            ]
            if clr_entry.VirtualAddress != 0 and clr_entry.Size != 0:
                result["has_clr"] = True
        except (AttributeError, IndexError, KeyError):
            pass
        for section in pe.sections:
            result["sections"].append({
                "name": section.Name.decode("utf-8", errors="replace").rstrip("\x00"),
                "size": section.SizeOfRawData,
                "entropy": round(section.get_entropy(), 2),
            })
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace") if entry.dll else "?"
                funcs = [imp.name.decode("utf-8", errors="replace") if imp.name else "ordinal"
                         for imp in entry.imports]
                result["imports"].append({"dll": dll, "functions": funcs})
    except Exception as e:
        result["error"] = str(e)
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass
    return result


def analyze_dotnet(path):
    """Run dnfile on the sample. Returns a dict of findings.

    Separates 'has CLR directory' (pefile) from 'dnfile parsed OK' (dnfile).
    """
    result = {"has_clr": False, "parse_ok": False, "assembly": None,
              "types": 0, "methods": 0}
    dotnet = None
    try:
        dotnet = dnfile.dnPE(path)
        if dotnet.net is not None:
            result["has_clr"] = True
            mdt = dotnet.net.mdtables
            if mdt.Assembly:
                for row in mdt.Assembly:
                    ver = f"{row.MajorVersion}.{row.MinorVersion}.{row.BuildNumber}.{row.RevisionNumber}"
                    result["assembly"] = {
                        "name": str(row.Name),
                        "version": ver,
                    }
                    break
            if mdt.TypeDef:
                result["types"] = len(mdt.TypeDef)
                method_count = 0
                for trow in mdt.TypeDef:
                    if trow.MethodList:
                        method_count += len(trow.MethodList)
                result["methods"] = method_count
            result["parse_ok"] = True
    except Exception as e:
        result["error"] = str(e)
    finally:
        if dotnet is not None:
            try:
                dotnet.close()
            except Exception:
                pass
    return result


def format_gate(path):
    """Combine pefile + dnfile into one format verdict.

    Returns a dict with a top-level 'format' key:
      - invalid
      - native
      - dotnet
      - dotnet_parse_failed
    """
    pe_info = analyze_pe(path)
    if not pe_info.get("pe_valid"):
        return {"format": "invalid", "pe": pe_info, "dotnet": None}
    dotnet_info = analyze_dotnet(path)
    clr_detected = pe_info.get("has_clr") or dotnet_info.get("has_clr")
    if not clr_detected:
        return {"format": "native", "pe": pe_info, "dotnet": dotnet_info}
    if not dotnet_info.get("parse_ok"):
        return {"format": "dotnet_parse_failed", "pe": pe_info, "dotnet": dotnet_info}
    return {"format": "dotnet", "pe": pe_info, "dotnet": dotnet_info}


def print_report(report, max_dlls=5, max_funcs=10):
    """Pretty-print the format_gate report."""
    pe = report["pe"]
    dotnet = report["dotnet"]
    fmt = report["format"]
    print(f"Format: {fmt}")
    print("=" * 60)
    print("\n--- pefile ---")
    if pe.get("error"):
        print(f"Error: {pe['error']}")
    else:
        print(f"Machine: {pe['machine']}")
        print(f"Has CLR directory: {pe.get('has_clr', False)}")
        print(f"Sections: {len(pe['sections'])}")
        for s in pe["sections"]:
            print(f"  {s['name']:<12} size={s['size']:>8}  entropy={s['entropy']}")
        print(f"Import DLLs: {len(pe['imports'])}")
        shown_dlls = pe["imports"][:max_dlls] if max_dlls > 0 else pe["imports"]
        for imp in shown_dlls:
            funcs = imp["functions"][:max_funcs] if max_funcs > 0 else imp["functions"]
            truncated = len(imp["functions"]) > max_funcs and max_funcs > 0
            suffix = " (truncated)" if truncated else ""
            print(f"  {imp['dll']}: {len(funcs)} funcs{suffix}")
    print("\n--- dnfile ---")
    if dotnet is None:
        print("Not run (not a valid PE).")
    elif dotnet.get("error"):
        print(f"Error: {dotnet['error']}")
    else:
        print(f"Has CLR: {dotnet['has_clr']}")
        print(f"Parse OK: {dotnet['parse_ok']}")
        print(f"Assembly: {dotnet['assembly']}")
        print(f"Types: {dotnet['types']}")
        print(f"Methods: {dotnet['methods']}")


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_exe>")
        sys.exit(1)
    path = sys.argv[1]
    if not os.path.isfile(path):
        print(f"ERROR: file not found: {path}")
        sys.exit(1)
    print(f"Analyzing: {path}")
    report = format_gate(path)
    print_report(report)


if __name__ == "__main__":
    main()

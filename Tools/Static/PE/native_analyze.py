#!/usr/bin/env python3
"""Analyze native (non-.NET) PE files and extract fingerprint features.

For each native PE, prints an analysis report to stdout.

The report contains features the LLM can read for family verdict:
  - PE header metadata (timestamp, linker, characteristics)
  - Section entropy & size stats (packed vs unpacked)
  - Imported DLLs & functions (API pattern)
  - Readable strings (potential config, C2, debug info)
  - UPX/packer detection
  - Resource type summary
  - YARA-like signature hints

Usage:
  Tools/.venv/bin/python Tools/Static/PE/native_analyze.py <path_to_exe>
  Or pipe a list of files: find Samples/ -name "*.exe" -print0 | xargs -0 -n1 Tools/.venv/bin/python Tools/Static/PE/native_analyze.py
"""

import sys
import os
import re
import hashlib
from collections import Counter

try:
    import pefile
except ImportError:
    print("ERROR: pefile not installed. Run: Tools/.venv/bin/python -m pip install pefile", file=sys.stderr)
    sys.exit(1)


# helpers

def sha256_of_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_upx_signature(pe):
    upx_sections = [s.Name.rstrip(b'\x00').decode('ascii', errors='replace').strip()
                     for s in pe.sections]
    return any('upx' in n.lower() for n in upx_sections)


def get_section_entropy(pe):
    entropies = []
    for s in pe.sections:
        try:
            entropies.append(round(s.get_entropy(), 2))
        except Exception:
            entropies.append(0.0)
    return entropies


# main analysis

def analyze_native_pe(exe_path):
    """Analyze a native PE file and return a dict of features."""
    sha = sha256_of_file(exe_path)
    pe = None
    try:
        pe = pefile.PE(exe_path)
    except Exception as e:
        return {"error": f"pefile read error: {e}", "sha": sha}

    try:
        report = {"sha": sha, "exe_path": exe_path}

        # PE header metadata
        try:
            pe_time = pe.FILE_HEADER.TimeDateStamp if hasattr(pe.FILE_HEADER, 'TimeDateStamp') else 0
            report["pe_timestamp"] = pe_time
            import datetime
            try:
                report["pe_timestamp_utc"] = datetime.datetime.fromtimestamp(
                    pe_time, tz=datetime.timezone.utc
                ).strftime("%Y-%m-%d %H:%M:%S UTC") if pe_time else "0"
            except Exception:
                report["pe_timestamp_utc"] = "0"
            report["pe_machine"] = hex(pe.FILE_HEADER.Machine) if pe.FILE_HEADER else "0"
            report["num_sections"] = pe.FILE_HEADER.NumberOfSections if pe.FILE_HEADER else 0
            chars = pe.FILE_HEADER.Characteristics if pe.FILE_HEADER else 0
            report["pe_characteristics"] = {
                "value": chars,
                "executable": bool(chars & 0x0002),
                "32bit": bool(chars & 0x0020),
                "dll": bool(chars & 0x2000),
            }
        except Exception as e:
            report["pe_header_error"] = str(e)

        # Section analysis
        sections = []
        section_entropies = get_section_entropy(pe)
        for i, s in enumerate(pe.sections):
            try:
                name = s.Name.rstrip(b'\x00').decode('ascii', errors='replace').strip() or "<unknown>"
                virt_size = s.Misc_VirtualSize
                raw_size = s.SizeOfRawData
                entropy = section_entropies[i] if i < len(section_entropies) else 0.0
                characteristics = ""
                if hasattr(s, 'Characteristics'):
                    c = s.Characteristics
                    chardetails = []
                    if c & 0x00000020: chardetails.append("MEM_EXECUTE")
                    if c & 0x00000040: chardetails.append("MEM_READ")
                    if c & 0x00000080: chardetails.append("MEM_WRITE")
                    characteristics = " | ".join(chardetails) if chardetails else "none"
                sections.append({
                    "name": name,
                    "virtual_size": virt_size,
                    "raw_size": raw_size,
                    "entropy": entropy,
                    "characteristics": characteristics,
                })
            except Exception:
                sections.append({"name": f"<err-{i}>", "virtual_size": 0, "raw_size": 0, "entropy": 0.0, "characteristics": "error"})

        report["sections"] = sections

        # UPX/packer detection
        report["upx_detected"] = find_upx_signature(pe)

        # Imported DLLs & functions
        imports = []
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.rstrip(b'\x00').decode('ascii', errors='replace') if entry.dll else "<unknown>"
                    funcs = [imp.name.rstrip(b'\x00').decode('ascii', errors='replace')
                             if imp and imp.name else f"ordinal_{imp.ordinal}" if imp and hasattr(imp, 'ordinal') else None
                             for imp in entry.imports] if hasattr(entry, 'imports') else []
                    funcs = [f for f in funcs if f]
                    imports.append({"dll": dll_name, "functions": funcs})
        except Exception as e:
            imports.append({"error": str(e)})

        report["imports"] = imports

        # Readable strings (early-exit when 50 meaningful strings found)
        meaningful = []
        try:
            with open(exe_path, "rb") as f:
                data = f.read()
            pattern = re.compile(rb'[ -~]{4,}')
            for m in pattern.finditer(data):
                s = m.group().decode('ascii', errors='replace').strip()
                if re.search(r'[a-zA-Z]', s):
                    meaningful.append(s)
                    if len(meaningful) >= 50:
                        break
            report["strings"] = meaningful
        except Exception as e:
            report["strings_error"] = str(e)

        # Resource summary
        resource_types = Counter()
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    try:
                        if resource_type.name is not None:
                            rtype = str(resource_type.name)
                        elif resource_type.id is not None:
                            rtype = pefile.RESOURCE_TYPE.get(resource_type.id, f"#{resource_type.id}")
                        else:
                            rtype = "<unknown>"
                        count = len(resource_type.directory.entries) if hasattr(resource_type, 'directory') else 1
                        resource_types[rtype] += count
                    except Exception:
                        continue
        except Exception:
            pass
        report["resource_types"] = dict(resource_types) if resource_types else {"none": 1}

        # Summary statistics
        import_count = sum(len(entry.get("functions", [])) for entry in report.get("imports", [{}]) if isinstance(entry, dict))
        report["imported_function_count"] = import_count
        section_entropies_vals = [s["entropy"] for s in report.get("sections", []) if isinstance(s, dict)]
        report["avg_section_entropy"] = round(sum(section_entropies_vals) / len(section_entropies_vals), 2) if section_entropies_vals else 0.0
        report["max_section_entropy"] = max(section_entropies_vals) if section_entropies_vals else 0.0

        return report
    finally:
        if pe is not None:
            try:
                pe.close()
            except Exception:
                pass

# output

def format_report(report):
    """Format the analysis report as readable text for the LLM."""
    lines = []
    lines.append("=" * 50)
    lines.append("NATIVE PE ANALYSIS REPORT")
    lines.append(f"SHA256: {report['sha']}")
    lines.append(f"FILE: {report.get('exe_path', 'N/A')}")
    lines.append("=" * 50)

    if "error" in report:
        lines.append(f"ERROR: {report['error']}")
        return "\n".join(lines)

    lines.append("\n--- PE HEADER ---")
    lines.append(f"Timestamp: {report.get('pe_timestamp', 'N/A')} ({report.get('pe_timestamp_utc', 'N/A')})")
    lines.append(f"Machine: {report.get('pe_machine', 'N/A')}")
    lines.append(f"Sections: {report.get('num_sections', 'N/A')}")
    chars = report.get("pe_characteristics", {})
    lines.append(f"Characteristics - Executable: {chars.get('executable', False)}, 32-bit: {chars.get('32bit', False)}, DLL: {chars.get('dll', False)}")

    lines.append("\n--- SECTIONS ---")
    for s in report.get("sections", []):
        lines.append(f"  [{s.get('name', '?')}] ent={s.get('entropy', 0):.2f} "
                     f"virt={s.get('virtual_size', 0):d} raw={s.get('raw_size', 0):d} "
                     f"chars={s.get('characteristics', '?')}")

    lines.append("\n--- IMPORTS ---")
    for imp in report.get("imports", []):
        if "error" in imp:
            lines.append(f"  DLL import error: {imp['error']}")
        else:
            dll = imp.get("dll", "?")
            funcs = imp.get("functions", [])
            if funcs:
                lines.append(f"  {dll}: {', '.join(funcs[:20])}" + (f" +{len(funcs)-20} more" if len(funcs) > 20 else ""))
            else:
                lines.append(f"  {dll}: (no imported functions listed)")

    lines.append(f"\n  Total imported functions: {report.get('imported_function_count', 0)}")

    lines.append("\n--- PACKER / UPX DETECTION ---")
    lines.append(f"UPX/packed: {report.get('upx_detected', False)}")

    lines.append("\n--- SECTION ENTROPY SUMMARY ---")
    avg = report.get("avg_section_entropy", 0.0)
    mx = report.get("max_section_entropy", 0.0)
    lines.append(f"Average entropy: {avg:.2f}  (high > 6.5 suggests packing/obfuscation)")
    lines.append(f"Max entropy:     {mx:.2f}")

    lines.append("\n--- RESOURCES ---")
    for rtype, count in report.get("resource_types", {}).items():
        lines.append(f"  {rtype}: {count} entry{'s' if count != 1 else ''}")

    lines.append("\n--- TOP READABLE STRINGS (min 4 chars) ---")
    for s in report.get("strings", [])[:30]:
        lines.append(f"  {s}")

    lines.append("\n--- FAMILY HINTS ---")
    hints = []
    if report.get("upx_detected"):
        hints.append("Possible UPX packing (common packer, may need unpacking)")
    if avg > 6.5:
        hints.append("High section entropy — possible packing or encrypted payload")
    if mx > 7.5:
        hints.append("Very high entropy section — likely packed or encrypted")
    imported_dlls = [imp.get("dll", "").lower() for imp in report.get("imports", []) if "error" not in imp]
    dll_text = " ".join(imported_dlls)
    all_funcs = [
        f.lower() for imp in report.get("imports", []) if "error" not in imp
        for f in imp.get("functions", [])
    ]
    func_text = " ".join(all_funcs)
    if "ws2_32" in dll_text or "winhttp" in dll_text or "wininet" in dll_text:
        hints.append("Network-related imports (Winsock/WinHTTP) — C2 or data exfil possible")
    if "kernel32" in dll_text and "advapi32" in dll_text:
        hints.append("Registry/Service API usage — possible persistence")
    if "loadlibrary" in func_text or "getprocaddress" in func_text:
        hints.append("Dynamic API loading — possible shellcode or reflective loading")
    if not hints:
        hints.append("No strong family-specific patterns detected; classify via LLM with cleaned core")
    for h in hints:
        lines.append(f"  - {h}")

    lines.append("\n" + "=" * 50)
    return "\n".join(lines)


def main():
    if len(sys.argv) < 2:
        print("Usage: python Tools/Static/PE/native_analyze.py <path_to_exe>", file=sys.stderr)
        sys.exit(1)

    exe_path = sys.argv[1]
    if not os.path.isfile(exe_path):
        print(f"ERROR: not a file: {exe_path}", file=sys.stderr)
        sys.exit(1)

    report = analyze_native_pe(exe_path)
    print(format_report(report))


if __name__ == "__main__":
    main()

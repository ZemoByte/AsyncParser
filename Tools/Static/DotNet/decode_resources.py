#!/usr/bin/env python3
"""decode_resources.py - real .NET resource decoding using dnfile ResourceSet."""
import json
import sys
import re
from pathlib import Path
import dnfile
from dotnet_common import artifacts_dir, record, safe_name, sha256_of_file


def _decode_serialized_data(data):
    if not data:
        return None
    try:
        if len(data) >= 8:
            length = int.from_bytes(data[:4], "little")
            if 0 < length < len(data) - 4:
                text_utf16 = data[4 : 4 + length * 2]
                try:
                    text = text_utf16.decode("utf-16-le", errors="replace")
                    if any(c.isprintable() for c in text[:20]) or text.strip():
                        return text.strip()
                except Exception:
                    pass
                text_utf8 = data[4 : 4 + length]
                try:
                    text = text_utf8.decode("utf-8", errors="replace")
                    if any(c.isprintable() for c in text[:20]) or text.strip():
                        return text.strip()
                except Exception:
                    pass
    except (ValueError, IndexError):
        pass
    try:
        matches = re.findall(rb"[ -~]{4,}", data)
        if matches:
            best = max(matches, key=len)
            return best.decode("ascii", errors="replace")
    except Exception:
        pass
    return None


def decode_resource_entry(entry_data, entry_name, res_name):
    result = {
        "name": f"{res_name}/{entry_name}",
        "decoded": False,
        "data": None,
        "type": "raw",
    }
    decoded = _decode_serialized_data(entry_data)
    if decoded is not None:
        result["decoded"] = True
        result["data"] = decoded
        result["type"] = "serialized_string"
        return result
    if entry_data and isinstance(entry_data, (bytes, bytearray)):
        result["data"] = entry_data
        result["type"] = "raw_binary"
    return result


def process_resources(pe_path, out_dir):
    import hashlib
    sha = hashlib.sha256(pe_path.read_bytes()).hexdigest()
    out_dir = out_dir / safe_name(sha)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest = []
    artifacts = []

    pe = dnfile.dnPE(str(pe_path))
    try:
        resources = pe.net.resources if pe.net else []
        for i, res in enumerate(resources):
            res_name = str(res.name) or f"resource_{i}"
            res_data = getattr(res, "data", None)
            if res_data is not None:
                entries = getattr(res_data, "entries", []) or []
            else:
                entries = []
            if not entries:
                manifest.append({"name": f"{res_name}: no entries", "decoded": False, "size": 0})
                continue
            for entry in entries:
                entry_name = getattr(entry, "name", f"entry_{i}")
                entry_data = getattr(entry, "data", None) or getattr(entry, "value", None)
                if entry_data is None:
                    manifest.append({"name": f"{res_name}/{entry_name}", "decoded": False, "size": 0, "reason": "no data"})
                    continue
                decoded = decode_resource_entry(entry_data, entry_name, res_name)
                if decoded["decoded"] and isinstance(decoded["data"], str):
                    out_path = out_dir / f"{safe_name(res_name)}__{safe_name(entry_name)}.txt"
                    out_path.write_text(decoded["data"], encoding="utf-8")
                    artifacts.append(out_path)
                    manifest.append(
                        {"name": f"{res_name}/{entry_name}", "decoded": True, "size": len(decoded["data"]), "type": "serialized_string", "file": out_path.name}
                    )
                elif decoded["type"] == "raw_binary":
                    out_path = out_dir / f"{safe_name(res_name)}__{safe_name(entry_name)}.bin"
                    out_path.write_bytes(decoded["data"])
                    artifacts.append(out_path)
                    manifest.append(
                        {"name": f"{res_name}/{entry_name}", "decoded": False, "size": len(decoded["data"]), "type": "raw_binary", "file": out_path.name}
                    )
                else:
                    manifest.append(
                        {"name": f"{res_name}/{entry_name}", "decoded": False, "size": len(entry_data) if entry_data else 0, "reason": "no readable content"}
                    )
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        record(sha, "resources", "ok", tool="decode_resources", artifacts=artifacts, reason=f"processed {len(resources)} resource set(s)")
        print(f"OK: {len(artifacts)} artifact(s), {len(manifest)} entry(ies) in manifest")
        return manifest
    finally:
        pe.close()


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Decode .NET resources using dnfile ResourceSet")
    ap.add_argument("sample", help="Path to .NET assembly/exe")
    ap.add_argument("--output", "-o", default="Cleaned", help="Output directory base (default: Cleaned)")
    args = ap.parse_args()
    src = Path(args.sample)
    if not src.is_file():
        print(f"ERROR: not a file: {src}", file=sys.stderr)
        sys.exit(1)
    out_dir = Path(args.output)
    process_resources(src, out_dir)


if __name__ == "__main__":
    main()
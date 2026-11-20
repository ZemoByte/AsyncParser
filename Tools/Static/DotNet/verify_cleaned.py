#!/usr/bin/env python3
"""verify_cleaned.py - verify cleaned output integrity."""
import json
import argparse
import sys
from pathlib import Path


def verify_manifest(manifest_path):
    """Verify the manifest.json from a cleaned output directory."""
    errors = []
    warnings = []

    if not manifest_path.exists():
        return {"valid": False, "errors": ["manifest.json not found: " + str(manifest_path)]}

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, Exception) as e:
        return {"valid": False, "errors": ["manifest.json is not valid JSON: " + str(e)]}

    if not isinstance(manifest, list):
        errors.append("manifest.json is not a list of entries")
        return {"valid": False, "errors": errors}

    artifact_files = set()
    decoded_count = 0
    raw_count = 0

    for i, entry in enumerate(manifest):
        if "name" not in entry:
            errors.append("Entry " + str(i) + ": missing 'name' field")
            continue
        if "type" not in entry:
            errors.append("Entry " + str(i) + ": missing 'type' field for '" + entry.get("name", "unknown") + "'")
            continue

        entry_type = entry["type"]
        if entry_type == "serialized_string":
            decoded_count += 1
            name = entry["name"]
            if "__" in name:
                parts = name.rsplit("__", 1)
                expected_file = parts[1]
                if not expected_file.endswith(".txt"):
                    expected_file += ".txt"
            else:
                expected_file = name + ".txt"

            manifest_dir = manifest_path.parent
            art_path = manifest_dir / expected_file
            if not art_path.exists():
                art_path = manifest_dir / name
                if not art_path.exists():
                    errors.append("Entry " + str(i) + ": decoded entry '" + name + "' missing artifact file")

        elif entry_type == "raw_binary":
            raw_count += 1
            name = entry["name"]
            if "__" in name:
                parts = name.rsplit("__", 1)
                expected_file = parts[1]
                if not expected_file.endswith(".bin"):
                    expected_file += ".bin"
            else:
                expected_file = name + ".bin"

            manifest_dir = manifest_path.parent
            art_path = manifest_dir / expected_file
            if not art_path.exists():
                art_path = manifest_dir / name
                if not art_path.exists():
                    errors.append("Entry " + str(i) + ": raw binary entry '" + name + "' missing artifact file")

        else:
            warnings.append("Entry " + str(i) + ": unknown type '" + entry_type + "' for '" + entry.get("name", "unknown") + "'")

        if "name" in entry:
            artifact_files.add(entry["name"])

    # Check for files on disk that aren't in the manifest
    manifest_dir = manifest_path.parent
    if manifest_dir.is_dir():
        actual_files = set(f.name for f in manifest_dir.iterdir() if f.is_file())
        missing_from_manifest = actual_files - artifact_files - {"manifest.json"}
        if missing_from_manifest:
            warnings.append("Files in output dir not in manifest: " + str(missing_from_manifest))

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "stats": {"decoded": decoded_count, "raw": raw_count, "total": len(manifest)}}


def main():
    ap = argparse.ArgumentParser(description="Verify cleaned output integrity")
    ap.add_argument("output_dir", help="Path to cleaned output directory")
    args = ap.parse_args()

    src = Path(args.output_dir)
    if not src.is_dir():
        print("ERROR: not a directory: " + str(src), file=sys.stderr)
        sys.exit(1)

    manifest_path = src / "manifest.json"
    result = verify_manifest(manifest_path)

    print("Verifying: " + str(src))
    print("Manifest valid: " + str(result["valid"]))

    if result["errors"]:
        print("\nErrors (" + str(len(result["errors"])) + "):")
        for e in result["errors"]:
            print("  - " + e)

    if result["warnings"]:
        print("\nWarnings (" + str(len(result["warnings"])) + "):")
        for w in result["warnings"]:
            print("  - " + w)

    stats = result.get("stats", {})
    print("\nStats: " + str(stats["total"]) + " total entries (" + str(stats["decoded"]) + " decoded, " + str(stats["raw"]) + " raw)")

    if result["valid"]:
        print("\nVerification PASSED: cleaned output is intact.")
        sys.exit(0)
    else:
        print("\nVerification FAILED: issues found with cleaned output.")
        sys.exit(1)


if __name__ == "__main__":
    main()
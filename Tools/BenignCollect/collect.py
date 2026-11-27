#!/usr/bin/env python3
"""Collect benign .NET PE files from public package archives.

Static only: archives are unzipped in memory and PE headers are parsed.
Nothing is executed, loaded or imported. Files are written only under
Samples/Benign/ and Data/BenignSources.csv.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._pe import is_dotnet_bytes  # noqa: E402

DEFAULT_STAGING = Path("/tmp/opencode/benign_staging")
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_CSV = ROOT / "Data" / "BenignSources.csv"
DOTNET_SDK_URL = "https://aka.ms/dotnet/8.0/dotnet-sdk-win-x64.zip"
NUGET_PACKAGES = (
    "newtonsoft.json", "serilog", "dapper", "automapper", "nlog",
    "restsharp", "polly", "mediatr", "fluentvalidation", "system.text.json",
    "microsoft.net.compilers.toolset", "microsoft.build", "nuget.commandline",
    "nunit.consolerunner", "xunit.runner.console", "reportgenerator",
    "gitversion.tool", "cake.tool", "dotnet-ef", "dotnet-format",
)
CHOCO_PACKAGES = (
    "ilspy", "dnspy", "dnspyex", "nuget.commandline", "nugetpackageexplorer",
    "fiddler", "linqpad", "paint.net", "keepass", "sharex", "greenshot",
    "screentogif", "screenpresso", "dotnetcore-sdk", "dotnet-sdk",
    "msbuild", "nunit-console", "nunit.consolerunner", "specflow", "cake",
    "fake", "paket", "gitversion", "gitversion.portable", "ilmerge",
    "costura", "confuserex", "de4dot", "dotpeek", "reportgenerator",
    "coverlet.console", "opencover", "vswhere", "wix",
)
GITHUB_REPOS = (
    "icsharpcode/ILSpy",
    "dnSpy/dnSpy",
    "ShareX/ShareX",
    "NickeManarin/ScreenToGif",
    "files-community/Files",
    "rocksdanister/lively",
    "DevToys-app/DevToys",
    "git-tfs/git-tfs",
    "GitTools/GitVersion",
    "cake-build/cake",
    "nunit/nunit-console",
    "dotnet/format",
    "dotnet/interactive",
    "microsoft/msbuild",
    "gitextensions/gitextensions",
)
USER_AGENT = "AsyncParser-benign-collector/1.0"
MAX_CANDIDATE_BYTES = 50 * 1024 * 1024
MAX_ARCHIVE_BYTES = 300 * 1024 * 1024
CSV_COLUMNS = ("sha256", "source", "origin", "ext", "url", "license",
               "size", "collected_at", "status")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str, dest: Path, timeout: int = 120) -> Path:
    if dest.is_file() and dest.stat().st_size > 0:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    temporary = dest.with_suffix(dest.suffix + ".part")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            with temporary.open("wb") as handle:
                while True:
                    chunk = response.read(1 << 20)
                    if not chunk:
                        break
                    handle.write(chunk)
        os.replace(temporary, dest)
    finally:
        if temporary.is_file():
            temporary.unlink()
    return dest


def _kind_matches(ext: str, kind: str) -> bool:
    return kind == "any" or ext == f".{kind}"


def iter_zip_candidates(archive_path: Path, source: str, url: str,
                        license_name: str, origin: str, kind: str,
                        min_size: int, stats: Counter | None = None) -> list[dict]:
    candidates = []
    if stats is None:
        stats = Counter()
    with zipfile.ZipFile(archive_path) as archive:
        for entry in archive.infolist():
            if entry.is_dir():
                stats["archive_dir"] += 1
                continue
            ext = Path(entry.filename).suffix.lower()
            if ext not in (".exe", ".dll"):
                stats["wrong_kind"] += 1
                continue
            if not _kind_matches(ext, kind):
                stats["wrong_kind"] += 1
                continue
            if entry.file_size < min_size:
                stats["too_small"] += 1
                continue
            if entry.file_size > MAX_CANDIDATE_BYTES:
                stats["too_large"] += 1
                continue
            with archive.open(entry) as handle:
                data = handle.read()
            if data[:2] != b"MZ":
                stats["not_mz"] += 1
                continue
            if not is_dotnet_bytes(data):
                stats["not_dotnet"] += 1
                continue
            candidates.append({
                "name": entry.filename,
                "ext": ext,
                "data": data,
                "sha256": sha256_bytes(data),
                "size": len(data),
                "source": source,
                "origin": origin,
                "url": url,
                "license": license_name,
            })
    return candidates


def iter_dir_candidates(directory: Path, source: str, url: str,
                        license_name: str, origin: str, kind: str,
                        min_size: int, stats: Counter | None = None) -> list[dict]:
    candidates = []
    if stats is None:
        stats = Counter()
    for path in sorted(directory.rglob("*")):
        if not path.is_file():
            continue
        ext = path.suffix.lower()
        if ext not in (".exe", ".dll"):
            stats["wrong_kind"] += 1
            continue
        if not _kind_matches(ext, kind):
            stats["wrong_kind"] += 1
            continue
        size = path.stat().st_size
        if size < min_size:
            stats["too_small"] += 1
            continue
        if size > MAX_CANDIDATE_BYTES:
            stats["too_large"] += 1
            continue
        data = path.read_bytes()
        if data[:2] != b"MZ":
            stats["not_mz"] += 1
            continue
        if not is_dotnet_bytes(data):
            stats["not_dotnet"] += 1
            continue
        candidates.append({
            "name": path.name,
            "ext": ext,
            "data": data,
            "sha256": sha256_bytes(data),
            "size": len(data),
            "source": source,
            "origin": origin,
            "url": url,
            "license": license_name,
        })
    return candidates


def existing_hashes(samples_root: Path) -> set[str]:
    hashes = set()
    if not samples_root.is_dir():
        return hashes
    for path in samples_root.rglob("*"):
        if not path.is_file():
            continue
        hasher = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                hasher.update(chunk)
        hashes.add(hasher.hexdigest())
    return hashes


def dedupe_candidates(candidates: list[dict], existing: set[str]) -> tuple[list[dict], int, int]:
    seen = set(existing)
    unique = []
    duplicate = 0
    for candidate in candidates:
        if candidate["sha256"] in seen:
            duplicate += 1
            continue
        seen.add(candidate["sha256"])
        unique.append(candidate)
    return unique, duplicate, len(existing)


def select_candidates(candidates: list[dict], limit: int = 0) -> list[dict]:
    ordered = sorted(
        candidates,
        key=lambda item: (
            not item["name"].lower().endswith(".exe"),
            item["size"] < 100_000,
            -item["size"],
            item["name"],
        ),
    )
    return ordered[:limit] if limit else ordered


def _infer_ext(samples_root: Path | None, sha256: str) -> str:
    if samples_root is None:
        return ""
    matches = list((samples_root / "Benign").glob(f"{sha256}.*"))
    return matches[0].suffix.lower() if matches else ""


def append_sources_csv(path: Path, rows: list[dict],
                       samples_root: Path | None = None) -> int:
    if not path.parent.is_dir():
        path.parent.mkdir(parents=True, exist_ok=True)
    existing_rows = []
    existing_fields = []
    if path.is_file():
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            existing_fields = reader.fieldnames or []
            existing_rows = list(reader)

    need_migration = bool(existing_rows) and existing_fields != list(CSV_COLUMNS)
    if need_migration:
        for row in existing_rows:
            row["origin"] = row.get("origin") or row.get("source") or "unknown"
            row["ext"] = row.get("ext") or _infer_ext(samples_root, row.get("sha256", ""))
            row["status"] = row.get("status") or "active"
        existing_rows = [{key: row.get(key, "") for key in CSV_COLUMNS}
                         for row in existing_rows]

    existing_shas = {row.get("sha256") for row in existing_rows}
    new_rows = [{key: row.get(key, "") for key in CSV_COLUMNS}
                for row in rows if row["sha256"] not in existing_shas]
    if not new_rows and not need_migration:
        return 0

    all_rows = existing_rows + new_rows
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(all_rows)
    os.replace(temporary, path)
    return len(new_rows)


def latest_nuget_version(package_id: str, timeout: int = 60) -> str:
    url = f"https://api.nuget.org/v3-flatcontainer/{package_id}/index.json"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        payload = json.loads(response.read())
    versions = [v for v in payload.get("versions", []) if "-" not in v]
    if not versions:
        raise RuntimeError(f"no stable version for NuGet package {package_id}")
    return versions[-1]


def _github_assets(repo: str, timeout: int) -> list[tuple[str, str, int]]:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
    })
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read())
    except urllib.error.HTTPError as exc:
        print(f"WARNING: github {repo} release lookup failed: {exc.code}")
        return []
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"WARNING: github {repo} release lookup failed: {exc}")
        return []
    assets = []
    for asset in payload.get("assets", []):
        name = str(asset.get("name") or "")
        url = str(asset.get("browser_download_url") or "")
        size = int(asset.get("size") or 0)
        if name.lower().endswith((".zip", ".exe")) and url:
            assets.append((name, url, size))
    return assets


def _pick_github_asset(assets: list[tuple[str, str, int]]) -> tuple[str, str, int] | None:
    for name, url, size in assets:
        lowered = name.lower()
        if any(tag in lowered for tag in ("win-x64", "win64", "windows", "win")) \
                and size <= MAX_ARCHIVE_BYTES:
            return name, url, size
    for name, url, size in assets:
        if name.lower().endswith(".zip") and size <= MAX_ARCHIVE_BYTES:
            return name, url, size
    return None


def source_archives(source: str, staging: Path, timeout: int) -> list[tuple[Path, str, str, str]]:
    """Return (archive path, url, license, origin)."""
    if source == "dotnet-sdk":
        dest = staging / "dotnet-sdk-win-x64.zip"
        return [(download(DOTNET_SDK_URL, dest, timeout), DOTNET_SDK_URL,
                 "MIT", "dotnet-sdk")]
    if source == "nuget":
        archives = []
        for package_id in NUGET_PACKAGES:
            try:
                version = latest_nuget_version(package_id, timeout)
                url = (f"https://api.nuget.org/v3-flatcontainer/{package_id}/"
                       f"{version}/{package_id}.{version}.nupkg")
                dest = staging / f"{package_id}.{version}.nupkg"
                archives.append((download(url, dest, timeout), url,
                                 "package-license", "nuget"))
            except (urllib.error.HTTPError, urllib.error.URLError, RuntimeError,
                    TimeoutError) as exc:
                print(f"WARNING: nuget {package_id} failed: {exc}")
        return archives
    if source == "chocolatey":
        archives = []
        for package_id in CHOCO_PACKAGES:
            url = f"https://community.chocolatey.org/api/v2/package/{package_id}"
            dest = staging / f"choco_{package_id}.nupkg"
            try:
                archives.append((download(url, dest, timeout), url,
                                 "package-license", "chocolatey"))
            except urllib.error.HTTPError as exc:
                print(f"WARNING: chocolatey {package_id} failed: {exc.code}")
        return archives
    if source == "github":
        archives = []
        for repo in GITHUB_REPOS:
            picked = _pick_github_asset(_github_assets(repo, timeout))
            if picked is None:
                print(f"WARNING: github {repo} has no suitable release asset")
                continue
            name, url, _size = picked
            dest = staging / f"github_{repo.replace('/', '_')}_{name}"
            try:
                archives.append((download(url, dest, timeout), url,
                                 "release-license", "github"))
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
                print(f"WARNING: github {repo} download failed: {exc}")
        return archives
    raise RuntimeError(f"unsupported source: {source}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Collect benign .NET PE files")
    parser.add_argument("--source", required=True,
                        choices=("dotnet-sdk", "nuget", "chocolatey", "github",
                                 "dike", "clrheader2023"))
    parser.add_argument("--kind", choices=("exe", "dll", "any"), default="exe")
    parser.add_argument("--min-size", type=int, default=100_000)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--staging", type=Path, default=DEFAULT_STAGING)
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out-csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--dike-dir", type=Path, default=None,
                        help="DikeDataset root; only files/benign is read")
    parser.add_argument("--github-dir", type=Path, default=None,
                        help="local GitHub dataset directory (origin=github)")
    parser.add_argument("--clrheader-dir", type=Path, default=None,
                        help="Hassan 2023 CLR-header repository root")
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    staging = args.staging.resolve()
    samples_root = args.samples_root.resolve()
    staging.mkdir(parents=True, exist_ok=True)
    stats: Counter = Counter()

    if args.source == "dike":
        if args.dike_dir is None:
            raise RuntimeError("--source dike requires --dike-dir")
        benign_dir = args.dike_dir.resolve() / "files" / "benign"
        if not benign_dir.is_dir():
            benign_dir = args.dike_dir.resolve() / "benign"
        if not benign_dir.is_dir():
            raise RuntimeError(f"no benign folder under {args.dike_dir}")
        candidates = iter_dir_candidates(
            benign_dir, "dike", str(benign_dir), "CC-BY-4.0", "dike",
            args.kind, args.min_size, stats)
        total_entries = len(candidates)
    elif args.source == "github" and args.github_dir is not None:
        github_dir = args.github_dir.resolve()
        if not github_dir.is_dir():
            raise RuntimeError(f"github dataset directory not found: {github_dir}")
        candidates = iter_dir_candidates(
            github_dir, "github", str(github_dir), "dataset-license", "github",
            args.kind, args.min_size, stats)
        total_entries = len(candidates)
    elif args.source == "clrheader2023":
        if args.clrheader_dir is None:
            raise RuntimeError("--source clrheader2023 requires --clrheader-dir")
        benign_dir = args.clrheader_dir.resolve() / "Benign" / "Benign exe"
        if not benign_dir.is_dir():
            raise RuntimeError(f"no Hassan benign folder under {args.clrheader_dir}")
        candidates = iter_dir_candidates(
            benign_dir, "clrheader2023", str(benign_dir),
            "research use only; cite Hassan et al. 2023; do not redistribute",
            "github", args.kind, args.min_size, stats)
        total_entries = len(candidates)
    else:
        candidates = []
        total_entries = 0
        for archive_path, url, license_name, origin in source_archives(
                args.source, staging, args.timeout):
            print(f"archive: {archive_path.name} ({archive_path.stat().st_size} bytes)")
            entries = iter_zip_candidates(
                archive_path, args.source, url, license_name, origin,
                args.kind, args.min_size, stats)
            print(f"  .NET {args.kind} candidates: {len(entries)}")
            candidates.extend(entries)
            total_entries += len(entries)

    existing = existing_hashes(samples_root)
    unique, duplicates, existing_count = dedupe_candidates(candidates, existing)
    selected = select_candidates(unique, args.limit)
    print(f"source={args.source} kind={args.kind} min_size={args.min_size} "
          f"candidates={total_entries} duplicates={duplicates} "
          f"existing={existing_count} unique={len(unique)} selected={len(selected)}")
    print(f"dropped: {dict(sorted(stats.items()))}")

    if args.dry_run:
        for item in selected:
            print(f"  {item['sha256'][:12]} {item['size']:>9} {item['ext']} "
                  f"{item['origin']} {item['name']}")
        print("dry run: nothing copied")
        return 0

    copied = 0
    csv_rows = []
    for item in selected:
        destination = samples_root / "Benign" / f"{item['sha256']}{item['ext']}"
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_file():
            continue
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_bytes(item["data"])
        os.replace(temporary, destination)
        copied += 1
        csv_rows.append({
            "sha256": item["sha256"],
            "source": item["source"],
            "origin": item["origin"],
            "ext": item["ext"],
            "url": item["url"],
            "license": item["license"],
            "size": item["size"],
            "collected_at": utc_now(),
            "status": "active",
        })
    appended = append_sources_csv(args.out_csv, csv_rows, samples_root)
    print(f"copied={copied} csv_rows={appended} out={args.out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

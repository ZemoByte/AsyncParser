#!/usr/bin/env python3
"""Cluster .NET payload samples by TLSH distance and shared config keys."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

import tlsh

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
DEFAULT_SAMPLES = ROOT / "Samples"
DEFAULT_LABELS = ROOT / "Data" / "Labels"
DEFAULT_OUT = ROOT / "Data" / "Clusters"
TLSH_THRESHOLD = 100
TLSH_MIN_BYTES = 256


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def write_marker(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / ".done").write_text("done\n", encoding="utf-8")


def load_label(sha: str, labels_root: Path) -> dict:
    path = labels_root / f"{sha}.json"
    if not path.is_file():
        raise RuntimeError(f"missing label JSON for {sha}")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid label JSON for {sha}: {exc}") from exc
    if not isinstance(payload, dict):
        raise RuntimeError(f"label JSON for {sha} is not an object")
    fields = payload.get("fields", {})
    return fields if isinstance(fields, dict) else {}


def _is_placeholder(value) -> bool:
    text = str(value).strip()
    if not text:
        return True
    if text.lower() == "none":
        return True
    if text.startswith("%") and text.endswith("%"):
        return True
    if text.lower().startswith("obfuscated_key_"):
        return True
    return False


def _norm(value) -> str:
    return str(value).strip().lower()


def config_keys_dict(config) -> dict:
    if not isinstance(config, dict) or "parse_error" in config:
        return {}
    result: dict = {}
    mutex = config.get("mutex")
    if mutex and not _is_placeholder(mutex):
        result["mutex"] = _norm(mutex)
    key = config.get("key")
    if key and not _is_placeholder(key):
        result["key"] = _norm(key)
    hosts = [_norm(h) for h in (config.get("hosts") or []) if h and not _is_placeholder(h)]
    if hosts:
        result["hosts"] = hosts
    return result


def config_keys(config) -> frozenset:
    d = config_keys_dict(config)
    keys: set = set()
    if "mutex" in d:
        keys.add(("mutex", d["mutex"]))
    if "key" in d:
        keys.add(("key", d["key"]))
    for host in d.get("hosts", []):
        keys.add(("host", host))
    return frozenset(keys)


def family_of(sha: str, labels_root: Path) -> str:
    fields = load_label(sha, labels_root)
    sug = str(fields.get("sug_fam") or "").strip().lower()
    if sug:
        return sug
    if str(fields.get("lbl_sts") or "").strip() == "verified":
        return "asyncrat"
    return ""


def is_dotnet_of(sha: str, labels_root: Path) -> bool:
    fields = load_label(sha, labels_root)
    return bool(fields.get("is_dotnet"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Cluster payload samples by TLSH and config keys")
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--labels-root", type=Path, default=DEFAULT_LABELS)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    samples_root = args.samples_root.resolve()
    labels_root = args.labels_root.resolve()
    out_root = args.out.resolve()

    sample_list = []
    for class_dir in (samples_root / "AsyncRAT",
                      samples_root / "OtherMalwares",
                      samples_root / "Benign"):
        if not class_dir.is_dir():
            continue
        for path in sorted(class_dir.iterdir()):
            if path.is_file():
                sha = sha256_file(path)
                sample_list.append((class_dir.name, sha, path))

    if not sample_list:
        print("no samples found")
        return 0

    for _class_name, sha, _path in sample_list:
        load_label(sha, labels_root)

    hashes = {}
    for _class_name, sha, path in sample_list:
        data = path.read_bytes()
        if len(data) < TLSH_MIN_BYTES:
            sys.stderr.write(f"WARNING: {sha} smaller than {TLSH_MIN_BYTES} bytes, skipping TLSH\n")
            continue
        try:
            hashes[sha] = tlsh.hash(data)
        except Exception as exc:
            sys.stderr.write(f"WARNING: TLSH failed for {sha}: {exc}\n")

    configs = {}
    config_dicts = {}
    families = {}
    is_dotnet_map = {}
    for _class_name, sha, _path in sample_list:
        fields = load_label(sha, labels_root)
        configs[sha] = config_keys(fields.get("config"))
        config_dicts[sha] = config_keys_dict(fields.get("config"))
        suggested = str(fields.get("sug_fam") or "").strip().lower()
        if not suggested and str(fields.get("lbl_sts") or "").strip() == "verified":
            suggested = "asyncrat"
        families[sha] = suggested
        is_dotnet_map[sha] = bool(fields.get("is_dotnet"))

    parent = {sha: sha for _cn, sha, _p in sample_list}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    shas = [sha for _cn, sha, _p in sample_list]
    for i, a in enumerate(shas):
        for b in shas[i + 1:]:
            # Partition: never union .NET with non-.NET
            if is_dotnet_map[a] != is_dotnet_map[b]:
                continue
            # Family guard: never union two samples with known differing families
            if families[a] and families[b] and families[a] != families[b]:
                continue
            tls_match = False
            if a in hashes and b in hashes:
                try:
                    if tlsh.diff(hashes[a], hashes[b]) <= TLSH_THRESHOLD:
                        tls_match = True
                except Exception:
                    pass
            ca, cb = configs.get(a, frozenset()), configs.get(b, frozenset())
            config_match = False
            if is_dotnet_map[a] and is_dotnet_map[b]:
                config_match = bool(ca and cb and (ca & cb))
            if tls_match or config_match:
                ra, rb = find(a), find(b)
                if ra != rb:
                    fam_a = {families[m] for m in shas if find(m) == ra and families[m]}
                    fam_b = {families[m] for m in shas if find(m) == rb and families[m]}
                    # Bridge guard: do not merge two components with differing known families
                    if fam_a and fam_b and not (fam_a & fam_b):
                        continue
                    union(a, b)

    components = {}
    for sha in shas:
        root = find(sha)
        components.setdefault(root, []).append(sha)

    cluster_id_map = {}
    for members in components.values():
        cid = min(members)
        for m in members:
            cluster_id_map[m] = cid

    for members in components.values():
        if len(members) <= 1:
            continue
        families = {family_of(m, labels_root) for m in members}
        families.discard("")
        if len(families) > 1:
            sys.stderr.write(
                f"WARNING: mixed-family cluster {min(members)[:12]}: {sorted(families)}\n"
            )

    for _class_name, sha, _path in sample_list:
        payload = {
            "schema_version": 1,
            "sha256": sha,
            "kind": "cluster",
            "producer": "clusterer",
            "fields": {
                "cluster_id": cluster_id_map[sha],
                "is_dotnet": bool(load_label(sha, labels_root).get("is_dotnet", True)),
                "tlsh": hashes.get(sha),
                "config_keys": config_dicts.get(sha, {}),
            },
        }
        write_json(out_root / f"{sha}.json", payload)

    write_marker(out_root)

    distinct = len(set(cluster_id_map.values()))
    multi = sum(1 for v in components.values() if len(v) > 1)
    print(f"clustered {len(sample_list)} samples into {distinct} clusters ({multi} multi-member)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

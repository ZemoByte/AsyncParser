#!/usr/bin/env python3
"""Shared helpers for the one-carver-per-folder tools."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import pefile


def is_dotnet(path: Path) -> bool:
    try:
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories()
        data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(data_directory) > 14 and data_directory[14].Size > 0
    except Exception:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_samples(samples_root: Path):
    for class_dir in (samples_root / "AsyncRAT",
                      samples_root / "OtherMalwares",
                      samples_root / "Benign"):
        if not class_dir.is_dir():
            continue
        for path in sorted(class_dir.iterdir()):
            if path.is_file():
                yield class_dir.name, path


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.replace(temporary, path)


def write_marker(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / ".done").write_text("done\n", encoding="utf-8")

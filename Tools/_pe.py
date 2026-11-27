#!/usr/bin/env python3
"""Single static PE/CLR header check.

No sample is executed or loaded as code; this only parses PE headers.
"""

from __future__ import annotations

from pathlib import Path

import pefile


def is_dotnet_bytes(data: bytes) -> bool:
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
        data_directory = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        return len(data_directory) > 14 and data_directory[14].Size > 0
    except Exception:
        return False


def is_dotnet(path: Path) -> bool:
    try:
        return is_dotnet_bytes(Path(path).read_bytes())
    except OSError:
        return False

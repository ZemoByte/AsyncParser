#!/usr/bin/env python3
"""Synthetic PE fixtures for tests. No real sample is read."""

from __future__ import annotations

import struct


def make_pe(dotnet: bool) -> bytes:
    """Minimal PE32 with an optional non-zero CLR data-directory size."""
    headers = bytearray(0x200)
    headers[0:2] = b"MZ"
    struct.pack_into("<I", headers, 0x3C, 0x40)

    pe_offset = 0x40
    headers[pe_offset:pe_offset + 4] = b"PE\0\0"
    coff = pe_offset + 4
    struct.pack_into("<HHIIIHH", headers, coff,
                     0x014C, 1, 0, 0, 0, 0xE0, 0x0102)

    optional = coff + 20
    struct.pack_into("<HBBIIIIII", headers, optional,
                     0x10B, 0, 0, 0x200, 0, 0, 0x1000, 0x1000, 0x2000)
    struct.pack_into("<II", headers, optional + 28, 0x400000, 0x1000)
    struct.pack_into("<II", headers, optional + 36, 0x200, 4)
    struct.pack_into("<HHHHHH", headers, optional + 44,
                     0, 0, 4, 0, 0, 0)
    struct.pack_into("<IIII", headers, optional + 56,
                     0x3000, 0x200, 0, 3)
    struct.pack_into("<IIIIII", headers, optional + 72,
                     0x100000, 0x1000, 0x100000, 0x1000, 0, 16)

    data_dirs = optional + 96
    # Index 14 is the CLR runtime header.
    struct.pack_into("<II", headers, data_dirs + 14 * 8,
                     0x1000 if dotnet else 0, 0x48 if dotnet else 0)

    section = optional + 0xE0
    headers[section:section + 8] = b".text\0\0\0"
    struct.pack_into("<IIIIIIHHI", headers, section + 8,
                     0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0x60000020)

    # A 72-byte CLR header is not required by the Size check, but keep the
    # section non-empty and deterministic.
    body = bytearray(0x200)
    if dotnet:
        struct.pack_into("<IHH", body, 0, 0x48, 2, 0)
    return bytes(headers) + bytes(body)

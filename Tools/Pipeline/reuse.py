#!/usr/bin/env python3
"""Per-sample cache decisions shared by labeler/carvers/voters."""

from __future__ import annotations

from collections import Counter


def output_version(payload: dict | None):
    if not isinstance(payload, dict):
        return None
    fields = payload.get("fields")
    if isinstance(fields, dict) and fields.get("producer_version") is not None:
        return fields.get("producer_version")
    return payload.get("producer_version")


def can_reuse(payload: dict | None, sha256: str, version: int) -> tuple[bool, str]:
    if not isinstance(payload, dict):
        return False, "missing output"
    if str(payload.get("sha256") or "") != sha256:
        return False, "sha mismatch"
    current = output_version(payload)
    if current is None:
        return False, "no producer_version (legacy)"
    if int(current) != int(version):
        return False, f"schema {current}->{version}"
    return True, "cached"


def schema_shift_message(versions: Counter, version: int, stage: str,
                         total: int) -> str | None:
    old = sorted(value for value in versions if value != version)
    if not old:
        return None
    return (f"schema changed {min(old)}->{version}: rerunning {stage} over "
            f"{total} samples (not only new)")

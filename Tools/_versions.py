#!/usr/bin/env python3
"""Output schema versions used for cache invalidation.

Bump a constant whenever the corresponding output schema or feature set
changes; the pipeline state fingerprints every stage with these values.
"""

PIPELINE_SCHEMA_VERSION = 2
LABEL_SCHEMA_VERSION = 2
EVIDENCE_SCHEMA_VERSION = 2
CARVER_SCHEMA_VERSION = 2
STRUCTURE_SCHEMA_VERSION = 2
FEATURE_SCHEMA_VERSION = 3
SPLIT_SCHEMA_VERSION = 2


def all_versions() -> dict:
    return {
        "pipeline": PIPELINE_SCHEMA_VERSION,
        "label": LABEL_SCHEMA_VERSION,
        "evidence": EVIDENCE_SCHEMA_VERSION,
        "carver": CARVER_SCHEMA_VERSION,
        "structure": STRUCTURE_SCHEMA_VERSION,
        "feature": FEATURE_SCHEMA_VERSION,
        "split": SPLIT_SCHEMA_VERSION,
    }

#!/usr/bin/env python3
"""Synthetic tests for the cross-family TLSH audit."""

from __future__ import annotations

import hashlib
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import tlsh  # noqa: E402

from Tools.Audit.cross_family import (  # noqa: E402
    build_clusters,
    find_cross_family_pairs,
)


def tlsh_of(seed: str) -> str:
    data = b"".join(hashlib.sha256(f"{seed}:{i}".encode()).digest()
                    for i in range(200))
    return tlsh.hash(data)


def clusters() -> tuple[dict, dict]:
    test = {"t1": {"cluster_id": "t1", "family": "AsyncRAT",
                   "members": ["test-a", "test-b"]}}
    train = {"r1": {"cluster_id": "r1", "family": "XWorm",
                    "members": ["train-a", "train-b"]},
             "r2": {"cluster_id": "r2", "family": "AsyncRAT",
                    "members": ["train-c"]}}
    return test, train


class CrossFamilyTests(unittest.TestCase):
    def test_cross_family_pair_is_reported(self):
        test, train = clusters()
        hashes = {"test-a": tlsh_of("same"), "test-b": tlsh_of("other"),
                  "train-a": tlsh_of("far"), "train-b": tlsh_of("same"),
                  "train-c": tlsh_of("same")}
        pairs = find_cross_family_pairs(test, train, hashes, threshold=0)
        self.assertEqual(len(pairs), 1)
        self.assertEqual(pairs[0]["test_cluster"], "t1")
        self.assertEqual(pairs[0]["train_cluster"], "r1")
        self.assertEqual(pairs[0]["train_family"], "XWorm")

    def test_same_family_is_never_reported(self):
        test = {"t1": {"cluster_id": "t1", "family": "AsyncRAT",
                       "members": ["test-a"]}}
        train = {"r1": {"cluster_id": "r1", "family": "AsyncRAT",
                        "members": ["train-a"]}}
        hashes = {"test-a": tlsh_of("same"), "train-a": tlsh_of("same")}
        self.assertEqual(find_cross_family_pairs(test, train, hashes, 0), [])

    def test_distance_above_threshold_is_not_reported(self):
        test, train = clusters()
        hashes = {"test-a": tlsh_of("one"), "test-b": tlsh_of("two"),
                  "train-a": tlsh_of("three"), "train-b": tlsh_of("four"),
                  "train-c": tlsh_of("five")}
        self.assertEqual(find_cross_family_pairs(test, train, hashes, 0), [])

    def test_build_clusters_keeps_split(self):
        rows = [{"sha256": "a", "split": "test", "cluster_id": "c1",
                 "status": "verified", "family": "AsyncRAT"},
                {"sha256": "b", "split": "train", "cluster_id": "c1",
                 "status": "verified", "family": "AsyncRAT"}]
        test = build_clusters(rows, "test")
        self.assertEqual(test["c1"]["members"], ["a"])


if __name__ == "__main__":
    unittest.main()

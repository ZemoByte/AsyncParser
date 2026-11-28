#!/usr/bin/env python3
"""Read-only Markdown report for Data/DataSet.db and Data/Clusters."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from Tools._label_common import (  # noqa: E402
    lineage_only_verified, load_final_label, load_gold_labels)
from Tools.Clustering.clusterer import family_of  # noqa: E402
from Tools._gate import evaluate_gate  # noqa: E402

DEFAULT_DATA = ROOT / "Data"
DEFAULT_SAMPLES = ROOT / "Samples"


def fmt_size(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{int(value)} B ({value / 1024:.1f} KiB)"


def sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def sample_index(samples_root: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    if not samples_root.is_dir():
        return index
    for class_dir in samples_root.iterdir():
        if not class_dir.is_dir():
            continue
        for path in class_dir.iterdir():
            if path.is_file():
                index.setdefault(sha256_file(path), path)
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description="Read-only dataset report")
    parser.add_argument("--data-root", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--samples-root", type=Path, default=DEFAULT_SAMPLES)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args()

    data_root = args.data_root.resolve()
    samples_root = args.samples_root.resolve()
    dataset_path = data_root / "DataSet.db"
    if not dataset_path.is_file():
        raise RuntimeError(f"dataset DB not found: {dataset_path}")

    conn = sqlite3.connect(f"file:{dataset_path}?mode=ro", uri=True)
    try:
        rows = [
            {
                "sha256": row[0], "lbl_sts": row[1] or "", "sug_fam": row[2] or "",
                "target_class_db": row[3] or "unassigned", "is_dotnet": row[4],
                "cluster_id": row[5] or "", "lbl_src": row[6] or "",
                "is_gold": row[7] or 0,
            }
            for row in conn.execute(
                "SELECT sha256, lbl_sts, sug_fam, target_class_db, is_dotnet, "
                "cluster_id, lbl_src, is_gold FROM dataset"
            )
        ]
    finally:
        conn.close()

    for row in rows:
        row["benign_stratum"] = ""
        if row["lbl_sts"] != "benign":
            continue
        fields = load_final_label(row["sha256"], data_root)
        source = str(fields.get("source") or "")
        origin = str(fields.get("origin") or "")
        kind = str(fields.get("kind") or "")
        if source == "clrheader2023":
            row["benign_stratum"] = "holdout"
        elif source == "fixture" or origin == "fixture":
            row["benign_stratum"] = "fixture"
        elif kind != "exe":
            row["benign_stratum"] = "aux"
        else:
            row["benign_stratum"] = "active"

    index = sample_index(samples_root)
    sizes_by_class: dict[str, list[int]] = defaultdict(list)
    dotnet_by_class: dict[str, list[int]] = defaultdict(list)
    missing_files = 0
    for row in rows:
        path = index.get(row["sha256"])
        if path is None:
            missing_files += 1
            continue
        sizes_by_class[row["target_class_db"]].append(path.stat().st_size)
        dotnet_by_class[row["target_class_db"]].append(int(bool(row["is_dotnet"])))

    clusters: dict[str, list[str]] = defaultdict(list)
    for path in (data_root / "Clusters").glob("*.json"):
        payload = json.loads(path.read_text(encoding="utf-8"))
        clusters[payload["fields"]["cluster_id"]].append(payload["sha256"])
    cluster_sizes = [len(members) for members in clusters.values()]
    mixed = 0
    for members in clusters.values():
        families = {family_of(sha, data_root / "Labels") for sha in members}
        families.discard("")
        if len(families) > 1:
            mixed += 1

    gold = load_gold_labels(data_root)
    gold_filled = sum(1 for row in gold.values() if row["gold_status"])

    lines = ["# Dataset report", ""]
    lines += ["## Rows by label status", "", "| lbl_sts | rows |", "|---|---:|"]
    for key, value in sorted(Counter(row["lbl_sts"] for row in rows).items()):
        lines.append(f"| `{key}` | {value} |")
    lines += ["", "## Rows by suggested family", "", "| sug_fam | rows |", "|---|---:|"]
    for key, value in sorted(Counter(row["sug_fam"] or "<none>" for row in rows).items()):
        lines.append(f"| `{key}` | {value} |")
    lines += ["", "## Rows by target class DB", "", "| target_class_db | rows |", "|---|---:|"]
    for key, value in sorted(Counter(row["target_class_db"] for row in rows).items()):
        lines.append(f"| `{key}` | {value} |")

    lines += ["", "## Size and .NET percentage per class", "",
              "| class | rows | min size | median size | max size | .NET |",
              "|---|---:|---:|---:|---:|---:|"]
    for key in sorted(sizes_by_class):
        sizes = sizes_by_class[key]
        dotnet = dotnet_by_class[key]
        pct = (100.0 * sum(dotnet) / len(dotnet)) if dotnet else 0.0
        lines.append(
            f"| `{key}` | {len(sizes)} | {fmt_size(min(sizes))} | "
            f"{fmt_size(statistics.median(sizes))} | {fmt_size(max(sizes))} | {pct:.1f}% |"
        )

    per_class_clusters: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        per_class_clusters[row["target_class_db"]][row["cluster_id"]] += 1
    lines += ["", "## Per-class cluster concentration", "",
              "| class | rows | clusters | largest | largest share | singletons |",
              "|---|---:|---:|---:|---:|---:|"]
    class_stats: dict[str, dict] = {}
    for key in sorted(per_class_clusters):
        counts = per_class_clusters[key]
        sizes = sorted(counts.values(), reverse=True)
        rows_count = sum(sizes)
        share = (100.0 * sizes[0] / rows_count) if sizes else 0.0
        class_stats[key] = {"rows": rows_count, "clusters": len(sizes),
                            "largest": sizes[0] if sizes else 0,
                            "share": share,
                            "singletons": sum(1 for size in sizes if size == 1)}
        lines.append(f"| `{key}` | {rows_count} | {len(sizes)} | {sizes[0]} | "
                     f"{share:.1f}% | {sum(1 for size in sizes if size == 1)} |")

    benign_strata: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        if row["benign_stratum"]:
            benign_strata[row["benign_stratum"]].append(row["cluster_id"])
    benign_stats = {}
    for stratum, cluster_ids in benign_strata.items():
        counts = Counter(cluster_ids)
        sizes = sorted(counts.values(), reverse=True)
        benign_stats[stratum] = {
            "rows": len(cluster_ids), "clusters": len(counts),
            "largest": sizes[0] if sizes else 0,
            "share": 100.0 * sizes[0] / len(cluster_ids) if cluster_ids else 0.0,
            "singletons": sum(1 for size in sizes if size == 1),
        }
    primary_clusters = benign_strata.get("active", []) + benign_strata.get("fixture", [])
    primary_counts = Counter(primary_clusters)
    primary_sizes = sorted(primary_counts.values(), reverse=True)
    benign_primary_stats = {
        "rows": len(primary_clusters), "clusters": len(primary_counts),
        "largest": primary_sizes[0] if primary_sizes else 0,
        "share": (100.0 * primary_sizes[0] / len(primary_clusters)
                  if primary_clusters else 0.0),
        "singletons": sum(1 for size in primary_sizes if size == 1),
    }
    lines += ["", "## Benign strata", "",
              "| stratum | rows | clusters | largest | largest share | singletons |",
              "|---|---:|---:|---:|---:|---:|"]
    for stratum in ("active", "fixture", "holdout", "aux"):
        item = benign_stats.get(stratum, {"rows": 0, "clusters": 0,
                                          "largest": 0, "share": 0.0,
                                          "singletons": 0})
        lines.append(f"| `{stratum}` | {item['rows']} | {item['clusters']} | "
                     f"{item['largest']} | {item['share']:.1f}% | {item['singletons']} |")
    lines.append(f"| `primary (active+fixture)` | {benign_primary_stats['rows']} | "
                 f"{benign_primary_stats['clusters']} | {benign_primary_stats['largest']} | "
                 f"{benign_primary_stats['share']:.1f}% | "
                 f"{benign_primary_stats['singletons']} |")

    gate = evaluate_gate(data_root)
    family_stats = gate["stage2"]["families"]
    lines += ["", "## Stage 2 families", "",
              "| family | rows | clusters | largest share | result |",
              "|---|---:|---:|---:|---|"]
    for family, item in sorted(family_stats.items()):
        lines.append(f"| `{family}` | {item['rows']} | {item['clusters']} | "
                     f"{item['share']:.1f}% | {'PASS' if item['ok'] else 'FAIL'} |")
    lines += ["", "## Dataset gate", "",
              "| gate | result | detail |", "|---|---|---|"]
    for label, stats in (("AsyncRAT.db", gate["stage1"]["asyncrat"]),
                         ("Benign active", gate["stage1"]["benign"])):
        lines.append(f"| Stage 1 `{label}` | {'PASS' if stats['ok'] else 'FAIL'} | "
                     f"{stats['clusters']} clusters, largest {stats['share']:.1f}% "
                     f"(target 10 clusters) |")
    lines.append(f"| Stage 2 | {'PASS' if gate['stage2']['ok'] else 'FAIL'} | "
                 f"{len(family_stats)} families; each needs >=2 clusters and "
                 f"<=50% share |")
    lines.append(f"| Overall | {'PASS' if gate['overall'] else 'FAIL'} "
                 f"| no enforcement |")

    cluster_json_count = len(list((data_root / "Clusters").glob("*.json")))
    if cluster_json_count != len(rows):
        sys.stderr.write(
            f"WARNING: cluster JSON count {cluster_json_count} != dataset rows "
            f"{len(rows)}\n")

    lines += ["", "## Clusters", "",
              "| metric | value |", "|---|---:|",
              f"| clusters | {len(clusters)} |",
              f"| multi-member | {sum(1 for size in cluster_sizes if size > 1)} |",
              f"| largest | {max(cluster_sizes) if cluster_sizes else 0} |",
              f"| singletons | {sum(1 for size in cluster_sizes if size == 1)} |",
              f"| mixed-family | {mixed} |",
              f"| missing sample files | {missing_files} |"]

    lineage = lineage_only_verified(data_root)
    lines += ["", "## Lineage-only verified", "",
              f"- rows: {len(lineage)} (own-YARA/MB lineage only; no "
              f"family-scoped AsyncRAT voter)"]
    for item in lineage:
        lines.append(f"  - `{item['sha256'][:12]}...` "
                     f"{sorted(item['groups'])}")

    lines += ["", "## Labels and gold", "",
              "| lbl_src | rows |", "|---|---:|"]
    for key, value in sorted(Counter(row["lbl_src"] or "<none>" for row in rows).items()):
        lines.append(f"| `{key}` | {value} |")
    lines += ["",
              f"- `is_gold=1`: {sum(1 for row in rows if row['is_gold'])}",
              f"- gold rows with non-empty `gold_status`: {gold_filled}",
              ""]
    positives = sum(1 for row in rows if row["lbl_sts"] in {"verified", "verified_other"})
    benign = benign_primary_stats["rows"]
    holdout = benign_stats.get("holdout", {}).get("rows", 0)
    lines += [f"Class balance: **{benign} primary benign vs {positives} positive** "
              f"({sum(1 for row in rows if row['lbl_sts'] == 'verified')} verified + "
              f"{sum(1 for row in rows if row['lbl_sts'] == 'verified_other')} verified_other); "
              f"{holdout} external holdout benign.", ""]

    report = "\n".join(lines)
    if args.out:
        args.out.write_text(report, encoding="utf-8")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

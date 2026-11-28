# D2 decision brief — Hassan 70/30 partition (not run)

**Status: NOT APPROVED. Do not execute without an explicit “approve D2”.**

## What D2 changes

- 70% of the 565 `clrheader2023` benign rows become ordinary benign training
  rows; 30% remain the external holdout.
- Partition by `cluster_id`, seed 42, cumulative about 70% of rows.
- Any cluster containing a non-Hassan row goes to the 70% train side. No
  cluster may be in both partitions.
- The fixture exclusion and all labels/clusters remain unchanged.

## Effect

- More negative diversity in training (roughly 396 rows instead of 0 Hassan
  rows in train).
- The external holdout shrinks from 565 to about 170 rows.
- Positive split assignments can change through the rebalance step; all models
  retrain.
- Results are **not comparable** to Phase 5. Any new number is a new
  experiment, not a continuation.

## Risks

- Wider holdout confidence intervals (~170 rows).
- Split drift after rebalancing; positive assignments must be checked against
  the pre-D2 manifest.
- It cannot fix Stage 1: the AsyncRAT ceiling is a positive-cluster problem
  (52 clusters, largest 89 = 57.8%), not a benign shortage.
- It is **not a gate fix** and does not create a detector claim.
- A cluster accidentally spanning partitions would invalidate the experiment;
  the partition helper must enforce the disjointness check.

## Exact commands if approved

**Tools/_partition.py exists and is tested; it is not wired into the
pipeline.** Preview: 565/293 -> 396/164 train, 169/129 holdout; D2 not
approved. After approval, the approved rebuild order is:

```bash
python3 Tools/Splits/split.py
python3 Tools/Importer/importer.py
python3 Tools/Features/build_matrix.py
python3 Tools/Models/baseline.py
python3 Tools/Models/fixup_eval.py
python3 Tools/Report/dataset_report.py
```

Before running, copy `Data/Features/baseline_results.json` and
`Data/Features/fixup_results.json` to `Data/Audit/`. After running, check:
0 cluster spans; positive split assignments versus the pre-D2 manifest; every
clrheader2023 cluster in exactly one partition; holdout ~30%. Stop if any
positive assignment changed.

## Decision

D2 remains **not approved**. The full 565-row holdout is unchanged.

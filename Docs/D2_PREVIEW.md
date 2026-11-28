# D2 partition preview — read-only

**D2 is not approved. No data changed. This preview implements and tests the
partition helper only; it does not run the split/importer/matrix/baseline/
evaluator.**

## Partition

Deterministic from the 565 `clrheader2023` rows and their `cluster_id`, seed
42, target 70% (`round(565*0.70)=396`). Any cluster containing a non-Hassan
row goes to train; fixtures stay excluded from the holdout.

| item | rows | clusters |
|---|---:|---:|
| Hassan total | 565 | 293 |
| Train | 396 | 164 |
| Holdout | 169 | 129 |
| **Holdout fraction** | **29.9%** | |

- Overlap clusters: **0** (no cluster in both).
- Forced-train clusters: **945** total clusters contain a non-Hassan row;
  **10** of them contain Hassan rows (78 Hassan rows).
- Fixture rows: **10** (forced train, never holdout).
- Missing carved/structure artifacts for Hassan train rows: **0**.

## Expected effect

- Benign training-eligible rows: **+396** (the class DB membership stays 704;
  the rows already exist; D2 changes their split eligibility).
- External holdout: **565 → 169 rows**. Expect wider FPR confidence intervals.
- Positive split assignments may change through rebalancing; all models
  retrain. Numbers are **not comparable** to Phase 5/6.
- This cannot fix Stage 1: the AsyncRAT positive ceiling is unchanged.

## Apply diff plan (future phase; not executed)

1. `Tools/Splits/split.py` `read_rows()`: replace the blanket
   `source == "clrheader2023"` exclusion with
   `_partition.assignment_for(manifest, cluster_id)`: include only `train`
   Hassan rows; skip `holdout`; keep the fixture/non-EXE exclusion unchanged.
2. `Tools/Importer/importer.py` `split_assignment()` `benign_ok`: allow
   Hassan rows only when the partition helper says `train`; reject holdout;
   keep fixtures excluded.
3. `Tools/Models/baseline.py` `holdout_shas()`: return only Hassan rows whose
   partition is `holdout`, not every `clrheader2023` row.
4. `Tools/Report/dataset_report.py`: show the train/holdout partitions and
   their counts.
5. `Tools/_gate.py` stays unchanged; it still tags every `clrheader2023` row as
   holdout, so the gate result should not change. Verify before/after.

The helper is `Tools/_partition.py` (`build_partition`, `assign_clusters`,
`assignment_for`). It is deterministic, synthetic-tested, and is the only
source of the 70/30 decision.

## Apply order if approved

```bash
python3 Tools/Splits/split.py
python3 Tools/Importer/importer.py
python3 Tools/Features/build_matrix.py
python3 Tools/Models/baseline.py
python3 Tools/Models/fixup_eval.py
python3 Tools/Report/dataset_report.py
```

Before running, copy `Data/Features/baseline_results.json` and
`Data/Features/fixup_results.json` to `Data/Audit/`. Stop if any of these fail:

- a cluster spans train/holdout;
- a positive split assignment changes versus `Data/Audit/splits_before_d2.json`;
- a non-Hassan cluster is assigned holdout;
- the holdout is not approximately 169 Hassan rows;
- any Hassan train row lacks its carved/structure JSON (currently 0 missing).

## Status

Overlap **0**, holdout **169/565 = 29.9%**, artifacts **0 missing**; the
partition preview is clean. Approval is still a separate decision.

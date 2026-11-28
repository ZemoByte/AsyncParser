# Claims — what this project supports

**All model numbers are DIAGNOSTIC ONLY. The dataset gate FAILS. There is no
detector result.** Evidence is in `Docs/FINAL_RESULTS.md`,
`Docs/results.md` and `Data/Features/fixup_results.json`.

| claim | status | evidence / boundary |
|---|---|---|
| The dataset has 1,824 rows / 1,228 clusters, 0 NULL clusters | **Supported** | `Data/DataSet.db` |
| Stage 1 fails: AsyncRAT 52 clusters, largest 89 = 57.8% (needs 178) | **Supported** | gate / `FINAL_RESULTS.md` §1 |
| Stage 2 fails overall; XWorm and VenomRAT pass their small checks | **Supported** | gate table |
| Label provenance is auditable; 530 rows (all unverified) are MB-only and 263 rows across classes are multi-source | **Supported** | `Data/Audit/label_quality.json` |
| Voter conflicts are mostly ties, not contradictions | **Supported** | verified_other 14 support / 0 different / 42 tie; unverified 20 different / 31 tie |
| Capability features rank above a single P/Invoke count on threshold-free PR/ROC | **Supported as diagnostic ranking** | PR .988 [.959,1.000] vs .695 [.553,.902]; ROC .980 [.941,1.000] vs .645 [.441,.847] |
| Capability F1 is higher than P/Invoke at the operating point | **Not supported** | Like-for-like 2.1d OOF F1 .903 [.800,.971] vs .788 [.677,.904]: CIs overlap at n=32. The .877 [.769,.951] value is the in-sample/95%-target sensitivity from Phase 2.1c, not the operating-point pair. |
| Capability has lower holdout FPR than P/Invoke | **Not supported** | thresholds land at different actual recalls (78.1% vs 81.2%); 0/565 is not a result |
| The model generalizes to real-world AsyncRAT or other .NET RATs | **Not supported** | gate FAIL, dominant cluster, 32 test positives |
| A static prototype CLI exists for single-EXE diagnostic scoring | **Supported as a prototype** | `Tools/Models/predict.py`; NOT VALIDATED banner, abstention rules, exit codes |
| The CLI detects AsyncRAT or other malware in deployment | **Not supported** | CLI parity checked on 30 known samples; prototype only; no detector claim; other families abstain. Gate FAIL; Stage 2 only AsyncRAT vs XWorm, n=29; no other-family model |
| A Stage 2 family model is ready | **Not supported** | only AsyncRAT + XWorm eligible, n=29 |
| The gold set is ground truth | **Not supported** | 30 rows, 0 filled; automated audit is not human gold |
| D2 improves the setup | **Not tested** | D2/WS3 not run; needs explicit approval |

## Safe sentence for a thesis

> On a frozen 1,824-row diagnostic dataset, capability features rank above a
> single P/Invoke count on threshold-free PR/ROC, but the operating-point F1
> CIs overlap and the dataset gate fails; the Stage 2 check has only 29 test
> rows. These are diagnostic findings, not a detector result.

## Do not write

- “The detector achieves 0.90+ F1 on AsyncRAT.”
- “Capability features beat P/Invoke.”
- “The holdout FPR is 0%.”
- “Stage 2 classifies AsyncRAT vs XWorm.”
- “The gold audit confirms the labels.”

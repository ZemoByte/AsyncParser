# results.md — run reports

> **Final synthesis:** see `Docs/FINAL_RESULTS.md` (plus `Docs/MODEL_CARD.md`
> and `Docs/CLAIMS.md`). This file is the chronological run log; Phase 5 is
> the last matched-recall run.

## Phase 5 — presentation and error analysis (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed; not a result.** One clean evaluator
run produced this section. The matched-95 calibration failed to transfer and
is presented as sensitivity only; the primary comparison is the fixed 0.5
probability reference plus threshold-free PR/ROC.

- `generated_at`: `2026-11-28T15:42:40+00:00`
- `script_sha256`: `6598bfce845eca72666753b7cd8ae2f21172947e83c4a43e43c9bc9c7e2cc5ef`
- `run_id`: `c7a21a6c37f14f5aabcc821dd26729cd`; `oof_folds`: 5;
  `threshold_source`: `train_oof_groupkfold`
- All sections carry the same `run_id`.

### Primary test view (probabilities at 0.5 and threshold-free ranking)

| model | F1 @0.5 | F1-optimal OOF | PR-AUC [CI] | ROC-AUC [CI] |
|---|---:|---:|---|---|
| f_capability_uncapped | 0.921 | 0.903 | 0.988 [0.959, 1.000] | 0.980 [0.941, 1.000] |
| g_capability_capped | 0.935 | 0.897 | 0.989 [0.961, 1.000] | 0.981 [0.947, 1.000] |
| h_capability_policy | 0.918 | 0.955 | 0.992 [0.967, 1.000] | 0.987 [0.961, 1.000] |
| i_capability_all | 0.900 | 0.941 | 0.992 [0.965, 1.000] | 0.988 [0.958, 1.000] |
| e_structural_policy | 0.857 | 0.844 | 0.933 [0.870, 0.987] | 0.880 [0.786, 0.973] |
| e2_structural_all_diagnostic | 0.831 | 0.857 | 0.929 [0.850, 0.984] | 0.881 [0.765, 0.971] |
| b_implmap_only | 0.795 | 0.788 | 0.695 [0.553, 0.902] | 0.645 [0.441, 0.847] |
| c_file_size_only_diagnostic | 0.000 | 0.400 | 0.827 [0.680, 0.934] | 0.688 [0.547, 0.851] |

**0.5 probability-only holdout reference:** capability-only 35/565 = 6.2%;
full model (capability + all counts) 13/565 = 2.3%; capped 125/565 = 22.1%;
capability+policy 13/565 = 2.3%. P/Invoke at 0.5 is a raw count ("any
P/Invoke") and is **not comparable**; its raw threshold is 4.

**Direct answer:** capability F1 at 0.5 is 0.921; P/Invoke
0.795. PR-AUC .988 [.959, 1.000] vs .695 [.553, .902] and
ROC-AUC .980 [.941, 1.000] vs .645 [.441, .847] separate. At the F1-optimal
OOF point, F1 .903 [.800, .971] vs .788 [.677, .904] overlaps. **Ranking
favors capability; the operating point does not separate at n=32 positives;
neither is a result.**

The primary capability-vs-P/Invoke comparison is capability-only; +policy and
+all counts are ablations, not the main model.

### Matched 95% target (failed calibration; sensitivity only)

This table was previously labelled “primary”; it is not. The target was
chosen on train OOF scores, but it does not transfer: capability's threshold
is 0.998 with actual test recall
0.781; P/Invoke's is 4.000 with
actual recall 0.812. **Every 0/565 cell below is not a
result** and FPRs at different actual recalls are not comparable.

| model | threshold | test recall | test F1 | holdout FP | holdout FPR [CI] |
|---|---:|---:|---:|---:|---|
| f_capability_uncapped | 0.998 | 0.781 | 0.877 | 0/565 | 0.0% [0.000, 0.000] |
| g_capability_capped | 0.998 | 0.781 | 0.877 | 0/565 | 0.0% [0.000, 0.000] |
| h_capability_policy | 0.140 | 1.000 | 0.955 | 100/565 | 17.7% [0.109, 0.255] |
| i_capability_all | 0.066 | 1.000 | 0.941 | 108/565 | 19.1% [0.119, 0.279] |
| e_structural_policy | 0.021 | 0.906 | 0.795 | 294/565 | 52.0% [0.444, 0.598] |
| e2_structural_all_diagnostic | 0.047 | 0.969 | 0.849 | 121/565 | 21.4% [0.144, 0.325] |
| b_implmap_only | 4.000 | 0.812 | 0.788 | 48/565 | 8.5% [0.051, 0.130] |
| c_file_size_only_diagnostic | -228352.000 | 0.531 | 0.642 | 434/565 | 76.8% [0.638, 0.852] |

The 90% target is the same failed-calibration sensitivity; its table is kept
for audit only:

| model | threshold | test recall | test F1 | holdout FP | holdout FPR [CI] |
|---|---:|---:|---:|---:|---|
| f_capability_uncapped | 1.000 | 0.688 | 0.815 | 0/565 | 0.0% [0.000, 0.000] |
| g_capability_capped | 1.000 | 0.688 | 0.815 | 0/565 | 0.0% [0.000, 0.000] |
| h_capability_policy | 0.140 | 1.000 | 0.955 | 100/565 | 17.7% [0.109, 0.255] |
| i_capability_all | 0.066 | 1.000 | 0.941 | 108/565 | 19.1% [0.119, 0.279] |
| e_structural_policy | 0.367 | 0.844 | 0.844 | 294/565 | 52.0% [0.444, 0.598] |
| e2_structural_all_diagnostic | 0.181 | 0.938 | 0.870 | 121/565 | 21.4% [0.144, 0.325] |
| b_implmap_only | 6.000 | 0.812 | 0.788 | 48/565 | 8.5% [0.051, 0.130] |
| c_file_size_only_diagnostic | -178688.000 | 0.438 | 0.571 | 434/565 | 76.8% [0.638, 0.852] |

### LOCO primary: 0.5 probability-only reference

Primary LOCO is the fixed 0.5 probability reference plus PR/ROC; P/Invoke and
file size at 0.5 are raw scores and are not comparable.

| scope / model | recall [CI] | FPR [CI] | F1 [CI] | PR-AUC | ROC-AUC |
|---|---|---|---|---|---|
| verified / f_capability | 0.981 [0.900, 1.000] | 0.016 [0.000, 0.039] | 0.984 [0.913, 0.997] | 0.998 | 0.997 |
| verified / g_capability_capped | 0.974 [0.877, 0.996] | 0.031 [0.000, 0.082] | 0.974 [0.875, 0.994] | 0.997 | 0.996 |
| verified / h_capability_policy | 0.981 [0.900, 1.000] | 0.039 [0.006, 0.094] | 0.974 [0.877, 0.994] | 0.997 | 0.996 |
| verified / i_capability_all | 0.987 [0.912, 1.000] | 0.031 [0.000, 0.082] | 0.981 [0.898, 0.996] | 0.998 | 0.997 |
| verified / e_structural_policy | 0.968 [0.846, 0.992] | 0.155 [0.067, 0.264] | 0.923 [0.727, 0.975] | 0.920 | 0.931 |
| positive / f_capability | 0.981 [0.946, 1.000] | 0.023 [0.000, 0.069] | 0.983 [0.951, 0.997] | 0.999 | 0.998 |
| positive / g_capability_capped | 0.981 [0.935, 0.996] | 0.031 [0.000, 0.082] | 0.981 [0.942, 0.994] | 0.998 | 0.997 |
| positive / h_capability_policy | 0.981 [0.935, 0.996] | 0.054 [0.000, 0.140] | 0.974 [0.929, 0.992] | 0.998 | 0.997 |
| positive / i_capability_all | 0.981 [0.935, 0.996] | 0.062 [0.007, 0.148] | 0.972 [0.924, 0.990] | 0.998 | 0.996 |
| positive / e_structural_policy | 0.962 [0.867, 0.987] | 0.140 [0.053, 0.267] | 0.940 [0.833, 0.978] | 0.962 | 0.948 |

Capability 0.5 FPR is .016 (verified) / .023 (positive); this is a real
probability operating point, unlike the failed matched-95 threshold.

### LOCO sensitivity: matched 95% target

Thresholds are chosen on fold-train at 95% target recall; actual held-out
recall is reported, not assumed. This is sensitivity only.

| scope / model | recall [CI] | FPR [CI] | F1 [CI] | fold-threshold range |
|---|---|---|---|---|
| verified / f_capability | 0.903 [0.623, 0.968] | 0.000 [0.000, 0.000] | 0.949 [0.767, 0.984] | 0.996–0.999 |
| verified / g_capability_capped | 0.916 [0.649, 0.972] | 0.000 [0.000, 0.000] | 0.956 [0.787, 0.986] | 0.996–0.999 |
| verified / h_capability_policy | 0.909 [0.660, 0.965] | 0.000 [0.000, 0.000] | 0.952 [0.795, 0.982] | 0.996–0.998 |
| verified / i_capability_all | 0.909 [0.660, 0.965] | 0.000 [0.000, 0.000] | 0.952 [0.795, 0.982] | 0.997–0.999 |
| verified / e_structural_policy | 0.825 [0.490, 0.906] | 0.062 [0.007, 0.157] | 0.879 [0.571, 0.942] | 0.913–0.992 |
| verified / b_implmap_only | 0.942 [0.744, 0.983] | 0.643 [0.495, 0.786] | 0.759 [0.375, 0.904] | 0.000–2.000 |
| positive / f_capability | 0.925 [0.780, 0.971] | 0.000 [0.000, 0.000] | 0.961 [0.877, 0.985] | 0.997–0.998 |
| positive / g_capability_capped | 0.925 [0.780, 0.971] | 0.000 [0.000, 0.000] | 0.961 [0.877, 0.985] | 0.996–0.998 |
| positive / h_capability_policy | 0.910 [0.762, 0.961] | 0.000 [0.000, 0.000] | 0.953 [0.865, 0.980] | 0.997–0.999 |
| positive / i_capability_all | 0.915 [0.779, 0.963] | 0.000 [0.000, 0.000] | 0.956 [0.876, 0.981] | 0.997–0.999 |
| positive / e_structural_policy | 0.840 [0.670, 0.896] | 0.062 [0.007, 0.157] | 0.894 [0.760, 0.939] | 0.949–0.991 |
| positive / b_implmap_only | 0.948 [0.866, 0.983] | 0.674 [0.515, 0.791] | 0.804 [0.573, 0.918] | 0.000–2.000 |

Capability's actual recall is .903/.925 with FPR 0/129; P/Invoke's is
.942/.948 with FPR .643/.674. The FPRs are at different actual recalls and
are not directly comparable. The old positive-only 2.1c view had 3/5 misses;
the mixed fold-threshold view has 24; the matched-95 view has 31.

### Error analysis (read-only)

- Test at matched 95: **0 FP / 7 FN** (capability). At the F1-optimal OOF
  threshold: 2 FP / 4 FN. The 7 FN have SHA, cluster, score, nearest TLSH
  neighbor, top 5 features and voter evidence in the JSON.
- LOCO: 3/5 old positive-only misses; 24 mixed fold-threshold misses; 31
  matched-95 misses (all singletons).
- Stage 2: **2 XWorm -> AsyncRAT errors**, clusters `32ba94d5…` and
  `9d08e5e6…`; neither is `00fe40a8`, and nearest distances to the 89-row
  AsyncRAT cluster are 706/354, not 88.
- Holdout false positives at the failed matched-95 point: **0**; not a result.
- Obfuscated test: **4 positives**, not 6; capability caught 2/4 at matched 95.
  The 6 obfuscated rows include 2 benign rows.

### Label audit conflict refinement

Conflict-only counts: verified_other **14 majority-supported / 0 different /
42 tie**; unverified **20 majority-different / 31 tie**; gold candidates
**4 majority-different / 7 tie**. Top unverified pairs: AsyncRAT|XWorm 28,
AsyncRAT|DcRat 19. No label is inferred. Gold remains **30 rows / 0 filled /
no merge**.

### Synthesis

`Docs/FINAL_RESULTS.md` is the thesis-ready synthesis; `Docs/CLAIMS.md` and
`Docs/MODEL_CARD.md` are the one-page claim and model-card views. The gate is
unchanged FAIL; D2/WS3 is not run.

## Phase 2.1d — OOF threshold, fixed-0.5 LOCO, label audit (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed; not a result.** One clean evaluator
run produced this section. D2/WS3 is **not run**.

- `generated_at`: `2026-11-28T15:15:13+00:00`
- `script_sha256`: `55b4fdd009653e4cbcccf6cdf9929a981aa8c29f2dd6bf9a21b0dc4e0b099c0b`
- `run_id`: `c50d3748a16145df982c8728719ce062`; `oof_folds`: 5; `threshold_source`:
  `train_oof_groupkfold`
- Historical Phase 2.1d: all sections in that block carry the same `run_id`
  (`c50d3748…`); it is not the final Phase 5 run.

### OOF threshold

Thresholds are selected on **grouped 5-fold OOF scores from train only**
(`GroupKFold` by `cluster_id`). The in-sample column is the old, overfit
sensitivity value.

| scored model | in-sample threshold | OOF threshold |
|---|---:|---:|
| b_implmap_only | 4.000 | 4.000 |
| c_file_size_only_diagnostic | -101376.000 | -101376.000 |
| e_structural_policy | 0.879 | 0.332 |
| e2_structural_all_diagnostic | 0.972 | 0.075 |
| f_capability_uncapped | 0.998 | 0.559 |
| g_capability_capped | 0.998 | 0.976 |
| h_capability_policy | 0.997 | 0.130 |
| i_capability_all | 0.998 | 0.064 |
| j_random_split_leaky | 0.993 | 0.486 |

`threshold = 0.5` is the fixed reference. The main test and holdout tables use
the OOF threshold; the in-sample threshold is labelled **overfit** and is not
the operating point.

### Test split (52 rows, 32 positives, 48 clusters)

CM = TN/FP/FN/TP at the OOF threshold.

| model | OOF thr | F1 @0.5 | F1 @in-sample (overfit) | F1 @OOF | PR-AUC | ROC-AUC | CM @OOF |
|---|---:|---:|---:|---:|---:|---:|---|
| a_majority | — | 0.762 | 0.762 | 0.762 | 0.615 | 0.500 | 0/20/0/32 |
| b_implmap_only | 4.000 | 0.795 | 0.788 | 0.788 | 0.695 | 0.645 | 12/8/6/26 |
| c_file_size_only_diagnostic | -101376.000 | 0.000 | 0.400 | 0.400 | 0.827 | 0.688 | 20/0/24/8 |
| d_tlsh_knn | — | 0.750 | 0.750 | 0.750 | 0.666 | 0.475 | 17/3/11/21 |
| e_structural_policy | 0.332 | 0.857 | 0.847 | 0.844 | 0.933 | 0.880 | 15/5/5/27 |
| e2_structural_all_diagnostic | 0.075 | 0.831 | 0.731 | 0.857 | 0.929 | 0.881 | 12/8/2/30 |
| f_capability_uncapped | 0.559 | 0.921 | 0.877 | 0.903 | 0.988 | 0.980 | 18/2/4/28 |
| g_capability_capped | 0.976 | 0.935 | 0.897 | 0.897 | 0.989 | 0.981 | 20/0/6/26 |
| h_capability_policy | 0.130 | 0.918 | 0.877 | 0.955 | 0.992 | 0.987 | 17/3/0/32 |
| i_capability_all | 0.064 | 0.900 | 0.857 | 0.941 | 0.992 | 0.988 | 16/4/0/32 |
| j_random_split_leaky | 0.486 | 0.960 | 0.951 | 0.960 | 0.999 | 0.998 | 38/1/4/60 |

95% CIs at the OOF operating point:

| model | F1 CI | PR-AUC CI | ROC-AUC CI |
|---|---|---|---|
| a_majority | [0.649, 0.865] | [0.481, 0.763] | [0.500, 0.500] |
| b_implmap_only | [0.677, 0.904] | [0.553, 0.902] | [0.441, 0.847] |
| c_file_size_only_diagnostic | [0.124, 0.636] | [0.680, 0.934] | [0.547, 0.851] |
| d_tlsh_knn | [0.585, 0.864] | [0.496, 0.832] | [0.301, 0.649] |
| e_structural_policy | [0.720, 0.935] | [0.870, 0.987] | [0.786, 0.973] |
| e2_structural_all_diagnostic | [0.746, 0.938] | [0.850, 0.984] | [0.765, 0.971] |
| f_capability_uncapped | [0.800, 0.971] | [0.959, 1.000] | [0.941, 1.000] |
| g_capability_capped | [0.792, 0.968] | [0.961, 1.000] | [0.947, 1.000] |
| h_capability_policy | [0.900, 1.000] | [0.967, 1.000] | [0.961, 1.000] |
| i_capability_all | [0.871, 0.985] | [0.965, 1.000] | [0.958, 1.000] |
| j_random_split_leaky | [0.867, 0.991] | [0.986, 1.000] | [0.989, 1.000] |

The random split (j) is leaky by construction: OOF F1
**0.960**,
**+0.057** above the cluster-split capability
model. It is not a result.

### Direct answer: capability vs P/Invoke

At the OOF threshold:

- **F1: capability 0.903 [0.800, 0.971]; P/Invoke
  0.788 [0.677, 0.904]; overlap: yes.**
- **PR-AUC: capability 0.988 [0.959, 1.000]; P/Invoke
  0.695 [0.553, 0.902]; overlap: no.**
- **ROC-AUC: capability 0.980 [0.941, 1.000]; P/Invoke
  0.645 [0.441, 0.847]; overlap: no.**

Because the operating-point F1 CIs overlap but the threshold-free PR-AUC and
ROC-AUC CIs separate: **ranking favors capability; the operating point does
not separate at n=32 positives; neither is a result.** No feature was added to
rescue it.

### Holdout FPR (565 external benign EXEs)

Main holdout rows use the OOF threshold; 0.5 is the historical comparison.
Any 0/565 below is not a result.

| model | OOF thr | @0.5 flagged | @0.5 FPR [CI] | @OOF flagged | @OOF FPR [CI] |
|---|---:|---:|---|---:|---|
| capability_uncapped | 0.559 | 35/565 | 6.2% [0.042, 0.089] | 19/565 | 3.4% [0.022, 0.052] |
| capability_capped | 0.976 | 125/565 | 22.1% [0.148, 0.311] | 6/565 | 1.1% [0.004, 0.023] |
| capability_policy | 0.130 | 13/565 | 2.3% [0.013, 0.039] | 101/565 | 17.9% [0.111, 0.258] |
| structural_policy | 0.332 | 173/565 | 30.6% [0.216, 0.402] | 182/565 | 32.2% [0.233, 0.416] |
| structural_all_diagnostic | 0.075 | 40/565 | 7.1% [0.043, 0.112] | 100/565 | 17.7% [0.121, 0.268] |
| capability_all | 0.064 | 13/565 | 2.3% [0.013, 0.041] | 108/565 | 19.1% [0.119, 0.279] |
| implmap_only | 4.000 | 91/565 | 16.1% [0.109, 0.232] | 48/565 | 8.5% [0.051, 0.130] |
| file_size_only_diagnostic | -101376.000 | 0/565 | 0.0% [0.000, 0.000] | 361/565 | 63.9% [0.475, 0.763] |

At 0.5, **capability-only is 35/565 = 6.2%** and the **full model
(capability + all counts) is 13/565 = 2.3%**. At OOF, capability is 19/565 =
3.4% and the full model is 108/565 = 19.1%. The historical 2.3% therefore
belongs to the full model at 0.5, not to capability-only. Capability's OOF
threshold is **0.559**, close
to 0.5; the full model's OOF threshold is
**0.064**. No 0/565 row is
headlined; the capped model's 6/565 at OOF is the only low-FPR row.

### LOCO at the fixed 0.5 operating point

Mixed folds hold out one positive cluster plus round-robin benign clusters;
every benign cluster is held out once and no cluster appears in fold-train.
Primary table is at **0.5**, not per-fold thresholds.

| scope / model | recall [CI] | FPR [CI] | F1 [CI] | PR-AUC [CI] | ROC-AUC [CI] |
|---|---|---|---|---|---|
| verified / a_majority | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.705 [0.367, 0.868] | 0.544 [0.225, 0.766] | 0.500 [0.500, 0.500] |
| verified / b_implmap_only | 0.942 [0.744, 0.983] | 0.636 [0.490, 0.776] | 0.761 [0.373, 0.908] | 0.779 [0.397, 0.913] | 0.800 [0.636, 0.871] |
| verified / c_file_size_only | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.817 [0.292, 0.976] | 0.788 [0.477, 0.917] |
| verified / d_tlsh_knn | 0.844 [0.578, 0.918] | 0.496 [0.264, 0.682] | 0.747 [0.352, 0.893] | 0.811 [0.167, 0.956] | 0.723 [0.265, 0.861] |
| verified / e_structural_policy | 0.968 [0.846, 0.992] | 0.155 [0.067, 0.264] | 0.923 [0.727, 0.975] | 0.920 [0.737, 0.983] | 0.931 [0.865, 0.971] |
| verified / f_capability | 0.981 [0.900, 1.000] | 0.016 [0.000, 0.039] | 0.984 [0.913, 0.997] | 0.998 [0.976, 1.000] | 0.997 [0.987, 1.000] |
| verified / g_capability_capped | 0.974 [0.877, 0.996] | 0.031 [0.000, 0.082] | 0.974 [0.875, 0.994] | 0.997 [0.969, 1.000] | 0.996 [0.980, 1.000] |
| verified / h_capability_policy | 0.981 [0.900, 1.000] | 0.039 [0.006, 0.094] | 0.974 [0.877, 0.994] | 0.997 [0.969, 1.000] | 0.996 [0.980, 1.000] |
| verified / i_capability_all | 0.987 [0.912, 1.000] | 0.031 [0.000, 0.082] | 0.981 [0.898, 0.996] | 0.998 [0.973, 1.000] | 0.997 [0.985, 1.000] |
| positive / a_majority | 0.580 [0.254, 1.000] | 0.977 [0.904, 1.000] | 0.534 [0.310, 0.744] | 0.548 [0.346, 0.728] | 0.302 [0.136, 0.526] |
| positive / b_implmap_only | 0.953 [0.872, 0.986] | 0.636 [0.490, 0.776] | 0.815 [0.575, 0.920] | 0.820 [0.640, 0.932] | 0.820 [0.732, 0.892] |
| positive / c_file_size_only | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.000 [0.000, 0.000] | 0.831 [0.463, 0.956] | 0.755 [0.505, 0.872] |
| positive / d_tlsh_knn | 0.821 [0.604, 0.898] | 0.496 [0.264, 0.682] | 0.773 [0.471, 0.898] | 0.817 [0.352, 0.951] | 0.672 [0.328, 0.824] |
| positive / e_structural_policy | 0.962 [0.867, 0.987] | 0.140 [0.053, 0.267] | 0.940 [0.833, 0.978] | 0.962 [0.873, 0.990] | 0.948 [0.898, 0.980] |
| positive / f_capability | 0.981 [0.946, 1.000] | 0.023 [0.000, 0.069] | 0.983 [0.951, 0.997] | 0.999 [0.990, 1.000] | 0.998 [0.991, 1.000] |
| positive / g_capability_capped | 0.981 [0.935, 0.996] | 0.031 [0.000, 0.082] | 0.981 [0.942, 0.994] | 0.998 [0.987, 1.000] | 0.997 [0.988, 1.000] |
| positive / h_capability_policy | 0.981 [0.935, 0.996] | 0.054 [0.000, 0.140] | 0.974 [0.929, 0.992] | 0.998 [0.987, 1.000] | 0.997 [0.988, 1.000] |
| positive / i_capability_all | 0.981 [0.935, 0.996] | 0.062 [0.007, 0.148] | 0.972 [0.924, 0.990] | 0.998 [0.985, 1.000] | 0.996 [0.984, 0.999] |

The fixed 0.5 removes the previous 0.000 FPR headline: capability FPR is
0.016 (verified)
and 0.023
(positive), with CIs that include zero. P/Invoke's raw-count 0.5 means "any
P/Invoke entry", so its 0.5 FPR is
0.636; its
fold-trained threshold of 4 gives the sensitivity FPR below.

Fold-threshold sensitivity (verified scope; positive scope is similar):

| model | fold-threshold range | pooled FPR at fold threshold | per-fold FPR range |
|---|---|---|---|
| f_capability | 0.993–0.997 | 0.000 | 0.000–0.000 |
| b_implmap_only | 4.000–4.000 | 0.202 | 0.000–1.000 |
| e_structural_policy | 0.849–0.965 | 0.116 | 0.000–1.000 |

Capability's per-fold thresholds are ~0.99, so the threshold row still shows
0 FPR; that is the in-sample artifact the fixed 0.5 table replaces. No nested
CV is used; 0.5 is the honest fixed point, and the threshold rows are
sensitivity only. The file-size rule has no meaningful 0.5 (negative-byte
score); its threshold row is the only comparable one.

### Automated label-quality audit (not a gold audit)

Header: **Automated label-quality audit (not a gold audit)**. Audited 1540 rows;
no gold fields were read, filled or inferred.

| class | rows | evidence mean | MB-only | multi-source | config | lineage-only | no family-scoped | obfuscated | conflicts |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| verified | 154 | 7.0 | 0 | 154 | 94 | 11 | 49 | 10 | 0 |
| verified_other | 58 | 7.0 | 0 | 58 | 31 | 0 | 0 | 1 | 56 |
| benign | 704 | 7.0 | 0 | 0 | 0 | 0 | 704 | 12 | 0 |
| unverified | 624 | 7.0 | 530 | 51 | 16 | 0 | 542 | 126 | 51 |

`lineage_only` is the project flag (`lbl_reason.lineage_only`, 11 verified);
`no family-scoped` is the broader DB-only count (49 verified). MB-signature-
only is **530**, all unverified; multi-source is
**263**. Conflicts are voter
disagreements, not proof of a wrong label.

Plain pairwise agreement is high for MB vs own-YARA (.968, n=220) and
Malpedia vs YARAify (.991, n=115), lower for MB vs rat-king-parser (.602,
n=186) and own-YARA vs rat-king-parser (.577, n=182). Obfuscated rows are
sparse; only MB vs YARAify has n>=10 (.529, n=17).

Conflict categories (not label changes):

| class | majority supports current | majority different | tie | no family votes |
|---|---:|---:|---:|---:|
| verified | 154 | 0 | 0 | 0 |
| verified_other | 16 | 0 | 42 | 0 |
| benign | 0 | 0 | 0 | 704 |
| unverified | 529 | 21 | 31 | 43 |
| gold candidates | 13 | 9 | 7 | 1 |

Of the **56 verified_other conflict flags**, **14 are majority-supported, 0 are
majority-different, and 42 are ties** — not 56 contradictions. Top pairs:
AsyncRAT|XWorm 49, AsyncRAT|VenomRAT 5, AsyncRAT|DcRat 1, AsyncRAT|QuasarRAT 1.
Of the **51 unverified conflicts**, **20 are majority-different and 31 are
ties**; top pairs: AsyncRAT|XWorm 28, AsyncRAT|DcRat 19, AsyncRAT|QuasarRAT 2,
AsyncRAT|VenomRAT 2; **no label is inferred**. The 30 gold candidates carry
**11 evidence-conflict flags** (4 majority-different, 7 tie); this is not a
human verdict. Gold remains **30 rows / 0 filled / no merge**.

### Stage 2 eligibility (unchanged)

Only AsyncRAT and XWorm qualify (>=20 rows, >=10 clusters). Test macro F1
**0.931 [0.807, 1.000]** on 29 rows.
Note: **diagnostic 2-family LightGBM on 29 test rows; eligibility is P2; not a result.** The excluded families still get no metric.

### Gate (unchanged)

Stage 1 FAIL (154 rows / 52 clusters, largest 89 = 57.8%); active benign PASS
(129/70, 14.7%); Stage 2 FAIL. Overall FAIL. The gate before and after is
identical and `Data/DataSet.db` SHA-256 is unchanged. No detector claim
follows from any number above.

## Fixup Phase 2.1c — corrected evaluation (2026-11-28)

> **Superseded operating point:** Phase 2.1d uses grouped OOF thresholds. The
> in-sample table below is retained as the overfit sensitivity/history record.

**DIAGNOSTIC ONLY — dataset gate failed; not a result.** No data was
collected, no label or cluster was changed, and no model was tuned on test.
D2/WS3 (Hassan 70/30) is **not run**: it awaits explicit approval.

### Operating point and thresholds

The main test table uses a **threshold fitted on train** to maximize F1
(`scores >= threshold`). The 0.5 row is the explicit default reference. Test
labels never choose a threshold. PR-AUC and ROC-AUC are threshold-free; their
95% CIs resample clusters. For fixed predictors (majority, TLSH kNN) there is
no threshold.

### Cap (D1, train only)

Largest train positive cluster `053fa0de…` capped **89 → 10 rows** (79
removed, numpy seed 42). Train **238 rows / 148 positives → 159 / 69**.
Val/test, the DB, labels and split files are unchanged. At the train-chosen
threshold the capped model is F1 **0.897** (vs 0.877 uncapped); at 0.5 it is
0.935. On the holdout, 0.5 FPR was 22.1%; the historical in-sample threshold
FPR was 0/565 and is superseded by the Phase 2.1d OOF table. The cap remains
an ablation, not a gate fix.

### Test split (52 rows, 32 positives, 48 clusters)

CM = TN/FP/FN/TP at the train-chosen threshold.

| model | threshold | F1 @ 0.5 | F1 @ train thr | PR-AUC | ROC-AUC | CM @ thr |
|---|---:|---:|---:|---:|---:|---|
| a_majority | — | 0.762 | 0.762 | 0.615 | 0.500 | 0/20/0/32 |
| b_implmap_only | 4.000 | 0.795 | 0.788 | 0.695 | 0.645 | 12/8/6/26 |
| c_file_size_only_diagnostic | -101376.000 | 0.000 | 0.400 | 0.827 | 0.688 | 20/0/24/8 |
| d_tlsh_knn | — | 0.750 | 0.750 | 0.666 | 0.475 | 17/3/11/21 |
| e_structural_policy | 0.879 | 0.857 | 0.847 | 0.933 | 0.880 | 18/2/7/25 |
| e2_structural_all_diagnostic | 0.972 | 0.831 | 0.731 | 0.929 | 0.881 | 19/1/13/19 |
| f_capability_uncapped | 0.998 | 0.921 | 0.877 | 0.988 | 0.980 | 20/0/7/25 |
| g_capability_capped | 0.998 | 0.935 | 0.897 | 0.989 | 0.981 | 20/0/6/26 |
| h_capability_policy | 0.997 | 0.918 | 0.877 | 0.992 | 0.987 | 20/0/7/25 |
| i_capability_all | 0.998 | 0.900 | 0.857 | 0.992 | 0.988 | 20/0/8/24 |
| j_random_split_leaky | 0.993 | 0.960 | 0.951 | 0.999 | 0.998 | 39/0/6/58 |

95% CIs at the train-chosen operating point:

| model | F1 CI | PR-AUC CI | ROC-AUC CI |
|---|---|---|---|
| a_majority | [0.649, 0.865] | [0.481, 0.763] | [0.500, 0.500] |
| b_implmap_only | [0.677, 0.904] | [0.553, 0.902] | [0.441, 0.847] |
| c_file_size_only_diagnostic | [0.124, 0.636] | [0.680, 0.934] | [0.547, 0.851] |
| d_tlsh_knn | [0.585, 0.864] | [0.496, 0.832] | [0.301, 0.649] |
| e_structural_policy | [0.727, 0.943] | [0.870, 0.987] | [0.786, 0.973] |
| e2_structural_all_diagnostic | [0.578, 0.857] | [0.850, 0.984] | [0.765, 0.971] |
| f_capability_uncapped | [0.769, 0.951] | [0.959, 1.000] | [0.941, 1.000] |
| g_capability_capped | [0.792, 0.968] | [0.961, 1.000] | [0.947, 1.000] |
| h_capability_policy | [0.769, 0.951] | [0.967, 1.000] | [0.961, 1.000] |
| i_capability_all | [0.744, 0.939] | [0.965, 1.000] | [0.958, 1.000] |
| j_random_split_leaky | [0.840, 0.984] | [0.986, 1.000] | [0.989, 1.000] |

The random split (j) is leaky by construction: its train-chosen F1 is
**0.951**, **+0.074**
above the cluster-split capability model. It is not a result.

**Feature policy (P1):** dropping the four container fields does not hurt on
this test set: structural policy 0.847
vs all counts 0.731;
capability+policy 0.877
vs capability+all 0.857.
The policy matrix is separate under `Data/Features/policy/`.

### Direct answer: capability vs P/Invoke

At the train-chosen threshold:

- **F1: capability 0.877 [0.769, 0.951]; P/Invoke
  0.788 [0.677, 0.904]; overlap: yes.**
- **PR-AUC: capability 0.988 [0.959, 1.000]; P/Invoke
  0.695 [0.553, 0.902]; overlap: no.**
- **ROC-AUC: capability 0.980 [0.941, 1.000]; P/Invoke
  0.645 [0.441, 0.847]; overlap: no.**

F1 at 0.5 is 0.921 (capability) vs 0.795
(P/Invoke); the train-chosen threshold lowers F1 for both.

Because the operating-point F1 CIs overlap but the threshold-free PR-AUC and
ROC-AUC CIs separate: **ranking favors capability; the operating point does
not separate at n=32 positives; neither is a result.** No feature was added to
rescue the comparison.

### Holdout FPR (full 565-row external partition)

The 30% Hassan ablation (D2) was not run. This is the **historical in-sample
view, superseded by Phase 2.1d**; its 0/565 rows are not a result.
`capability_uncapped` is capability-only; `capability_all` is the full model
(capability + all counts); `capability_policy` is capability + policy counts.

| model | threshold | @0.5 flagged | @0.5 FPR [CI] | @thr flagged | @thr FPR [CI] |
|---|---:|---:|---|---:|---|
| capability_uncapped | 0.998 | 35/565 | 6.2% [0.042, 0.089] | 0/565 | 0.0% [0.000, 0.000] |
| capability_capped | 0.998 | 125/565 | 22.1% [0.148, 0.311] | 0/565 | 0.0% [0.000, 0.000] |
| capability_policy | 0.997 | 13/565 | 2.3% [0.013, 0.039] | 0/565 | 0.0% [0.000, 0.000] |
| structural_policy | 0.879 | 173/565 | 30.6% [0.216, 0.402] | 102/565 | 18.1% [0.111, 0.270] |
| structural_all_diagnostic | 0.972 | 40/565 | 7.1% [0.043, 0.112] | 6/565 | 1.1% [0.003, 0.022] |
| capability_all | 0.998 | 13/565 | 2.3% [0.013, 0.041] | 0/565 | 0.0% [0.000, 0.000] |
| implmap_only | 4.000 | 91/565 | 16.1% [0.109, 0.232] | 48/565 | 8.5% [0.051, 0.130] |
| file_size_only_diagnostic | -101376.000 | 0/565 | 0.0% [0.000, 0.000] | 361/565 | 63.9% [0.475, 0.763] |

**Attribution:** at 0.5, **capability-only is 35/565 = 6.2%**, while the
**full model (capability + all counts) is 13/565 = 2.3%**. Historical 2.3%
lines therefore refer to the full model, not capability-only. At the
train-chosen threshold both flag 0/565; that is a boundary/operating-point
artifact of a threshold near 0.998 on a shifted holdout, **not** evidence of a
perfect detector. The 0/565 CIs degenerate to [0, 0]; treat them as 0/565,
not a precise zero rate.

The cap raises the 0.5 FPR from 6.2% to 22.1% for capability-only. At the
train threshold the capped model flags 0/565. This is a trade-off, not a
tuning opportunity on the holdout.

### Obfuscated test subset

Only **6 of 52** test rows are obfuscated, and only **4 are positives** (below
the 20-positive floor). Counts only: 46 plain / 6 obfuscated.

### LOCO (mixed positive and benign clusters)

Each fold holds out one positive cluster plus its round-robin benign clusters.
Every benign cluster is held out exactly once; no held-out cluster appears in
fold-train. Both scopes have 70 benign clusters, 129 benign rows and **0 mixed
clusters**. Folds: **52** (verified AsyncRAT only) and **82** (verified +
verified_other). Pooled rows: 283 and 341.

| scope / model | recall [CI] | FPR [CI] | F1 [CI] | PR-AUC [CI] | ROC-AUC [CI] |
|---|---|---|---|---|---|
| verified / a_majority | 1.000 [1.000, 1.000] | 1.000 [1.000, 1.000] | 0.705 [0.367, 0.868] | 0.544 [0.225, 0.766] | 0.500 [0.500, 0.500] |
| verified / b_implmap_only | 0.916 [0.653, 0.972] | 0.202 [0.108, 0.327] | 0.879 [0.587, 0.950] | 0.779 [0.397, 0.913] | 0.800 [0.636, 0.871] |
| verified / c_file_size_only | 0.896 [0.622, 0.965] | 0.628 [0.412, 0.787] | 0.740 [0.327, 0.901] | 0.817 [0.292, 0.976] | 0.788 [0.477, 0.917] |
| verified / d_tlsh_knn | 0.844 [0.578, 0.918] | 0.496 [0.264, 0.682] | 0.747 [0.352, 0.893] | 0.811 [0.167, 0.956] | 0.723 [0.265, 0.861] |
| verified / e_structural_policy | 0.922 [0.778, 0.957] | 0.116 [0.032, 0.236] | 0.913 [0.717, 0.964] | 0.920 [0.737, 0.983] | 0.931 [0.865, 0.971] |
| verified / f_capability | 0.935 [0.754, 0.981] | 0.000 [0.000, 0.000] | 0.966 [0.860, 0.991] | 0.998 [0.976, 1.000] | 0.997 [0.987, 1.000] |
| verified / g_capability_capped | 0.929 [0.711, 0.978] | 0.000 [0.000, 0.000] | 0.963 [0.831, 0.989] | 0.997 [0.969, 1.000] | 0.996 [0.980, 1.000] |
| verified / h_capability_policy | 0.942 [0.765, 0.984] | 0.000 [0.000, 0.000] | 0.970 [0.867, 0.992] | 0.997 [0.969, 1.000] | 0.996 [0.980, 1.000] |
| verified / i_capability_all | 0.922 [0.711, 0.968] | 0.000 [0.000, 0.000] | 0.959 [0.831, 0.984] | 0.998 [0.973, 1.000] | 0.997 [0.985, 1.000] |
| positive / a_majority | 0.580 [0.254, 1.000] | 0.977 [0.904, 1.000] | 0.534 [0.310, 0.744] | 0.548 [0.346, 0.728] | 0.302 [0.136, 0.526] |
| positive / b_implmap_only | 0.925 [0.787, 0.973] | 0.202 [0.108, 0.327] | 0.903 [0.750, 0.960] | 0.820 [0.640, 0.932] | 0.820 [0.732, 0.892] |
| positive / c_file_size_only | 0.873 [0.652, 0.950] | 0.628 [0.412, 0.787] | 0.774 [0.469, 0.911] | 0.831 [0.463, 0.956] | 0.755 [0.505, 0.872] |
| positive / d_tlsh_knn | 0.821 [0.604, 0.898] | 0.496 [0.264, 0.682] | 0.773 [0.471, 0.898] | 0.817 [0.352, 0.951] | 0.672 [0.328, 0.824] |
| positive / e_structural_policy | 0.882 [0.768, 0.920] | 0.078 [0.018, 0.176] | 0.914 [0.812, 0.949] | 0.962 [0.873, 0.990] | 0.948 [0.898, 0.980] |
| positive / f_capability | 0.934 [0.802, 0.974] | 0.000 [0.000, 0.000] | 0.966 [0.890, 0.987] | 0.999 [0.990, 1.000] | 0.998 [0.991, 1.000] |
| positive / g_capability_capped | 0.929 [0.806, 0.972] | 0.000 [0.000, 0.000] | 0.963 [0.892, 0.986] | 0.998 [0.987, 1.000] | 0.997 [0.988, 1.000] |
| positive / h_capability_policy | 0.939 [0.837, 0.972] | 0.000 [0.000, 0.000] | 0.968 [0.911, 0.986] | 0.998 [0.987, 1.000] | 0.997 [0.988, 1.000] |
| positive / i_capability_all | 0.920 [0.780, 0.963] | 0.000 [0.000, 0.000] | 0.958 [0.877, 0.981] | 0.998 [0.985, 1.000] | 0.996 [0.984, 0.999] |

Capability vs P/Invoke (verified scope): recall 0.935
vs 0.916, FPR
0.000 vs
0.202. Positive scope:
recall 0.934 vs
0.925, FPR
0.000 vs
0.202.

Capability's 0/129 FPR is at a fold-train threshold near 0.99 and its
percentile CI degenerates at the boundary; it is a diagnostic, not a
production FPR. Recall CIs overlap with P/Invoke. Precision is no longer fixed
at 1.0 because the test folds now contain benign rows; the old positive-only
F1 is not used as a detection metric.

### Stage 2 eligibility (P2)

A family needs at least 20 rows and 10 clusters. Only AsyncRAT and XWorm
qualify; the gate code is unchanged.

| family | rows | clusters | eligible | test rows | test clusters | low support |
|---|---:|---:|---|---:|---:|---|
| AsyncRAT | 154 | 52 | yes | 14 | 14 | no |
| XWorm | 49 | 23 | yes | 15 | 12 | no |
| VenomRAT | 5 | 4 | no | 1 | 1 | yes |
| QuasarRAT | 3 | 2 | no | 1 | 1 | yes |
| DcRat | 1 | 1 | no | 1 | 1 | yes |

AsyncRAT vs XWorm on the test split: macro F1 **0.931**
[0.807, 1.000]; AsyncRAT P/R/F1
0.875/1.000/0.933
(support 14), XWorm
1.000/0.867/0.929
(support 15). Note: **diagnostic 2-family LightGBM on 29 test rows; eligibility is P2; not a result.** The CI
is a cluster bootstrap over 29 rows.

### Gate (unchanged)

Stage 1 FAIL (154 rows / 52 clusters, largest 89 = 57.8%); active benign PASS
(129/70, 14.7%); Stage 2 FAIL (AsyncRAT, QuasarRAT, DcRat). Overall FAIL.
The gate before and after this work is identical, and `Data/DataSet.db` has the
same SHA-256; no label, cluster, split or threshold changed. No detector claim
follows from any number above.

## Fixup Phase 2.1 — labeler-bias audit (2026-11-28)

**DIAGNOSTIC ONLY — evidence, not proof.** Population: the 498 rows with
`lbl_sts='unverified'` and `sug_fam='AsyncRAT'` (106 obfuscated, 392 plain).

Each row's `label_evidence` was classified by whether any voter other than the
MalwareBazaar (MB) signature produced a family verdict. These are
MB-signature **suggestions**, not confirmed AsyncRAT:

| class | plain | obfuscated | total |
|---|---:|---:|---:|
| (a) no family verdict at all | 0 | 0 | 0 |
| (b) only the MB signature said AsyncRAT | 392 | 106 | **498** |
| (c) other/conflicting family verdict | 0 | 0 | 0 |

So **all 498 depend on the MB signature alone**, and **all 106 obfuscated
rows have zero family-scoped verdicts** (the MB evidence on these 498 rows
is `scope=lineage`).
There is no obfuscated-specific blind spot in this table: the 392 plain builds
show exactly the same pattern.

Per-voter diagnostics (same population):

| signal | plain (392) | obfuscated (106) |
|---|---:|---:|
| rat_king_parser config error | 366 (93.4%) | 90 (84.9%) |
| YARAify `reason=no_family` | 391 | 106 |
| Elastic / Malpedia / own-YARA family match | 0 | 0 |
| DIE label | 392 plain | 15 obfuscator types |

The 16 obfuscated rows without a parser error still got no family verdict, so
parser failure alone does not explain the gap (26 plain rows are in the same
position). The evidence points to
historical builds that only the MB signature recognises; obfuscation is not
the discriminator here. Full per-row reasons:
`Data/Audit/unverified_asyncrat_reasons.json`.

### Gold status (WS9)

The sheet has **30 rows, 0 filled**; all 30 `file_path` values resolve and
match their SHA-256. `merge_gold_review.py --dry-run` reports 0 updates;
`--write` was **not** run. Per-voter precision/recall cannot be computed until
a human fills the sheet. The stale `Data/Gold/review_sheet.md` was removed in
Phase 2.1d; the current markdown is `Data/Gold/review/gold_review_sheet.md`.

## Phase 4 — LOCO, abstention, explainability, Stage 2 rules (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed (Stage 1 57.8%, Stage 2 FAIL).**
No more data was collected; the ceiling in `Docs/limitations.md` stands.

### Cluster-level LOCO (primary honest metric)

Leave-one-cluster-out over **all 152 clusters** (82 positive folds, 212
positives / 129 negatives); every row is tested exactly once, no cluster is
split. Models: LightGBM full, capability-only, structural-only, TLSH kNN.
Metrics are aggregated over folds; CIs resample clusters.

| model | precision | recall | F1 | PR-AUC | F1 95% CI |
|---|---:|---:|---:|---:|---|
| full | 0.986 | 0.976 | 0.981 | 0.999 | [0.938, 0.994] |
| capability only | 0.990 | 0.976 | **0.983** | 0.999 | [0.946, 0.994] |
| structural only | 0.889 | 0.943 | 0.915 | 0.982 | [0.793, 0.961] |
| TLSH kNN | 0.731 | 0.821 | 0.773 | 0.817 | [0.471, 0.898] |

Obfuscation strata (DIE): full 0.990 plain / **0.818 obfuscated**;
capability 0.990 / 0.857; structural 0.923 / 0.762; kNN 0.786 / 0.560.
The obfuscated stratum is only 20 rows.

These numbers are high because many clusters are near-duplicate builds; they
are diagnostic, not a real-world claim.

### Abstention (calibrated on training only)

Threshold: combined `TypeRef + MemberRef` count **< 357** abstains
(5th percentile of training positives, fitted on the train split only).
Missing carvers/non-.NET abstain by construction; no method-body detector is
used. Rates over all 1,824 rows:

| class | rows | abstained | rate |
|---|---:|---:|---:|
| verified | 154 | 14 | **9.1%** |
| verified_other | 58 | 2 | 3.4% |
| benign | 704 | 464 | 65.9% |
| unverified | 624 | 388 | 62.2% |
| rejected_non_dotnet | 278 | 278 | 100% |

Coverage on verified AsyncRAT: **90.9%** (140/154 evaluated). The high benign
abstention is a real limitation: most benign EXEs have fewer references.

### Explainability

- LightGBM gain (global): `System.Diagnostics.Process::GetProcesses`,
  `System.Security.Cryptography.CipherMode`,
  `System.Net.Sockets.Socket::Dispose`, …
- Per-sample top-10 contributions via LightGBM `pred_contrib` (SHAP-compatible
  values; no external SHAP dependency). Example template: “references
  `Process::GetProcesses`, `SymmetricAlgorithm::set_Key`; nearest TLSH sample
  `7b92ddcdd8d9` (distance 53)”.
- TLSH kNN nearest training sample + distance. No causal claim.

### Hassan 2023 non-name CLR-header comparison

Simplified non-name CLR-header baseline (booleans/table presence/counts,
14 features; no names or “all references”), same LOCO folds:

| feature set | precision | recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|
| capability (ours) | 0.990 | 0.976 | 0.983 | 0.999 |
| CLR-header (Hassan-style) | 0.852 | 0.896 | 0.874 | 0.737 |
| structural | 0.889 | 0.943 | 0.915 | 0.982 |

This is a methodology comparison, not a superiority claim; the split is
degenerate and the CLR extractor is a faithful subset, not the paper’s exact
34 non-name features.

### Stage 2 rules/kNN (no trained family model)

Rules + TLSH nearest known family, with abstention:

- 58 verified_other rows; **24 abstain (41.4%)**.
- XWorm: 31 correct, 1 confused as VenomRAT, 17 abstain.
- VenomRAT: 2 correct, 3 abstain.
- QuasarRAT 3/3 and DcRat 1/1 abstain (tiny families need explicit
  confidence). Among the 34 decided rows: 33 correct, 1 error.

### Holdout and ceiling

- Baseline train-split **full model** (capability + all counts): Hassan FPR
  **13/565 = 2.3%**. Capability-only is **35/565 = 6.2%** — see Phase 2.1d.
- Phase 4 all-primary model: **61/565 = 10.8%** — training composition
  matters; both are diagnostic.
- Stage 1 remains **FAIL** (154/52, largest 89 = 57.8%; 24 short).
- Stage 2 remains FAIL (AsyncRAT/Quasar/DcRat); XWorm and VenomRAT pass.
- Gold: 30 rows, 0 missing, 0 filled — human pending.


## Phase 3.0 — frozen ceiling and orchestrator hardening (2026-11-28)

**DIAGNOSTIC ONLY — no real-world claim.** The dataset is frozen at 1,824
rows; no batch 3, no family queue, no uploads.

- Stage 1 `AsyncRAT` 154 rows / 52 clusters / largest **89 = 57.8% FAIL**
  (24 verified short of the 178 needed at that cluster size). Benign active
  129 / 70 / 14.7% PASS.
- Stage 2: AsyncRAT FAIL, QuasarRAT 3/2/66.7% FAIL, DcRat 1/1 FAIL;
  XWorm 49/23/49.0% PASS and VenomRAT 5/4/40% PASS; overall FAIL.
- Lineage-only verified: **11** (kept). With them 57.8%, without 62.2% —
  failure does not depend on them.
- Class DBs 154 / 58 / 704; evidence 12,768; 0 NULL clusters.
- DIE at 1,824 rows: **1,603 plain / 221 obfuscated / 0 unknown**.
- Batches: batch 1 + 2 = 700 historical samples; batch-2 verified yield
  **24/350 = 6.9%**, below the 13% stop line.
- Split 341 rows: train 238/148/23 clusters at 60.1% (degenerate); val 51
  (32 positives, 30 clusters, 6.2%); test 52 (32, 29, 12.5%); 0 spans;
  reference_only NULL.
- Cross-family pairs: XWorm↔AsyncRAT 88; DcRat↔AsyncRAT 64 — human/gold
  items, no merge.
- Holdout FPR **13/565 = 2.3%** is the **full model** (capability + all
  counts), not capability-only; capability-only is 35/565 = 6.2% — see
  Phase 2.1d. LOCO not triggered; all model numbers diagnostic (capability F1
  0.921 at this state; 0.963 was the 1,505 state).

### Orchestrator state/lock fix

Each stage now takes a PID lock under `Data/Pipeline/locks/`, records
`started_at`, `finished_at`, wall seconds, return code, output count and
marker mtime, and fails (status `failed:stale_output`, never `ok`) if its
marker is not newer than the stage start. A second YARAify/DIE process is
refused while the lock PID is alive.

Cold stage work remains **~43 min** (labeler 256 s, carvers ~210 s each,
structure 192 s, YARAify **1,217 s** in the cold log). The state entry
`yaraify=2.3 s` comes from a later all-reused verification invocation, not
from the cold lookup run; the new lock/freshness fields make this auditable.
Warm pass after the fix: **15.2 s**, 20 stages skipped (`cached`), only the two
idempotent importers ran (7.8 s + 7.2 s), YARAify skipped. State 22/22 `ok`.

Gold: 30 rows, 0 missing, 0 filled (human pending). Details in
`Docs/limitations.md`.

## Phase 1.9 — batch 2, cold/warm orchestrator (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed; not a result.**

Batch 2 finished (350/350 historical AsyncRAT samples) and the first
fingerprint-aware orchestrator pass ran. Stage 1 improves but still fails on
the largest-share rule; the batch-2 verified yield is **6.9%**, below the
agreed 13% stop threshold, so no further history was downloaded.

### Dataset

- **1,824 rows**, 0 NULL `cluster_id`, **1,228 clusters**.
- Evidence **12,768 = 7 × 1,824**.
- Labels: 154 `verified`, 58 `verified_other`, 704 `benign`, 624
  `unverified`, 278 `rejected_non_dotnet`, 4 `review`, 2 `reference_only`.
- Class DBs: AsyncRAT **154**, OtherMalwares **58**, Benign 704.
- DIE: 1,603 plain / 221 obfuscated / 0 unknown (28 protector families).
- Batch 2: 24 new verified (6.9%), 66 new non-.NET; 350/350 downloaded.

### Stage 1 (FAIL)

| state | rows | clusters | largest | share | result |
|---|---:|---:|---:|---:|---|
| before batch 2 | 1,505 | 32 | 86 | 57.8% | FAIL |
| after batch 2 | 1,824 | **52** | **89** | **57.8%** | **FAIL** |

Active benign: **70 clusters / 14.7% — PASS**.

Lineage-only sensitivity (11 rows: the previous 9 plus `26e8b9f0`, `b5ddcd46`):

| variant | rows | clusters | largest | share | result |
|---|---:|---:|---:|---:|---|
| with lineage-only | 154 | 52 | 89 | 57.8% | FAIL |
| without lineage-only | 143 | 41 | 89 | 62.2% | FAIL |

The gate fails **with or without** the 11 lineage-only rows; they are not the
reason for the failure and were not downgraded.

### Stage 2 (FAIL)

| family | rows | clusters | largest share | result |
|---|---:|---:|---:|---|
| AsyncRAT | 154 | 52 | 57.8% | FAIL |
| XWorm | 49 | 23 | 49.0% | **PASS** |
| VenomRAT | 5 | 4 | 40.0% | PASS |
| QuasarRAT | 3 | 2 | 66.7% | FAIL |
| DcRat | 1 | 1 | 100.0% | FAIL |

XWorm now has enough independent clusters; the remaining failures are
AsyncRAT's 89-row cluster and singleton QuasarRAT/DcRat.

### Split (341 primary: 212 positives, 129 negatives)

| split | rows | pos | neg | pos clusters | neg clusters | largest pos share | degenerate |
|---|---:|---:|---:|---:|---:|---:|---|
| train | 238 | 148 | 90 | 23 | 32 | 60.1% | **yes** |
| val | 51 | 32 | 19 | 30 | 19 | 6.2% | no |
| test | 52 | 32 | 20 | 29 | 19 | 12.5% | no |

- Correction: earlier text said 180 positives / 161 negatives; the DB-backed
  count is **212 / 129**. 0 cluster spans; 0 stale split files; split files =
  `.done` = 341.
- The rebalance post-pass made **no move**: after batch 2 the test split is
  already healthy (12.5%), and the 14-row cluster from Phase 1.7 no longer
  dominates. Train remains degenerate at 60.1%.
- `reference_only`/`unverified`/gold rows have NULL splits.

### Baselines (test 52 rows, 32 positives, 29 clusters)

| model | F1 | PR-AUC |
|---|---:|---:|
| majority | 0.762 | 0.615 |
| logistic, structural | 0.000 | 0.827 |
| TLSH kNN | 0.750 | 0.666 |
| LightGBM, full | 0.900 | 0.992 |
| LightGBM, capability only | **0.921** | 0.988 |
| LightGBM, structural only | 0.831 | 0.929 |

- `not_a_result=true` because train is degenerate; structural confound false.
- LOCO not triggered (23 train positive clusters). Holdout FPR **13/565 = 2.3%**
  is the **full model**; capability-only is 35/565 = 6.2% — see Phase 2.1d.

### Cross-family audit (human/gold item, no merge)

Two test→train pairs within TLSH 100:

- XWorm `00fe40a8` ↔ AsyncRAT `053fa0de`, distance **88**.
- DcRat `054498f9` ↔ AsyncRAT `053fa0de`, distance **64**.

Both sides carry strong family-scoped voters and valid configs; the family
guard is intentional. Leave as-is, no automatic merge or relabel.

### Orchestrator cold vs warm

- **Cold:** 22 stages, each once; carvers once; YARAify 1 req/s (one process);
  DIE 4 workers. Stage work ≈ **43 min** (labeler 256 s, carvers ~210 s each,
  structure 192 s, YARAify 1,217 s, serial stages ~60 s).
- **Warm:** **14.7 s** wall; 20 stages skipped (`cached`), only the two
  idempotent importers ran (7.2 s + 7.4 s). YARAify skipped; no carver rerun.
- `Data/Pipeline/state.json`: **22/22 stages status=ok**.

### Integrity and git

- No sample executed or uploaded; YARAify rate unchanged.
- DBs contain no real credentials (the shared auth key is absent; only .NET
  `Authorization`/`password` reference names appear).
- Dataset DBs are tracked now (`DataSet.db` 32.8 MiB, `Benign.db` 13.9 MiB,
  `AsyncRAT.db` 3.4 MiB, `OtherMalwares.db` 1.2 MiB); generated JSONs,
  markers, logs and `Samples/` remain untracked.
- Gold review: 30 rows, **0 missing, 0 filled** (human pending).
- No commits.

### Limitations

- Stage 1 ceiling: 57.8% largest share; passing would require ≥178 verified at
  the 89-row cluster (or more independent clusters). Batch-2 yield was 6.9%,
  so more history is not justified.
- Stage 2 fails on AsyncRAT, QuasarRAT and DcRat.
- Train split remains degenerate (60.1%), so every model number is diagnostic.
- Two cross-family near-duplicate pairs remain as gold-review items.


## Phase 1.7 — YARAify, DIE, family queue, fork-label fix (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed; not a result.**

This phase closed the evidence gaps and exposed a label bug: AsyncRAT-derived
forks were being written to `AsyncRAT.db` because lineage AsyncRAT votes were
checked before family-specific fork votes. The aggregator now resolves forks
first. That is why `verified` drops from 152 to 130 while `verified_other`
rises from 9 to 40 — the labels are more correct, not worse.

### YARAify (shared key, parser bug, rerun)

- One abuse.ch key (`YARAIFY_AUTH_KEY`, else `MB_AUTH_KEY`); key present, never
  logged.
- **Parser bug:** `lookup_hash` returns `data` as a dict (`metadata`, `tasks`),
  but the old parser only accepted a list and returned `[]` for every sample.
  The fixed parser reads `static_results[].rule_name`/`malpedia_family`,
  `clamav_results[]`, `unpacked_yara_matches[]` and metadata signatures, for
  both dict and list response shapes. Curated ClamAV/metadata names only
  disambiguate conflicting static rules (sample `4902c56dfa` → AsyncRAT).
- Rerun: **1,505/1,505** evidence files, ≤1 req/s.
- **174 medium hits:** AsyncRAT 142, XWorm 27, QuasarRAT 4, DcRat 1.
  At scan time 92 hit rows were already verified, 53 unverified, 22 review,
  7 rejected; the final hit set is 116 verified + 7 verified_other.
- No generic-rule promotions; multiple-family responses are `weak/no_match`.

### Detect It Easy (obf_lvl)

Official DIE 4.1.0 Fedora 45 RPM + Fedora 45 Qt5 + `current-database` db,
run through a local wrapper. Voter updated for the 4.x JSON schema (and `-e`
removed because it suppresses the `detects` block).

- 1,505/1,505 evidence rows: **1,359 plain / 146 obfuscated / 0 unknown**.
- Top: .NET Reactor 41, UPX 21, Smart Assembly 19, Enigma 12, ConfuserEx 10,
  Dotfuscator 10, Themida/Winlicense 5, VMProtect 4, PyInstaller 4.

### Signature backfill and gold

- `downloads.signature`: **801/801 non-null**; 170 older rows backfilled from
  the full export (0 not found; no invented values).
- Gold review sheet: 30 rows, SHA-256 path resolution, **0 missing, 0 filled**;
  human audit still pending. `merge_gold_review.py --dry-run` reports 0 errors.

### Family queue (35 names, 12 available, 23 `unavailable_mb`)

181 samples downloaded (target-capped; 23 families never queried):

| family | downloaded | .NET | verified_other | unverified | rejected_non_dotnet | clusters |
|---|---:|---:|---:|---:|---:|---:|
| BitRAT | 50 | 33 | 0 | 33 | 17 | 0 |
| DcRat | 50 | 12 | 0 | 12 | 38 | 0 |
| VenomRAT | 50 | 27 | **5** | 20 | 23 | **4** |
| GhOstRAT | 16 | 1 | 0 | 1 | 15 | 0 |
| DarkRAT | 7 | 4 | 0 | 4 | 3 | 0 |
| BoratRAT | 4 | 3 | 0 | 3 | 1 | 0 |
| XieBroRAT | 2 | 0 | 0 | 0 | 2 | 0 |
| JasonRAT | 1 | 1 | 0 | 1 | 0 | 0 |
| PhoenixRAT | 1 | 1 | 0 | 1 | 0 | 0 |

Only VenomRAT reaches `verified_other` (5 samples, 4 clusters, largest 40%).
The other families lack the two independent family-scoped voters required,
so they stay `unverified`; no generic rule was used to promote them.

### AsyncRAT batch 2 (paused)

31/350 downloaded before the user paused it; the remaining 319 are
`selected` in the manifest and resumable. The 31 are included:
6 verified, 18 unverified, 7 non-.NET. No further downloads.

### Fork-label fix (aggregator)

- Rule 5 (`verified_other`) now runs before Rule 4 (`verified` AsyncRAT), and
  Rule 4 is blocked by a strong/medium non-AsyncRAT family name.
- XWorm: 32 samples / 11 clusters, supported by malpedia + rat-king (and
  YARAify on part of the set). 23 of these were previously trained as
  AsyncRAT; that is the bug this phase fixed.
- VenomRAT: 5 / 4 clusters (40%). QuasarRAT 2 / 1, DcRat 1 / 1.
- 3 new tests cover lineage AsyncRAT vs fork votes; all pass.

### Gate before/after

| state | rows | AsyncRAT verified / clusters / largest share | Stage 1 | Stage 2 | overall |
|---|---:|---|---|---|---|
| after Phase 1.6 | 1,293 | 152 / 36 / 88 (57.9%) | FAIL | FAIL | FAIL |
| after Phase 1.7 | 1,505 | **130 / 32 / 86 (66.2%)** | FAIL | FAIL | FAIL |

Stage 1 benign (active only): **70 clusters, largest 14.7% — PASS**.
Stage 2 (each family needs ≥2 clusters and ≤50% share):

| family | rows | clusters | largest share | result |
|---|---:|---:|---:|---|
| AsyncRAT | 130 | 32 | 66.2% | FAIL |
| XWorm | 32 | 11 | 59.4% | FAIL |
| VenomRAT | 5 | 4 | 40.0% | PASS |
| QuasarRAT | 2 | 1 | 100.0% | FAIL |
| DcRat | 1 | 1 | 100.0% | FAIL |

The 86-sample recent-MB cluster is 66.2% of AsyncRAT; to pass at that cluster
size the class needs ≥172 verified. Batch 2's remaining 319 would likely
reach it, but it was not run (by instruction).

### Split (greedy whole-cluster, 299 primary rows)

| split | rows | pos | neg | pos clusters | neg clusters | largest pos share | degenerate |
|---|---:|---:|---:|---:|---:|---:|---|
| cluster train | 209 | 119 | 90 | 16 | 32 | 72.3% | **yes** |
| cluster val | 44 | 25 | 19 | 20 | 19 | 16.0% | no |
| cluster test | 46 | 26 | 20 | 13 | 19 | 53.8% | **yes** |
| temporal train | 208 | 118 | 90 | 47 | 44 | 38.1% | no |
| temporal val | 44 | 25 | 19 | 3 | 17 | 88.0% | **yes** |
| temporal test | 47 | 27 | 20 | 4 | 17 | 70.4% | **yes** |

0 cluster spans; 10 temporal spans. Stale split cleanup removed 17 files;
split file count `.done` count = 299. `reference_only`, `unverified`, `gold`
and fixtures have NULL splits.

### Baselines (test 46 rows, 26 positives, 13 clusters)

| model | precision | recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|
| majority | 0.565 | 1.000 | 0.722 | 0.565 |
| logistic, structural | 0.793 | 0.885 | 0.836 | 0.730 |
| TLSH kNN | 0.808 | 0.808 | 0.808 | 0.830 |
| LightGBM, full | 0.889 | 0.923 | 0.906 | 0.990 |
| LightGBM, capability only | 0.929 | 1.000 | **0.963** | 0.997 |
| LightGBM, structural only | 0.833 | 0.769 | 0.800 | 0.934 |

- `not_a_result=true`: the cluster split is degenerate (train 72.3%); the
  test side also exceeds the 40% share rule (53.8%).
- Structural confound: **false** (0.963 vs 0.800).
- LOCO not triggered (16 train positive clusters); the split is primary.
- **Leakage:** a 14-row AsyncRAT test cluster is TLSH distance **86** from a
  19-row XWorm train cluster. The clusterer's family guard keeps them
  separate; it is true AsyncRAT/XWorm code proximity, not a split error.
  Reported, not re-clustered.
- Holdout FPR: **9/565 = 1.59%**.

### Integrity

- DataSet **1,505 rows**, 0 NULL `cluster_id`, **925** clusters.
- Evidence **10,535 = 7 × 1,505**; 1,505 labels and cluster JSONs.
- Class DBs: AsyncRAT 130, OtherMalwares 40, Benign 704; 631 unassigned.
- `reference_only` 2 (the two stub-named clients without config evidence were
  restored; the other two remain flagged).
- No samples deleted or executed. No commits.

### Limitations

- Stage 1 fails on largest share (66.2%); Stage 2 fails on AsyncRAT, XWorm and
  singleton families.
- Train remains degenerate (one cluster 72.3%), so all model numbers are
  DIAGNOSTIC ONLY.
- The 181-family queue yielded only 5 verified_other samples; most historical
  family files are unverified or non-.NET.
- Batch 2 is 31/350; the remaining 319 are queued in the manifest.
- Holdout FPR rose to 1.59% (still diagnostic).


## Phase 1.6 — historical AsyncRAT from the full export (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed; not a result.**

Historical samples were pulled from the MalwareBazaar **full export** (not the
recent `get_taginfo` window). Batch 1 added **50 verified AsyncRAT samples in
34 new clusters**. The pooled class is now **152 verified in 36 clusters**, but
the pre-existing 88-sample 2023–2026 cluster keeps the largest share at
**57.9%**, so Stage 1 still fails on the 50% criterion. Batch 2 was **not**
run: P0.2 required `>=10 new clusters AND pooled share <=50%`; the clusters
condition passed (34), the pooled share did not.

### Export and batch 1

Archive: `full.csv.zip`, 220.1 MiB, export timestamp **2026-11-27 19:40:17
UTC**. Streamed from the zip; the CSV is never extracted. The URL (which
contains the API key) is never logged.

| stage | rows |
|---|---:|
| parsed CSV rows | 1,181,317 (1,181,316 physical data lines) |
| signature `AsyncRAT`/`AsyncRat` | 10,922 |
| `file_type_guess=exe` | 7,930 |
| already in ledger | 233 |
| already in selection manifest | 0 |
| selected (50/year, 2020–2026) | **350** |
| downloaded / failed | **350 / 0** |
| TLSH rejected (`<=100` to a selected sample) | 557 |
| export TLSH re-verified after download | 15/15 exact matches |

Batch 1 label yield (350 samples):

| label | rows |
|---|---:|
| `verified` client | 50 |
| `reference_only` (file name says stub) | 3 |
| `review` | 1 |
| `unverified` | 232 |
| `rejected_non_dotnet` | 64 |
| **.NET yield** | **286 / 350 (81.7%)** |

The 232 unverified samples are .NET but only the MalwareBazaar signature
supports AsyncRAT; `rat_king_parser`, own YARA, Malpedia and Elastic all
return `no_match` on these historical builds. They stay out of training.

### Gate before/after

| state | rows | AsyncRAT rows / clusters / largest share | Benign primary | Stage 2 | overall |
|---|---:|---|---|---|---|
| after Phase 1.5 | 943 | 103 / 6 / 76.7% | PASS 71 / 13.7% | FAIL | FAIL |
| after batch 1 (before audit) | 1,293 | 156 / 37 / 57.1% | PASS 71 / 13.7% | FAIL | FAIL |
| after batch 1 + scope audit | 1,293 | **152 / 36 / 57.9%** | PASS 71 / 13.7% | FAIL | FAIL |

Stage 2 remains FAIL: `AsyncRAT` 152 / 36 / 57.9% and `XWorm` 9 / 2 / 77.8%.
XWorm was not touched by this batch, so Stage 2 cannot pass from AsyncRAT
downloads alone.

### Split validity (greedy whole-cluster packing)

`Tools/Splits/split.py` now packs whole clusters by **rows per class**
(70/15/15), largest cluster first, into the split furthest below its row
target (ties by `cluster_id`). No cluster spans splits.

| split | rows | positives | negatives | pos clusters | neg clusters | largest pos share | degenerate |
|---|---:|---:|---:|---:|---:|---:|---|
| train | 203 | 113 | 90 | 3 | 32 | 77.9% | **yes** |
| val | 43 | 24 | 19 | 18 | 19 | 20.8% | no |
| test | 44 | 24 | 20 | 17 | 19 | 29.2% | no |
| temporal train | 202 | 112 | 90 | 38 | 44 | 42.9% | **yes** |
| temporal val | 43 | 24 | 19 | 3 | 17 | 83.3% | **yes** |
| temporal test | 45 | 25 | 20 | 4 | 17 | 76.9% | **yes** |

- 290 primary rows (161 positives, 129 negatives); 0 cluster spans.
- The cluster split is still degenerate because **train** is dominated by one
  88-sample cluster (77.9% > 40%) and has only 3 positive clusters. The test
  side is healthy (24 positives, 17 clusters).
- Test thresholds pass (`test_positives=24 >= 20`,
  `test_positive_clusters=17 >= 5`), but the split degeneracy alone forces
  DIAGNOSTIC ONLY.

### Matrix and baselines (test = 44 rows, 24 positives, 17 clusters)

- 290 rows / 161 positives / 108 clusters; vocabulary **2,048** (train-only,
  min cluster DF = 3); 11 dense structural counts.
- `validity`: `structural_confound=false`, `loco_inspect=true`,
  `split_degenerate=true`, `not_a_result=true`.

| model | precision | recall | F1 | PR-AUC |
|---|---:|---:|---:|---:|
| majority | 0.545 | 1.000 | 0.706 | 0.545 |
| logistic, structural only | 1.000 | 0.542 | 0.703 | 0.926 |
| TLSH kNN | 0.941 | 0.667 | 0.780 | 0.809 |
| LightGBM, full | 0.957 | 0.917 | **0.936** | 0.941 |
| LightGBM, capability only | 0.957 | 0.917 | **0.936** | 0.941 |
| LightGBM, structural only | 0.870 | 0.833 | 0.851 | 0.938 |

- Capability features match the full model; structural-only is 0.085 F1
  behind, so there is no structural confound — but this is still not a result
  (degenerate train, LOCO perfect with 3 train clusters).
- Per-cluster recall: 15 of 16 positive test clusters at 1.0; one singleton
  missed (TLSH distance 556 to any train cluster).
- **Leakage flag:** one 7-row test cluster is at TLSH distance **17** from a
  train cluster, below the 100 threshold. Report it; do not claim.

### LOCO (triggered: 3 train positive clusters < 10)

| rows | positives | precision | recall | F1 | PR-AUC |
|---:|---:|---:|---:|---:|---:|
| 203 | 113 | 1.000 | 1.000 | 1.000 | 1.000 |

Perfect LOCO with three near-duplicate-heavy clusters measures within-family
consistency, not independent-campaign generalization (`loco_inspect=true`).

### External benign holdout (Hassan 2023)

- 565 unique .NET EXEs, still excluded from train/val/test.
- Holdout FPR for the diagnostic full model: **28 / 565 = 4.96%** (0.35% in
  Phase 1.5; the historical positives made the model less conservative).

### Scope audit (server/builder)

`Tools/Audit/reference_only.py` flags `server|builder|stub|panel` file names
(labeling metadata only, never a feature). **4 verified samples** were marked
`reference_only` (`previous_status=verified` preserved); 3 are batch-1
samples. They are excluded from `AsyncRAT.db` and from every split.
A static spot-check of **20 verified samples** (EXEs, no DLLs) found no
server/builder/panel/listener types; details in `Data/Audit/spot_check.json`.

### Integrity

- DataSet: **1,293 rows**, 0 NULL `cluster_id`, **734** clusters.
- Evidence: **9,051 rows** = 7 × 1,293.
- Class DBs: AsyncRAT **152**, OtherMalwares 9, Benign 704; 4
  `reference_only` and 428 unassigned in DataSet only.
- 1,293 labels / cluster JSONs; 1,187 structure JSONs and 1,187 JSONs per
  carver (106 non-.NET samples have no metadata); 290 current split rows
  (294 split JSONs including 4 stale reference_only files).
- `is_gold=0`; no sample deletion; no sample execution.
- Git: generated `Data/` outputs and DBs untracked, `git ls-files '*.json'`
  is 0; `Data/BenignSources.csv`, `Data/Gold/gold.csv` and the ledger DB stay
  tracked. See `Docs/REPRODUCE.md`.

### Limitations

- Stage 1 fails only on the largest-share criterion; Stage 2 fails on XWorm
  (9 samples, 2 clusters, 77.8%) and cannot be fixed by AsyncRAT batches.
- 232 of 350 historical .NET samples are unverified because the independent
  voters do not recognize those builds; only the MB signature does.
- Train remains dominated by one 88-sample cluster, so every baseline number
  is DIAGNOSTIC ONLY even if the dataset gate later passes.
- One test cluster is within TLSH distance 17 of train (leakage flag).
- Batch 2 (the remaining 350 of the 700 target) was deliberately not run.


## Phase 1.5 — gate, MB batch, diagnostic baselines (2026-11-28)

**DIAGNOSTIC ONLY — dataset gate failed; not a result.**

The ceiling moved but did not break: **103 positives in 6 clusters, 79 in one
cluster (76.7%)**. The non-interactive MB `contains` batch was run and added
**45 verified AsyncRAT samples (69 new rows)**, but only **3 new clusters**.
The `contains AsyncRAT` candidate pool is now exhausted (68 candidates), so
further MB downloads cannot fix Stage 1.

### Gate before/after

| state | rows | benign (primary / holdout) | clusters | AsyncRAT gate | Benign gate | Stage 2 | overall |
|---|---:|---|---:|---|---|---|---|
| before P0.0 | 488 | 318 / 0 | 160 | FAIL 3 clusters / 96.6% | PASS 116 / 24.5% | FAIL 1 family | FAIL |
| after DLL retirement | 309 | 139 / 0 | 116 | FAIL 3 / 96.6% | PASS 71 / 13.7% | FAIL | FAIL |
| after Hassan holdout | 874 | 139 / 565 | 399 | FAIL 3 / 96.6% | PASS 71 / 13.7% | FAIL | FAIL |
| after MB batch | 943 | 139 / 565 | 418 | FAIL 6 / 76.7% | PASS 71 / 13.7% | FAIL | FAIL |

The P0.0 check expected **72** benign clusters; the measured value is **71**.
Largest cluster and share match: **19 (13.7%)**. No cluster IDs or TLSH
threshold were changed, and no re-randomization was done.

### Benign strata

| stratum | rows | clusters | largest | largest share | singletons |
|---|---:|---:|---:|---:|---:|
| `active` | 129 | 70 | 19 | 14.7% | 55 |
| `fixture` | 10 | 1 | 10 | 100.0% | 0 |
| `holdout` (Hassan) | 565 | 293 | 108 | 19.1% | 247 |
| `primary (active+fixture)` | 139 | 71 | 19 | 13.7% | 55 |

Only the primary stratum gates Stage 1; the holdout is measured separately.
The 10 fixtures form one cluster by construction and are excluded from the
matrix.

### Stage 2 families

| family | rows | clusters | largest share | result |
|---|---:|---:|---:|---|
| AsyncRAT | 103 | 6 | 76.7% | FAIL |
| XWorm | 9 | 2 | 77.8% | FAIL |

### Splits (241 primary rows: 112 positives, 129 negatives)

| split | rows | positives | positive clusters | all clusters | degenerate |
|---|---:|---:|---:|---:|---|
| cluster train | 121 | 25 | 5 | 54 | no |
| cluster val | 14 | 1 | 1 | 11 | **yes** |
| cluster test | 106 | 86 | 2 | 13 | **yes** |
| temporal train | 168 | 78 | 6 | 50 | no |
| temporal val | 35 | 16 | 5 | 22 | no |
| temporal test | 38 | 18 | 4 | 21 | no |

Cluster split: **0 clusters span splits**. Temporal split: **11** clusters
span splits (reported, not hidden). The cluster split is the evaluation split,
but it is not a balanced evaluation: the test side is dominated by two
near-duplicate AsyncRAT clusters (79 and 7 samples), while validation has a
single positive.

### Matrix

- 241 rows; 112 positives; 129 negatives; 78 clusters.
- Vocabulary: **3,157** items, fitted on the train split only, minimum
  cluster DF = 3; 11 dense structural counts; seed 42.
- Shapes: train 121 rows / 25 positives / 54 clusters; val 14 / 1 / 11;
  test 106 / 86 / 13.
- Excluded: unverified, review, rejected labels, non-.NET, gold filled,
  fixtures, and `source=clrheader2023` holdout.

### Baselines (test set is 106 rows with 86 positives — diagnostic)

PR-AUC is shown with the cluster-level bootstrap 95% interval (2.5th, 97.5th
percentile). Bootstrap means differ slightly from the point estimates.

| model | precision | recall | F1 | PR-AUC [95% CI] |
|---|---:|---:|---:|---|
| majority | 0.000 | 0.000 | 0.000 | 0.811 [0.223, 0.963] |
| logistic, structural only | 0.976 | 0.930 | 0.952 | 0.997 [0.990, 1.000] |
| TLSH kNN | 1.000 | 0.430 | 0.602 | 0.940 [0.855, 1.000] |
| LightGBM, full | 1.000 | 1.000 | 1.000 | 1.000 [1.000, 1.000] |
| LightGBM, capability only | 1.000 | 1.000 | 1.000 | 1.000 [1.000, 1.000] |
| LightGBM, structural only | 0.988 | 0.988 | 0.988 | 0.999 [0.995, 1.000] |

These numbers are **not** a detector claim. The test positives are two
near-duplicate clusters, so the model is scored on siblings of the same
AsyncRAT build it already saw. The structural-only baseline reaching 0.988
confirms that structural counts alone separate these clusters — evidence that
the clusters are too homogeneous, not that the capability features work.
Precision/recall bootstrap intervals collapse to 0.0 at the 2.5th percentile
whenever a resample draws no positive cluster.

### LOCO (triggered because positive clusters = 5 < 10)

| rows | positives | precision | recall | F1 | PR-AUC |
|---:|---:|---:|---:|---:|---:|
| 121 | 25 | 1.000 | 1.000 | 1.000 | 1.000 |

LOCO is the primary diagnostic; the 70/15/15 split is secondary. A perfect
LOCO score with five positive clusters means the folds share nearly identical
capability profiles — again a sign of near-duplicate builds, not of
independent-campaign generalization. The gate still fails.

### External benign holdout (Hassan 2023)

- 757 candidates; **565 unique .NET EXEs** after 192 duplicate removals.
- `source=clrheader2023`, `origin=github`; kept out of train/val/test.
- Holdout FPR for the diagnostic LightGBM full model: **2 / 565 = 0.35%**.
  This is a diagnostic measurement, not a result.

### MB `contains` batch (run)

| stage | rows |
|---|---:|
| tag query pool | 500 |
| dropped by tag filter | 267 |
| duplicate (already in ledger) | 164 |
| wrong file type | 1 |
| new candidates | 68 |
| downloaded / adopted | 68 (+1 smoke) |
| new verified AsyncRAT | 45 |
| new clusters | 3 |

- 69 new ledger rows; 69 signatures stored; 239 rows total.
- `downloads_rejected` audit table: 1,741 rows, 444 distinct hashes
  (append-only, one row per poll).
- One run hit a transient `sqlite3.OperationalError: attempt to write a
  readonly database` on its 7th download. Six files were on disk without
  ledger rows; the next run re-adopted them by hash. A post-run `check_ledger`
  now reports any file without a ledger row, and the batch path is
  non-interactive (`--batch --tag --file-type --tag-mode --limit --rate`).

### Pipeline bug found and fixed

Running the full labeler rewrote all 704 benign labels **without**
`source/origin/kind`, which would have leaked the Hassan holdout into
train/val/test. Provenance is restored for all 704 labels, the full path now
merges the manifest fields for benign files, and three synthetic tests cover
the merge. The holdout is again excluded: split rows are 241, not 806.

### Integrity

- DataSet: **943 rows**, 0 NULL `cluster_id`, **418** clusters.
- Evidence: **6,601 rows** = 7 × 943; scope populated.
- Class DBs: AsyncRAT 103, OtherMalwares 9, Benign 704.
- `is_gold=0`; 241 split JSONs; 901 structure JSONs; 943 cluster JSONs;
  179 DLLs and their derived artifacts live under `Samples/_aux/`.
- `Data/BenignSources.csv`: 883 rows (139 active EXE + 179 retired DLL +
  565 Hassan holdout).
- No commits; no deletions; no sample execution.

## Phase 0.5 — remaining voters, lineage scope, gold (2026-11-27)

Pipeline: `labeler -> rat-king -> own YARA -> Elastic -> Malpedia ->
MalwareBazaar -> DIE -> YARAify -> aggregator -> clusterer -> carvers ->
importer -> gold template -> importer`.

### Final `lbl_sts` (before vs after)

The malware labels were measured on 180 samples before P2.1. The final dataset
is 380 samples after adding 200 collected benign files; only `benign` changes.

| label | Phase 0.4 (180) | Phase 0.5 (180) | final (380) |
|---|---:|---:|---:|
| `verified` | 48 | **58** | 58 |
| `verified_other` | 0 | **9** (all XWorm) | 9 |
| `unverified` | 78 | 71 | 71 |
| `rejected_non_dotnet` | 31 | 31 | 31 |
| `review` | 13 | **1** | 1 |
| `benign` | 10 | 10 | **210** |

`sug_fam` final: 155 empty, 210 Benign, 9 XWorm, 3 DcRat, 2 QuasarRAT,
1 AsyncRAT.

### Voter hits (joined to the final `lbl_sts`)

| Voter | Positive hits | Final status breakdown |
|---|---:|---|
| `rat_king_parser` | 73 | AsyncRAT 48 → 48 verified; DcRat 2 → 2 unverified; QuasarRAT 3 → 2 unverified + 1 verified; VenomRAT 1 → 1 review; XWorm 9 → 9 verified_other |
| `own_yara` | 73 | AsyncRAT 73 → 58 verified, 1 review, 2 unverified, 9 verified_other, 3 rejected_non_dotnet; benign 0 |
| `elastic` | 48 | AsyncRAT 45 → 45 verified; DcRat 1 → 1 review; XWorm 2 → 2 verified_other |
| `malpedia` | 71 | AsyncRAT 59 → 58 verified + 1 unverified; XWorm 9 → 9 verified_other; XWorm 3 → 3 rejected_non_dotnet |
| `malwarebazaar` | 165 | weak AsyncRAT 165 → 56 verified, 1 review, 68 unverified, 9 verified_other, 31 rejected_non_dotnet; no_match 5 (2 verified, 3 unverified) |
| `detect_it_easy` | 0 family | 380 no_match; `obf_lvl=unknown` (no `diec`) |
| `yaraify` | 0 | 380 no_match (no `YARAIFY_AUTH_KEY`) |

Positive hit counts are unchanged by the benign expansion: all 210 benign
samples are `no_match` for every family voter.

`label_evidence`: **2660 rows** (7 × 380), max `raw` 1246 bytes.
Scope column: 649 `lineage`, 2011 `family`, 0 NULL.

### Real `verified_other` promotion

- 9 XWorm samples are `verified_other`; `OtherMalwares.db` has **9 rows**.
  The 30 gold candidates are not excluded until `gold_status` is filled, so
  they remain in the class DBs.
- The promotion is real, not synthetic: rat-king XWorm strong + Malpedia
  and/or Elastic XWorm family-scoped strong, with own-YARA/Elastic/Malpedia
  AsyncRAT evidence marked `scope=lineage` so it does not contradict the fork.
- DcRat (2) and QuasarRAT (2) remain `unverified`: only rat-king votes for
  them; no second family-scoped group matched.

### Remaining contradiction

Only one review remains:

| sha256 prefix | voters | verdicts |
|---|---|---|
| `10102a03f784` | `elastic` (family) vs `rat_king_parser` (family) | DcRat strong vs VenomRAT strong |

This is a genuine family disagreement, not a lineage artefact.

### Clusters

Final (380 samples): **94 clusters**, 33 multi-member, largest 78,
61 singletons, 0 mixed-family. Clusters containing ≥1 `verified` AsyncRAT:
**3 of 94** (the benign expansion adds benign-only clusters; the three
malware clusters are unchanged). The XWorm `verified_other` group occupies
2 clusters.

### Gold set

- `Tools/Gold/build_gold_set.py` selected **30 samples from 30 distinct
  clusters**: 3 verified, 1 verified_other, 1 review, 18 unverified, 1 benign,
  6 rejected_non_dotnet.
- `Data/Gold/gold.csv` human fields are blank; `gold_fam` is NULL.
- After the P0.1 fix, `is_gold=1` is **0** on all 380 rows; blank `gold_status`
  is a candidate, not a gold row. Class DBs are `AsyncRAT.db` 58,
  `OtherMalwares.db` 9, `Benign.db` 210. There are no filled gold rows, so no
  class-DB exclusion yet.
- Hand-labeling in dnSpyEx is pending; precision/recall audit is not done.

### Data-loss checks

- The original 180 label JSONs are byte-identical:
  `406aa42609521b0cf9c98158296c90336ad5d921f9128914030429cb5db49c88`.
- The original 745 carved JSONs are byte-identical:
  `6c8c4b86a16c9f62bce09ed63bab48f52771e0aa7830403e27aad1dbc7f1c37f`.
- `samples.db` SHA-256 is unchanged:
  `08f938c5b00d1565b7de74cc230434f42ed5e4312e06630ea5f44670130dc10d`.
- `DataSet.db` 380 rows, 0 NULL `cluster_id`, 94 clusters.
- `label_evidence` 2660 rows; scope 649 `lineage` + 2011 `family`, 0 NULL.
- `lbl_reason` valid JSON on all rows.
- New benign rows: 200 collected + 10 hand-built = 210; 200 CSV rows.

### Phase 0 finish checks (P0/P1/P2)

**P0.1 `is_gold` semantics.** `is_gold=1` only when `gold_status` is
non-empty. Blank rows are candidates and remain in their class DB. Final:
`is_gold=0` on all 380 rows; class DBs 58 / 9 / 210.

**P0.3 vote scope.** `label_evidence.scope` is persisted: 649 `lineage`,
2011 `family`, 0 NULL. Attribute voters (DIE) are stored as `family` because
they cannot promote a family.

**P1.1 single PE parser.** `Tools/_pe.py` is the only `is_dotnet`
implementation; the labeler and carver common module import it. Synthetic
tests cover .NET, native, truncated and non-MZ files.

**P1.2 threshold sweep (380 samples).**

| TLSH threshold | clusters | largest | singletons | multi-member | mixed-family |
|---:|---:|---:|---:|---:|---:|
| 25 | 277 | 46 | 243 | 34 | 0 |
| 50 | 241 | 56 | 200 | 41 | 0 |
| 100 (default) | 94 | 78 | 61 | 33 | 0 |

The acceptance rule holds at every threshold: no cluster contains more than
one known family. The default stays 100; `Data/Clusters` was not overwritten.

**P1.3 dataset report.** `python3 Tools/Report/dataset_report.py` reports
380 rows, 94 clusters, 61 singletons, largest 78, 0 mixed-family. Class DBs:
58 AsyncRAT, 9 OtherMalwares, 210 Benign. Median size: AsyncRAT 45 KiB,
Benign 705 KiB; class balance **210 benign vs 67 positive**.

**P2.1 benign collection.** NuGet dry run: 91 .NET PE candidates, 65 unique,
20 selected. .NET SDK dry run: 3,751 candidates, 3,152 unique, 20 selected.
The 10-file live run copied 10; the full run collected 200
(**21 EXE, 179 DLL**) plus 10 hand-built = **210** benign files. The SDK has
only 21 .NET EXEs; DLLs were included to reach the 200 target. `labeler
--benign-only` wrote labels/evidence without the parser; the full 7-voter
pipeline then produced 380 rows / 210 benign / 94 clusters / 2,660 evidence
rows. No sample was executed.

**P2.2 gold quota warning.** The builder now prints unmet quotas and the
substitution. On the 380-row dataset: verified 8→3, review 7→1, and 11
substituted rows (benign 9, unverified 1, verified_other 1).
`Data/Gold/gold.csv` was not changed.

### Plain conclusion

The remaining voters materially improved the result: `verified` 48→58,
`verified_other` 0→9, `review` 13→1, cluster coverage 2→3. P2.1 then expanded
benign from 10 to 210 without changing the malware labels. The external
blockers are `diec` for `obf_lvl`, `YARAIFY_AUTH_KEY`/MalwareBazaar
`signature` for stronger metadata, and a second family-scoped voter for
DcRat/QuasarRAT. The 200 collected benign files are 21 EXE + 179 DLL; DLLs
were needed because the SDK has only 21 .NET EXEs.

## Label coverage (Phase 0.4 offline core, 2026-11-27) — SUPERSEDED BY PHASE 0.5

> This section is historical. Use the Phase 0.5 numbers above.

Pipeline: `labeler -> rat_king_parser evidence -> own YARA -> aggregator ->
clusterer -> 5 carvers -> importer`.

### `lbl_sts` before vs after

| `lbl_sts` | before | after |
|---|---:|---:|
| `verified` | 48 | 48 |
| `unverified` | 76 | 78 |
| `rejected_non_dotnet` | 31 | 31 |
| `review` | 15 | 13 |
| `benign` | 10 | 10 |

### `sug_fam` before vs after

| `sug_fam` | before | after |
|---|---:|---:|
| `<none>` | 155 | 146 |
| `Benign` | 10 | 10 |
| `XWorm` | 9 | 9 |
| `AsyncRAT` | 0 | 9 |
| `QuasarRAT` | 3 | 3 |
| `DcRat` | 2 | 2 |
| `VenomRAT` | 1 | 1 |

### Clusters

| Metric | before | after |
|---|---:|---:|
| Clusters | 45 | 45 |
| Multi-member | 14 | 14 |
| Mixed-family | 0 | 0 |
| Clusters containing ≥1 `verified` AsyncRAT | 2 | 2 |

The two verified clusters are `053fa0de7562` (56 members) and
`4902c56dfa5b` (singleton). The new voters **confirmed** the existing 48
AsyncRAT samples but did not add a second independent voter for the 9
own-YARA-only AsyncRAT samples, so cluster coverage did not improve.

### `verified_other`

- Count: **0**.
- `OtherMalwares.db`: **absent** (0 rows).
- Reason: only rat-king-parser votes on non-AsyncRAT families. A second
  family-specific voter (Malpedia/Elastic) is needed before promotion. The
  routing is implemented and covered by tests, but no real row exists yet.

### Contradictions (all `review`)

Every contradiction is own-YARA `AsyncRAT` vs rat-king fork. The aggregator
keeps `sug_fam` on the fork family so the clusterer partitions it away from
AsyncRAT.

| sha256 prefix | own_yara | rat_king_parser |
|---|---|---|
| `0dda9bf0db4f` | AsyncRAT strong | DcRat strong |
| `0eec59785a5e` | AsyncRAT strong | XWorm strong |
| `10102a03f784` | AsyncRAT strong | VenomRAT strong |
| `3d3362f1bd81` | AsyncRAT strong | XWorm strong |
| `53a8bd56d87f` | AsyncRAT strong | XWorm strong |
| `5e72a6fc387d` | AsyncRAT strong | XWorm strong |
| `7813085032d6` | AsyncRAT strong | XWorm strong |
| `9b6ba2ef41d4` | AsyncRAT strong | XWorm strong |
| `ab1d3375e08f` | AsyncRAT strong | XWorm strong |
| `ac7e7f562436` | AsyncRAT strong | XWorm strong |
| `b2a0f706a39d` | AsyncRAT strong | QuasarRAT strong |
| `cbd25e49ec37` | AsyncRAT strong | DcRat strong |
| `eb8b9a20fc7d` | AsyncRAT strong | XWorm strong |

The 2 QuasarRAT samples not hit by own YARA are `unverified` with
`sug_fam=QuasarRAT`; they have one strong voter but not two.

### Own-YARA hits

| Label status | Raw matches | Evidence `AsyncRAT` |
|---|---:|---:|
| `verified` | 48 | 48 |
| `review` | 13 | 13 |
| `unverified` | 9 | 9 |
| `rejected_non_dotnet` | 3 | 3 |
| `benign` | **0** | **0** |

- Benign hits: **0**.
- The 3 `rejected_non_dotnet` matches contain 7–8 wide AsyncRAT strings but no
  CLR header. Aggregator rule 1 still labels them `rejected_non_dotnet`.
- The rule is a lineage detector: it also hits XWorm/DcRat/VenomRAT/QuasarRAT
  forks. That is why those rows are `review`, not `verified`.

### Evidence table

- `label_evidence`: 360 rows (180 `rat_king_parser` + 180 `own_yara`).
- `lbl_src`: 170 `auto_aggregator`, 10 `hand_benign`.
- `is_gold`: 180 × `0`; `gold_fam`: 180 × NULL.
- Max `raw` length: 717 bytes (limit ~8 KB).
- `lbl_reason`: valid JSON on all 170 aggregated rows.

### Data-loss checks

- `Tools/MBDownloader/samples.db` SHA-256 unchanged.
- 180 label JSONs byte-identical to the pre-run digest.
- All 15 carved directories byte-identical to the pre-run digests.
- `DataSet.db` 180 rows, 0 NULL `cluster_id`.
- `AsyncRAT.db` 48 rows; `Benign.db` 10 rows; no missing or extra samples.
- Importer reruns preserve existing `split` values (all NULL today).

### Plain conclusion

The offline core works and is auditable, but it did **not** improve the
`verified` count or cluster coverage. It made the label state more explicit:
13 contradictions are now `review` with recorded voters, and 2 single-voter
QuasarRAT rows are `unverified` instead of `review`. To improve coverage:
add a second independent AsyncRAT voter (Elastic or Malpedia) and a
family-specific voter for `verified_other`.

### Tests

- `python3 tests/run_tests.py` → **25/25 pass**.
- Covers aggregator rules 1-10, abstention vs contradiction, independence
  counting, `verified_other` routing, no-family error, evidence upsert
  idempotency, marker requirement, empty class folder, final-label merge,
  clusterer family read, and the own-YARA 4-of-13 threshold.

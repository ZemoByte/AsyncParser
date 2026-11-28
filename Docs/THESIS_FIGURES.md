# Thesis figures and tables

**DIAGNOSTIC ONLY — dataset gate FAIL.** No figure is a detector result.
Matplotlib is not installed; the frozen data is provided as CSV under
`Docs/figures/` plus the tables below. No curves or new metrics were created.

| # | item | source | caption |
|---:|---|---|---|
| 1 | Gate and labels | `Docs/figures/gate.csv`, `labels.csv`, `Data/Audit/fixup_snapshot.json` | **DIAGNOSTIC ONLY — gate FAIL.** Stage 1 AsyncRAT 154 rows / 52 clusters / largest 89 (57.8%); benign 129/70 (14.7%). Stage 2 FAIL. 1,824 rows / 1,228 clusters; labels 154/58/704/624/278/4/2. |
| 2 | Split | `Docs/figures/split.csv`, `Data/Features/metadata.json` | **DIAGNOSTIC ONLY — gate FAIL.** Train 238 rows / 148 positives / 55 total clusters; val 51/32/49; test 52/32/48. The train positive share is degenerate. |
| 3 | Test F1 with CIs | `Docs/figures/test_f1.csv`, `Data/Features/fixup_results.json` | **DIAGNOSTIC ONLY — gate FAIL.** Capability F1 .921 at 0.5, .903 OOF [.800,.971]; P/Invoke .795/.788 [.677,.904]. CIs overlap; not a result. |
| 4 | PR/ROC AUC | `Docs/figures/pr_roc.csv` | **DIAGNOSTIC ONLY — gate FAIL.** Capability PR .988 [.959,1.000], ROC .980 [.941,1.000]; P/Invoke .695 [.553,.902], .645 [.441,.847]. Ranking only. |
| 5 | Holdout FPR | `Docs/figures/holdout_fpr.csv` | **DIAGNOSTIC ONLY — gate FAIL.** At 0.5 capability 35/565 (6.2%), full 13/565 (2.3%); matched-95 is a failed calibration. 0/565 is not a result. |
| 6 | LOCO recall/FPR | `Docs/figures/loco.csv` | **DIAGNOSTIC ONLY — gate FAIL.** 52 verified / 82 positive folds; primary 0.5 probability view. Capability .981/.016, P/Invoke raw 0.5 not comparable. |
| 7 | Label audit | `Docs/figures/label_audit.csv`, `Data/Audit/label_quality.json` | **DIAGNOSTIC ONLY — gate FAIL.** Automated audit, not human gold: 530 MB-only, 263 multi-source, 107 conflicts. 30 gold rows / 0 filled. |
| 8 | CLI parity | `Docs/figures/cli_parity.csv`, `Data/Audit/cli_parity.json` | **Prototype only — DIAGNOSTIC ONLY — gate FAIL.** 30 known samples: 23 scored matches, 0 mismatches, 7 abstentions, 30 raw parses. Not a detector. |
| 9 | D2 preview | `Docs/figures/d2_preview.csv`, `Data/Audit/d2_partition_preview.json` | **D2 not run — DIAGNOSTIC ONLY — gate FAIL.** Preview: 565/293 Hassan rows/clusters → 396/164 train, 169/129 holdout (29.9%), overlap 0. |
| 10 | Test comparison table | `Docs/figures/test_f1.csv`, `pr_roc.csv` | **DIAGNOSTIC ONLY — gate FAIL.** Capability-only is the main comparison; +policy/+all are ablations. No detector claim. |

## Table A — primary test and holdout

| item | value |
|---|---|
| Test rows / positives | 52 / 32 |
| Capability F1 @0.5 | .921 |
| Capability F1-optimal OOF | .903 [.800, .971] |
| Capability PR-AUC / ROC-AUC | .988 [.959, 1.000] / .980 [.941, 1.000] |
| P/Invoke F1 @0.5 / OOF | .795 / .788 [.677, .904] |
| Holdout @0.5 capability | 35/565 = 6.2% |
| Holdout @0.5 full | 13/565 = 2.3% |

## Table B — LOCO at 0.5 (primary probability view)

| scope | model | recall | FPR | F1 |
|---|---|---:|---:|---:|
| verified | capability | .981 | .016 | .984 |
| verified | P/Invoke | not comparable (raw count) | — | — |
| positive | capability | .981 | .023 | .983 |

## Table C — label audit and prototype

| item | value |
|---|---|
| Audited rows | 1,540 |
| MB-signature-only | 530 |
| Multi-source | 263 |
| Conflicts | 107 (14 support / 20 different / 73 tie) |
| Gold | 30 rows / 0 filled |
| CLI parity | 23 matches / 0 mismatches / 7 abstentions |

All tables copy frozen JSON values; no new metrics, no curves, no evaluator
rerun.

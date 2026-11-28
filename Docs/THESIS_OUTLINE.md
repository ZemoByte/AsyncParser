# Thesis outline

**Working title:** Capability-based static analysis of .NET AsyncRAT client
payloads: a cluster-aware diagnostic study.

## Abstract (one page draft)

This project studies whether external .NET metadata references can separate
AsyncRAT client payloads from benign .NET executables, and whether the same
features can support a narrow diagnostic family comparison. The frozen dataset
contains 1,824 rows in 1,228 clusters: 154 verified AsyncRAT clients, 58
verified other RATs, 704 benign files, 624 unverified files, 278 non-.NET
files, 4 review rows and 2 reference-only rows. The dataset gate fails:
AsyncRAT has 52 clusters and its largest cluster is 89 rows (57.8%), while the
50% rule requires 178 verified rows at that cluster size. Stage 2 also fails
because AsyncRAT, QuasarRAT and DcRat have too few independent clusters.

On the 52-row test split, capability-only F1 is .921 at 0.5 and .903 at the
F1-optimal grouped OOF threshold [.800, .971]; a single P/Invoke count reaches
.788 [.677, .904]. F1 confidence intervals overlap, while PR-AUC (.988 vs
.695) and ROC-AUC (.980 vs .645) separate. The honest conclusion is therefore
that ranking favors capability, but the operating point does not separate at
n=32 positives; neither result is a detector claim. The 565-row benign
holdout has 35/565 (6.2%) false positives at 0.5 for capability-only and
13/565 (2.3%) for the full model; the matched-95 calibration failed to
transfer and is reported only as sensitivity. A mixed positive/benign LOCO
check, an automated label audit, error analysis and a static prototype CLI
complete the diagnostic package. The CLI is not validated; the gate remains
FAIL; gold is 0/30.

**Safe thesis sentence:** On a frozen 1,824-row diagnostic dataset, capability
features rank above a single P/Invoke count on threshold-free PR/ROC, but the
operating-point F1 CIs overlap and the dataset gate fails; the Stage 2 check
has only 29 test rows. These are diagnostic findings, not a detector result.

## Chapters

1. **Introduction.** Problem, AsyncRAT context, research questions, scope,
   contributions, and the explicit non-goal of a deployed detector.
2. **Background.** AsyncRAT client/server architecture; .NET metadata
   (TypeRef, MemberRef, AssemblyRef, ImplMap, ImportTable); capability
   features; TLSH; cluster-aware evaluation; related .NET malware work.
3. **Data and labels.** 1,824 rows / 1,228 clusters; seven voters; aggregator;
   independent static review (partial, not gold); Hassan 2023 holdout;
   label-quality audit; gold 30/0; gate definitions and failure.
4. **Methods.** Capability vocabulary; P1 feature policy; cluster split;
   Stage 1/Stage 2 gates; LightGBM and TLSH kNN; grouped OOF thresholds;
   matched-recall sensitivity; mixed LOCO; cluster bootstrap CIs; abstention;
   error analysis; static CLI.
5. **Results.** Test F1/PR/ROC; holdout FPR at 0.5 and the failed matched-95
   calibration; LOCO; D1 cap and P1 policy ablations; random-split leak gap;
   Stage 2 eligibility; label audit; CLI parity; D2 preview (not run).
6. **Discussion and limitations.** Dominant 89-row cluster, 52 AsyncRAT
   clusters, 32 test positives, degenerate train split, threshold transfer,
   tiny obfuscated subset, partial independent review, no human gold.
7. **Conclusion and future work.** Freeze at the measured ceiling; D2 is a
   separate, unapproved ablation; a targeted independent-cluster campaign
   would be needed before any detector claim; no other-family model exists.

## Chapter-to-evidence map

| chapter | evidence |
|---|---|
| 1 | `Docs/FINAL_RESULTS.md` §§1, 10; `Docs/CLAIMS.md` |
| 2 | `Docs/Plan.md`; `Docs/papers/hassan2023/` |
| 3 | `Data/Audit/label_quality.json`; `Docs/limitations.md`; `Docs/GOLD_AUDIT.md` |
| 4 | `Tools/Models/fixup_eval.py`; `Tools/Features/build_matrix.py`; `Docs/REPRODUCE.md` |
| 5 | `Data/Features/fixup_results.json`; `Docs/figures/*.csv`; `Docs/THESIS_FIGURES.md` |
| 6 | `Docs/limitations.md`; `Data/Audit/error_analysis.json` |
| 7 | `Docs/D2_DECISION.md`; `Docs/D2_PREVIEW.md`; `Docs/CLI.md` |

## What can and cannot be claimed

| claim | status |
|---|---|
| Dataset composition and gate failure are measured | **Supported** |
| Label provenance is auditable; MB-only and conflict counts are measured | **Supported** |
| Capability features rank above a single P/Invoke count on PR/ROC | **Supported as diagnostic ranking** |
| Capability F1 is higher at the operating point | **Not supported** — CIs overlap at n=32 |
| Capability has a lower holdout FPR | **Not supported** — different actual recalls; 0/565 is not a result |
| The model generalizes to real-world malware | **Not supported** — gate FAIL |
| A Stage 2 family model is ready | **Not supported** — only AsyncRAT/XWorm, n=29 |
| The CLI is a validated detector | **Not supported** — prototype; NOT VALIDATED |
| Gold is ground truth | **Not supported** — 0/30 filled |

## Figures

Figures are frozen-data CSVs under `Docs/figures/` (matplotlib not installed)
and the captions/tables in `Docs/THESIS_FIGURES.md`. Every caption is marked
**DIAGNOSTIC ONLY — gate FAIL**; D2 is labeled “not run” and the CLI
“prototype.”

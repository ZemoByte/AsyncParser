# FINAL RESULTS — static AsyncRAT client detector (diagnostic)

**DIAGNOSTIC ONLY — the dataset gate fails. This is not a detector result.**
No data was collected, no label/cluster/split changed, and D2/WS3 was not run.
Run: `2026-11-28T15:42:40+00:00`, `run_id=c7a21a6c37f14f5aabcc821dd26729cd`,
`script_sha256=6598bfce845eca72666753b7cd8ae2f21172947e83c4a43e43c9bc9c7e2cc5ef`,
seed 42, OOF folds 5.

## 1. Dataset and gate

- **1,824 rows / 1,228 clusters / 0 NULL `cluster_id`; evidence 12,768.**
- Labels: **154 verified** (AsyncRAT), **58 verified_other**, **704 benign**,
  **624 unverified**, **278 rejected_non_dotnet**, **4 review**,
  **2 reference_only**.
- Class DBs: AsyncRAT 154, OtherMalwares 58, Benign 704.
- Stage 1 AsyncRAT: **52 clusters, largest 89 = 57.8% — FAIL** (24 verified
  short of the 178 needed at that cluster size). Active benign: 129 rows /
  70 clusters / largest 14.7% — PASS.
- Stage 2: AsyncRAT FAIL, QuasarRAT 3/2/66.7% FAIL, DcRat 1/1 FAIL; XWorm
  49/23/49.0% PASS and VenomRAT 5/4/40% PASS; **overall FAIL**.
- **No real-world detection claim follows from this dataset.**

## 2. Splits

341 primary rows (rows / positives / positive clusters): **train 238 / 148 /
23 at 60.1% (degenerate); val 51 / 32 / 30 at 6.2%; test 52 / 32 / 29 at
12.5%**. Zero cluster spans; `reference_only`, `unverified`, review and gold rows have NULL
splits. The train split is still dominated by one 89-row cluster.

## 3. Test performance

Thresholds are train-only. The primary view is the fixed 0.5 probability
reference plus threshold-free PR/ROC; “OOF” is the F1-optimal grouped train
threshold. The matched-95 target is a failed-calibration sensitivity and is
shown in §4/§5, not as the main performance table.

| model | F1 @0.5 | F1-optimal OOF | PR-AUC [95% CI] | ROC-AUC [95% CI] |
|---|---:|---:|---|---|
| capability only | .921 | .903 | .988 [.959, 1.000] | .980 [.941, 1.000] |
| capability + policy counts | .918 | .955 | .992 [.967, 1.000] | .987 [.961, 1.000] |
| capability + all counts | .900 | .941 | .992 [.965, 1.000] | .988 [.958, 1.000] |
| capped capability | .935 | .897 | .989 [.961, 1.000] | .981 [.947, 1.000] |
| structural only (policy) | .857 | .844 | .933 [.870, .987] | .880 [.786, .973] |
| structural only (all, diagnostic) | .831 | .857 | .929 [.850, .984] | .881 [.765, .971] |
| P/Invoke count only | .795 | .788 | .695 [.553, .902] | .645 [.441, .847] |
| file size only (diagnostic) | .000 | .400 | .827 [.680, .934] | .688 [.547, .851] |
| random split (leaky diagnostic) | .960 | .960 | .999 [.986, 1.000] | .998 [.989, 1.000] |

**Direct answer:** capability F1 at 0.5 is .921 and P/Invoke .795; the
F1-optimal OOF CIs overlap (.903 [.800, .971] vs .788 [.677, .904]). PR-AUC
(.988 vs .695) and ROC-AUC (.980 vs .645) CIs separate. **Ranking favors
capability; the operating point does not separate at n=32 positives; neither
is a result.** The primary capability-vs-P/Invoke comparison is
capability-only; +policy and +all counts are ablations.

The random split is **+0.057** F1 above the cluster split and is not a result.

## 4. Holdout FPR (565 external Hassan benign EXEs)

**Primary (0.5 probability-only):** capability-only **35/565 = 6.2%**; full
model (capability + all counts) **13/565 = 2.3%**; capped capability 125/565 =
22.1%; capability+policy 13/565 = 2.3%. The historical 2.3% is the full model
at 0.5, not capability-only. P/Invoke at 0.5 is a raw count (“any P/Invoke”)
and is **not comparable**.

**Failed matched-95 calibration (sensitivity only):** capability **0/565 at
actual recall 78.1%, which is not a result**; P/Invoke 48/565 = 8.5% at actual
recall 81.2%; full model 108/565 = 19.1% at actual recall 100%. The target does
not transfer and the FPRs are at different actual recalls; no “capability has
lower FPR” claim is made. Any 0/565 is not a result.

## 5. LOCO (mixed positive + benign folds)

Every fold holds out one positive cluster plus its round-robin benign
clusters; all 70 benign clusters are held out exactly once; 0 mixed clusters;
no held-out cluster appears in fold-train. **Primary is the 0.5
probability-only reference plus PR/ROC.** P/Invoke and file size at 0.5 are
raw scores and are not comparable.

| scope | model | recall [CI] | FPR [CI] | F1 [CI] | PR-AUC | ROC-AUC |
|---|---|---|---:|---|---:|---:|
| verified | capability | .981 [.900, 1.000] | .016 [.000, .039] | .984 [.913, .997] | .998 | .997 |
| verified | capped | .974 [.877, .996] | .031 [.000, .082] | .974 [.875, .994] | .997 | .996 |
| verified | capability+policy | .981 [.900, 1.000] | .039 [.006, .094] | .974 [.877, .994] | .997 | .996 |
| verified | capability+all | .987 [.912, 1.000] | .031 [.000, .082] | .981 [.898, .996] | .998 | .997 |
| verified | structural | .968 [.846, .992] | .155 [.067, .264] | .923 [.727, .975] | .920 | .931 |
| positive | capability | .981 [.946, 1.000] | .023 [.000, .069] | .983 [.951, .997] | .999 | .998 |
| positive | capped | .981 [.935, .996] | .031 [.000, .082] | .981 [.942, .994] | .998 | .997 |
| positive | capability+policy | .981 [.935, .996] | .054 [.000, .140] | .974 [.929, .992] | .998 | .997 |
| positive | capability+all | .981 [.935, .996] | .062 [.007, .148] | .972 [.924, .990] | .998 | .996 |
| positive | structural | .962 [.867, .987] | .140 [.053, .267] | .940 [.833, .978] | .962 | .948 |

**Matched-95 LOCO (sensitivity only):** capability actual recall .903/.925
with FPR 0/129; P/Invoke .942/.948 with FPR .643/.674. The target does not
transfer and the FPRs are at different actual recalls; not directly
comparable. The old positive-only 2.1c diagnostic had 3 verified / 5 positive
singleton misses; the mixed fold-threshold view has 24; the matched-95 view
has 31. Details in `Data/Audit/error_analysis.json`.

## 6. Ablations

- **D1 cap (train only):** largest positive cluster `053fa0de…` **89 → 10**
  (79 removed); train **238/148 → 159/69**. Test F1 at OOF .897 vs .903
  uncapped; 0.5 F1 .935. It does not change the DB, labels, splits or gate.
- **P1 feature policy:** file size, section count, entropy max/mean are not
  model features; they remain diagnostic. Structural policy .844 vs all .857
  (OOF); capability+policy .955 vs capability+all .941. The policy matrix is
  `Data/Features/policy/`.
- **Random-split leak:** .960 vs .903 capability OOF, **+0.057**; leaky
  diagnostic only.

## 7. Stage 2

Eligibility (>=20 rows, >=10 clusters) leaves **AsyncRAT and XWorm only**.
Test: 29 rows, macro F1 **.931 [.807, 1.000]**; AsyncRAT .933, XWorm .929.
There are 2 XWorm→AsyncRAT errors, clusters `32ba94d5…` and `9d08e5e6…`;
neither is `00fe40a8`, and their nearest distance to the 89-row AsyncRAT
cluster is 706/354, not 88. This is a diagnostic 2-family LightGBM on 29
rows, **not a family model**.

## 8. Automated label audit (not human gold)

Audited 1,540 rows; 530 rows (all unverified) are MB-signature-only, and
263 rows across classes are multi-source. Conflict-only categories:

- verified_other: **14 majority-supported / 0 different / 42 tie** (56 flags);
- unverified: **20 majority-different / 31 tie** (51 flags);
- gold candidates: **4 majority-different / 7 tie** (11 flags).

Top unverified pairs: AsyncRAT|XWorm 28, AsyncRAT|DcRat 19. The project
`lineage_only` flag is 11 verified; the broader DB-only no-family-scoped count
is 49. **No labels were changed or inferred. Gold is 30 rows / 0 filled / no
merge. The independent static review is partial (5/30); it is not used as
ground truth and is not merged.**

## 9. Obfuscation, temporal, gold

- Obfuscation: verified 10/154 (6.5%); unverified AsyncRAT-suggested 106/498
  (21.3%). Test has 6 obfuscated rows, **4 positives**; capability caught 2/4
  at matched 95. No metric is computed below 20 positives.
- Temporal: benign dates are collection batches (10 `collected_at` values);
  every temporal number is diagnostic.
- Gold: 30 rows, 0 filled; no human review, no merge. An independent static
  review is a separate, incomplete track; it is not used as ground truth and
  is not merged. D2/WS3 **not run**.

## 10. What can be claimed

| claim | status |
|---|---|
| Dataset composition and gate failure are measured | **Supported** |
| Label provenance is auditable; MB-only and conflict counts are measured | **Supported** |
| Capability features rank above a single P/Invoke count (PR/ROC CIs separate) | **Supported as diagnostic ranking**, not a deployed detector |
| F1 at the operating point is higher than P/Invoke | **Not supported** — CIs overlap at n=32 |
| The model generalizes to real-world AsyncRAT or other .NET RATs | **Not supported** |
| A Stage 2 family model is ready | **Not supported** — 29 rows, 2 families |
| The gate passes or a detector is deployable | **Not supported** — gate FAIL |
| Gold labels are ground truth | **Not supported** — 0/30 filled |

## 11. Model card

- **Intended use:** research/education, static triage of .NET AsyncRAT client
  payloads, capability ablation and methodology study. Research only.
- **Out of scope:** droppers, loaders, PowerShell/VBS stagers, native (Go/C++)
  builds, dynamic analysis, server/builder/stub/panel artifacts, deployment.
- **Features:** external metadata references (TypeRef, MemberRef, AssemblyRef,
  ImplMap, ImportTable) and allowed metadata counts; TLSH nearest neighbor for
  explanation. File size/section/entropy are diagnostic-only, not policy
  features. No sample names, user strings, `is_dotnet`, or label fields.
- **Labels:** 154 verified AsyncRAT clients, 58 verified_other (XWorm 49,
  VenomRAT 5, QuasarRAT 3, DcRat 1), 704 benign (565 external holdout + 139),
  plus 624 unverified, 278 non-.NET, 4 review, 2 reference-only.
- **Performance:** see §3–§5. All numbers are diagnostic; the gate fails.
- **Limitations:** dominant 89-row cluster, 52 AsyncRAT clusters, 32 test
  positives, degenerate train split, threshold target does not transfer,
  small Stage 2, label audit is not human gold, no real-world claim.
- **Ethics/safety:** static parsing only; no execution; samples untracked.

## 12. Reproduction

```bash
python3 Tools/Models/fixup_eval.py
python3 Tools/Audit/label_quality.py
python3 Tools/Audit/error_analysis.py
```

Seed 42; OOF `GroupKFold` by `cluster_id`; script hash and run id above. The
outputs are `Data/Features/fixup_results.json`,
`Data/Audit/label_quality.json` and `Data/Audit/error_analysis.json`.

## D2 remains not run

D2 would move 70% of the 565 `clrheader2023` benign rows into ordinary training
(by cluster, seed 42) and keep 30% (~170 rows) as the external holdout. It can
change positive split assignments and shrinks the holdout, so it requires
**explicit approval**. It was not executed here; the full 565-row holdout is
unchanged.

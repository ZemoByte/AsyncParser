# results.md — run reports

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

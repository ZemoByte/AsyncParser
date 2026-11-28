# Limitations — frozen at the Phase 1.9/3.0 ceiling

These are measured limits, not open tasks. No more AsyncRAT data collection is
planned (batch-2 yield was 6.9%, below the 13% stop line).

## Dataset ceiling

- **1,824 rows / 1,228 clusters / 0 NULL `cluster_id` / evidence 12,768.**
- Labels: 154 verified, 58 verified_other, 704 benign, 624 unverified,
  278 rejected_non_dotnet, 4 review, 2 reference_only.
- Class DBs: AsyncRAT 154, OtherMalwares 58, Benign 704.
- Stage 1 AsyncRAT: **52 clusters, largest 89 = 57.8% — FAIL** (needs ≥178
  verified at that cluster size, or ≤50% share; 24 samples short).
- Stage 1 benign active: 70 clusters, largest 14.7% — PASS.
- Stage 2: XWorm 49/23/49.0% PASS; VenomRAT 5/4/40% PASS; AsyncRAT 57.8%
  FAIL; QuasarRAT 3/2/66.7% FAIL; DcRat 1/1/100% FAIL → overall FAIL.
  This cannot be fixed by AsyncRAT downloads.

## Labels

- **11 verified rows are lineage-only** (own-YARA/MB, no family-scoped
  AsyncRAT voter): 9 from Phase 1.7 + `26e8b9f0`, `b5ddcd46`. Kept, not
  downgraded. Stage 1 is 57.8% with them and **62.2% without them** — it fails
  either way.
- **624 unverified** rows (mostly historical files only the MB signature
  recognizes) and **278 non-.NET** rows are outside training.
- Batch 2 added 24 verified from 350 samples (**6.9%**).
- All 498 unverified rows with an MB-signature AsyncRAT **suggestion** are
  supported by that signature alone; none has a family-scoped voter verdict.
  This is a suggestion, **not confirmed AsyncRAT**. Obfuscated (106) and plain
  (392) rows show the same pattern, so obfuscation is not the discriminator.

## Split validity

- 341 primary rows: train 238 (148 positives, 23 clusters, largest **60.1%,
  degenerate**), val 51 (32/30, 6.2%), test 52 (32/29, 12.5%).
- 0 cluster spans; `reference_only`, `unverified`, review and gold rows have
  NULL splits. The rebalance post-pass made no move because the test split was
  already healthy after batch 2.
- Because train is degenerate, **every model number is DIAGNOSTIC ONLY**.
  Capability-only F1 0.921 (and the earlier 0.963 at 1,505 rows) is a
  diagnostic, not validation.
- **Holdout FPR, ordered:** capability-only 0.5 = **35/565 (6.2%)**; full model
  0.5 = **13/565 (2.3%)**; full model OOF = **108/565 (19.1% [11.9, 27.9])**;
  capability OOF = **19/565 (3.4%)**. The 2.3% is a 0.5 historical number,
  **not the main FPR**. LOCO not triggered (23 train positive clusters).
- **Benign time order is a collection-batch artifact:** all 704 benign rows
  fall back to `collected_at` (10 distinct timestamps), not real first-seen
  dates. Positives use `YYYY-MM-DD HH:MM:SS`; benign uses ISO
  `YYYY-MM-DDTHH:MM:SS+00:00`, so mixed formats can sort wrongly within one
  date. Every temporal result is diagnostic.

## Cross-family proximity

Two test→train pairs within TLSH 100, kept as human/gold review items:

1. XWorm `00fe40a8` (4 rows) ↔ AsyncRAT `053fa0de` (89 rows), distance 88.
2. DcRat `054498f9` (1 row) ↔ AsyncRAT `053fa0de` (89 rows), distance 64.

Both sides carry strong family-scoped voters and valid configs (the DcRat
pair 1/1 config). The family guard is intentional; **no merge or relabel** was
applied. A human should decide whether these are build-family edges or
labeling errors.

## Evidence coverage

- YARAify: 1,824 lookups at 1 req/s, 193 rule hits; benign/non-.NET samples
  are skipped honestly (`skipped_benign` / `skipped_non_dotnet`).
- DIE: 1,603 plain / 221 obfuscated / 0 unknown. DIE signatures are not
  ground truth and some packers are not covered.
- The 12,768 evidence rows are seven voters per sample; a missing voter would
  reduce coverage, not silently pass.

## Gold and claims

- Gold audit is **0/30 filled**; the review sheet has 30 rows, 0 missing.
  Only a human can fill `gold_status`/`gold_family`.
- There is **no real-world detection claim**. Stage 1 and Stage 2 fail their
  gates; all baselines are diagnostic. Do not report a detector result from
  this dataset until independent clusters (especially AsyncRAT) increase.

## Phase 4 diagnostics (still not a result)

- LOCO over 152 clusters (82 positive folds): full F1 0.981, capability 0.983,
  structural 0.915, TLSH kNN 0.773. High because clusters are near-duplicate
  builds; capability F1 is **not** a validated result.
- Abstention threshold 357 (train-only): verified abstain 9.1% (coverage
  90.9%), other 3.4%, benign 65.9%. The benign abstention rate is a real
  coverage limitation.
- Obfuscated stratum is tiny (20 rows): full F1 0.818 vs 0.990 plain.
- Hassan-style non-name CLR-header baseline F1 0.874 vs capability 0.983 —
  methodology comparison only, not superiority.
- Stage 2 rules/kNN: 24/58 abstain; 33/34 decided correct (1 XWorm→VenomRAT).
  QuasarRAT/DcRat always abstain with these counts.
- Holdout FPR follows the ordered block above; 2.3% is a 0.5 historical
  number for the full model, not the main FPR. Training composition matters;
  neither number is a production estimate.
- The data ceiling and no-batch-3 decision remain in force.

## Fixup policies (diagnostic, 2026-11-28)

- **P1 feature policy:** `structure_file_size`, `structure_section_count`,
  `structure_entropy_max` and `structure_entropy_mean` are not model features;
  they appear only in the diagnostic run. The policy matrix is separate
  (`Data/Features/policy/`); the original matrix and baseline are untouched.
- **D1 cap:** train only, largest positive cluster `053fa0de…` capped from 89
  to 10 rows (79 removed, numpy seed 42). Train goes from 238 rows / 148
  positives to 159 / 69. Val and test are not capped; the DB, labels and split
  files are unchanged. This is an ablation, not a fix for the gate.
- **P2 Stage 2 eligibility:** a family needs at least 20 rows and 10 clusters.
  Only AsyncRAT (154/52) and XWorm (49/23) qualify. VenomRAT (5/4), QuasarRAT
  (3/2) and DcRat (1/1) are excluded from Stage 2 metrics; the gate code is
  unchanged.
- **D2 Hassan 70/30 partition:** not run; it awaits explicit approval. The
  main FPR remains the full 565-row external holdout.
- **P3 temporal:** every temporal number is diagnostic; see the
  collection-batch caveat above.
- **Still no detector claim.** Stage 1 and Stage 2 fail, and no number in this
  document is a real-world estimate.

### Fixup evaluation limits

- **OOF threshold:** the main operating point is selected on grouped 5-fold
  OOF train scores (`GroupKFold` by `cluster_id`). Test labels never choose it.
  0.5 is the fixed reference; the in-sample threshold is an explicitly overfit
  sensitivity column. Capability's OOF threshold is **0.559** (close to 0.5);
  the full model's is **0.064**.
- Test split is 52 rows (32 positives, 48 clusters). At the OOF threshold,
  capability F1 is **.903 [.800, .971]** and P/Invoke **.788 [.677, .904]**
  (overlap): the operating point does not separate them. PR-AUC **.988
  [.959, 1.000]** vs **.695 [.553, .902]** and ROC-AUC **.980 [.941, 1.000]**
  vs **.645 [.441, .847]** do separate. Ranking favors capability; neither
  comparison is a result.
- The random split leak check is **.960 (+.057)** F1; not a result.
- **Holdout:** capability-only 0.5 = **35/565 = 6.2%**; full model 0.5 =
  **13/565 = 2.3%**; full model OOF = **108/565 = 19.1% [11.9, 27.9]**;
  capability OOF = **19/565 = 3.4% [2.2, 5.2]**. The historical 2.3% is the
  full model at 0.5, not the main FPR; no 0/565 row is headlined. The capped
  model's 6/565 at OOF is not evidence of a perfect detector.
- **Mixed LOCO at 0.5:** 52 verified folds and 82 positive folds; 70 benign
  clusters, each held out once; 0 mixed clusters; no held-out cluster in
  fold-train. Capability recall .981/.981 with FPR .016/.023; P/Invoke recall
  .942/.953 with FPR .636 (raw-count 0.5 means "any P/Invoke"). Capability's
  fold-trained thresholds are ~0.993–0.997 and still give 0 FPR; that is the
  in-sample artifact the fixed 0.5 table replaces. Threshold rows are
  sensitivity only.
- **Label audit:** the automated audit covers 1,540 rows; 530 are MB-signature-
  only (all unverified), 263 are multi-source, 107 have conflicting family
  verdicts. The project `lineage_only` flag is 11 verified rows; the broader
  DB-only no-family-scoped count is 49. This is evidence, **not human gold**.
- **Gold:** 30 rows, 0 filled, no merge; 11 gold candidates have evidence
  conflicts. No gold_status/gold_family was filled or inferred.
- **Still no detector claim.** Stage 1 and Stage 2 fail, and no number in this
  document is a real-world estimate.

## Matched-recall caveat (Phase 5)

- The primary external comparison is the fixed **0.5 probability reference**
  plus threshold-free PR/ROC. The matched-95 target is a failed calibration and
  is sensitivity only.
- Matched thresholds are chosen on **train OOF** scores at 95%/90% target
  recall. The target does **not** transfer: capability's 95% threshold is
  ~.998 but actual test recall is 78.1%; P/Invoke's actual test recall is
  81.2% at raw threshold 4. Capability's holdout FPR is 0/565 at 78.1% actual
  recall, P/Invoke's is 48/565 at 81.2%. **0/565 is not a result**, and FPRs at
  different actual recalls are not directly comparable. No “capability has
  lower FPR” claim is made.
- LOCO matched 95: capability actual recall .903/.925 with FPR 0/129;
  P/Invoke .942/.948 with FPR .643/.674. The same actual-recall caveat applies;
  0.5 is a probability-model reference only, never P/Invoke/file size.
- **Conflict definition:** a conflict is any row with more than one distinct
  non-`no_match` family verdict. There are 107: verified_other 56 = **14
  majority-supported / 0 majority-different / 42 tie**; unverified 51 = **20
  majority-different / 31 tie**. Gold candidates have 11: **4 different / 7
  tie**. This is evidence about voter disagreement, **not human gold**.
- Obfuscated test subset: 6 obfuscated rows, of which **4 are positives**;
  capability caught 2/4 at matched 95. No metric is computed below 20
  positives.
- Gold remains **30 rows / 0 filled / no merge**; D2/WS3 is not run.

## Independent static review (not gold)

The independent static review is partial: **15/30 rows**, with **8
status+family agreements, 1 family match/status upgrade, and 6 real
disagreements**. Five unverified rows look benign (3 AsyncRAT-suggested, 2
XWorm-suggested); `0384e80d` sits in a 40-row unverified cluster. It is not
ground truth, no labels were changed, and it was not merged.

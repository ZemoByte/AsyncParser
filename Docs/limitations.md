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

## Split validity

- 341 primary rows: train 238 (148 positives, 23 clusters, largest **60.1%,
  degenerate**), val 51 (32/30, 6.2%), test 52 (32/29, 12.5%).
- 0 cluster spans; `reference_only`, `unverified`, review and gold rows have
  NULL splits. The rebalance post-pass made no move because the test split was
  already healthy after batch 2.
- Because train is degenerate, **every model number is DIAGNOSTIC ONLY**.
  Capability-only F1 0.921 (and the earlier 0.963 at 1,505 rows) is a
  diagnostic, not validation.
- Holdout FPR 13/565 = 2.3%; LOCO not triggered (23 train positive clusters).

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

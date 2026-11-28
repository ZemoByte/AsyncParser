# Handoff — AsyncParser Phase 6 freeze

**Status:** frozen diagnostic package. Dataset gate **FAIL**; no detector
claim. Gold **30 rows / 0 filled**; D2/WS3 **not run**. No data, labels,
clusters, splits or gate thresholds changed in this phase.

## Done

- Dataset: 1,824 rows / 1,228 clusters / 0 NULL; labels 154/58/704/624/278/4/2.
- Pipeline and evidence: seven voters, aggregator, clustering, carvers,
  importer, splits, feature matrices, baseline and fixup diagnostics.
- Evaluation: grouped OOF thresholds, matched-recall sensitivity, mixed LOCO,
  error analysis, automated label-quality audit.
- Final docs: `FINAL_RESULTS.md`, `CLAIMS.md`, `MODEL_CARD.md`,
  `D2_DECISION.md`, `limitations.md`, `REPRODUCE.md`.
- Tests: 234 pass; `git diff --check` clean.

## Not done

- D2/WS3 70/30 Hassan partition (not approved; see `D2_DECISION.md`).
- Human gold audit (0/30); independent static review is partial and not merged.
- Deployment, real-world validation, dynamic analysis, droppers/loaders/
  stagers/native builds.

## File map

- `Docs/FINAL_RESULTS.md` — thesis-ready synthesis.
- `Docs/CLAIMS.md` — supported / diagnostic / not-supported claims.
- `Docs/MODEL_CARD.md` — one-page model card.
- `Docs/D2_DECISION.md` — D2 brief; not run.
- `Docs/limitations.md` — measured ceilings and caveats.
- `Docs/REPRODUCE.md` — pipeline and final commands.
- `Docs/results.md` — chronological run log.
- `Data/Features/fixup_results.json` — final evaluator output (run
  `c7a21a6c37f14f5aabcc821dd26729cd`, script `6598bfce…`).
- `Data/Audit/label_quality.json` — automated label audit, not human gold.
- `Data/Audit/error_analysis.json` — test/LOCO/Stage 2/holdout errors.
- `Data/Gold/review/gold_review_sheet.csv` — 30 rows, 0 filled.

## Reproduction

```bash
python3 tests/run_tests.py
python3 Tools/Models/fixup_eval.py
python3 Tools/Audit/label_quality.py
python3 Tools/Audit/error_analysis.py
```

Seed 42; OOF `GroupKFold` by `cluster_id`; one evaluator run. Full pipeline
order is in `Docs/REPRODUCE.md`. The gate is checked by
`Tools/_gate.py:evaluate_gate` and remains **FAIL** (AsyncRAT 52 clusters,
largest 89 = 57.8%).

## Thesis claim

> On a frozen 1,824-row diagnostic dataset, capability features rank above a
> single P/Invoke count on threshold-free PR/ROC, but the operating-point F1
> CIs overlap and the dataset gate fails; the Stage 2 check has only 29 test
> rows. These are diagnostic findings, not a detector result.

## Git handoff

This phase staged and committed nothing. At freeze, `git status --short`
showed:

```text
 M Docs/DECISIONS.md
 M Docs/DECISIONS_PART2.md
MM Docs/GOLD_AUDIT.md
 M Docs/Plan.md
MM Docs/REPRODUCE.md
MM Docs/TO-DO.md
MM Docs/limitations.md
MM Docs/results.md
 M Tools/Features/build_matrix.py
 M Tools/Models/baseline.py
M  Tools/Models/evaluate.py
 M Tools/_versions.py
A  tests/test_phase4.py
?? Docs/CLAIMS.md
?? Docs/D2_DECISION.md
?? Docs/FINAL_RESULTS.md
?? Docs/HANDOFF.md
?? Docs/MODEL_CARD.md
?? Tools/Audit/error_analysis.py
?? Tools/Audit/label_quality.py
?? Tools/Models/fixup_eval.py
?? tests/test_fixup.py
?? tests/test_label_quality.py
```

The staged entries predate this phase. Suggested neutral commit message:

```
Freeze diagnostic evaluation and thesis package (Phase 6)
```

Do not commit binaries, `Samples/`, or generated JSON/logs. No deletions were
made in this phase.

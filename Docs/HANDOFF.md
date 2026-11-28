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
- Tests: 258 pass; `git diff --check` clean.

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
python3 Tools/Pipeline/run.py --freeze   # frozen-package check; runs no stages
python3 Tools/Models/fixup_eval.py
python3 Tools/Audit/label_quality.py
python3 Tools/Audit/error_analysis.py
python3 Tools/Models/export_model.py
python3 Tools/Models/predict.py --file /path/to/file.exe
```

`run.py` is plan-only unless `--apply` is passed; `--allow-network` is needed
only for **YARAify**, the only online voter. No stage was run in this phase.
The CLI is a static prototype, not a detector; see `Docs/CLI.md`. Parity on 30 known samples: 23 scored matches, 7 abstentions, 0 mismatches.

Seed 42; OOF `GroupKFold` by `cluster_id`; one evaluator run. Full pipeline
order is in `Docs/REPRODUCE.md`. The gate is checked by
`Tools/_gate.py:evaluate_gate` and remains **FAIL** (AsyncRAT 52 clusters,
largest 89 = 57.8%).

## Portable bundle

See `Docs/BUNDLE.md` and `Docs/HOST_SETUP.md` for the final host bundle `/tmp/opencode/asyncparser_bundle_final.tar.gz`, exclusions, CPU-only setup and smoke commands. The thesis package is `Docs/THESIS_OUTLINE.md` / `Docs/THESIS_FIGURES.md`; the final audit is `Docs/FINAL_AUDIT.md`.

## Thesis claim

> On a frozen 1,824-row diagnostic dataset, capability features rank above a
> single P/Invoke count on threshold-free PR/ROC, but the operating-point F1
> CIs overlap and the dataset gate fails; the Stage 2 check has only 29 test
> rows. These are diagnostic findings, not a detector result.

## Git handoff

No Git actions were performed by the implementation; the user owns the repo.
At freeze, the working tree contained pre-existing index entries and new
untracked docs/source files; nothing was staged or committed in this phase.
Do not commit binaries, `Samples/`, or generated JSON/logs. No deletions were
made in this phase.

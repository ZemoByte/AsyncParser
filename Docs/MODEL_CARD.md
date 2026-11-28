# Model card — AsyncRAT capability detector (diagnostic)

**Status:** research/education artifact. **Not a deployed detector.** Dataset
gate FAIL. No real-world performance claim.

## Intended use

Static triage and methodology study of **.NET AsyncRAT client payloads**:
capability features from .NET metadata, cluster-aware evaluation, threshold
calibration and error analysis. Research use only.

## Out of scope

Droppers, loaders, PowerShell/VBS stagers, native (Go/C++) builds, dynamic
analysis, server/builder/stub/panel artifacts, non-.NET files, production SOC
deployment, and any claim of family attribution beyond the diagnostic
AsyncRAT-vs-XWorm Stage 2 check.

## Features

- External metadata references: TypeRef, MemberRef, AssemblyRef, ImplMap,
  ImportTable.
- Allowed metadata counts: type, method, typeref, memberref, implmap,
  importtable, resource.
- TLSH nearest-neighbor explanation only.
- Excluded from policy features: file size, section count, entropy max/mean
  (diagnostic run only). No sample names, user strings, `is_dotnet` or label
  fields.

## Labels and data

1,824 rows / 1,228 clusters: 154 verified AsyncRAT, 58 verified_other
(XWorm 49, VenomRAT 5, QuasarRAT 3, DcRat 1), 704 benign (565 external
`clrheader2023` holdout + 139), 624 unverified, 278 non-.NET, 4 review,
2 reference-only. Gold is **0/30**; the automated label audit is not human
gold.

## Performance summary

- Test (52 rows / 32 positives): capability F1 .921 at 0.5 and .903 at the
  F1-optimal OOF threshold; P/Invoke .795/.788. F1 CIs overlap; PR-AUC
  (.988 vs .695) and ROC-AUC (.980 vs .645) CIs separate. The primary
  capability-vs-P/Invoke comparison is capability-only; +policy and +all are
  ablations.
- Holdout 565 at 0.5: capability 35/565 (6.2%); full model 13/565 (2.3%).
  P/Invoke at 0.5 is a raw count and is not comparable.
- LOCO at 0.5: capability recall .981, FPR .016 (verified); P/Invoke raw-count
  0.5 is not comparable.
- Stage 2: AsyncRAT vs XWorm only, n=29, macro F1 .931 [.807, 1.000];
  diagnostic, not a family model.

## Limitations

Dominant 89-row AsyncRAT cluster (57.8%); 52 AsyncRAT clusters; 32 test
positives; degenerate train split (60.1%); tiny obfuscated subset (4
positives); label audit is not ground truth; no human gold; no real-world
claim. The matched-95 calibration failed to transfer: capability flagged
0/565 at 78.1% actual recall; **this is not a result**. D2/WS3 is not run.

## Prototype CLI

A static single-EXE prototype exists (`Tools/Models/predict.py`). Its outputs
are Stage 1 diagnostic and, only for a Stage-1 RAT, an AsyncRAT-vs-XWorm
diagnostic (`n=29`); all other cases abstain. It is not a detector and makes
no other-malware claim. See `Docs/CLI.md`.

## Safety

Static parsing only. No sample execution, loading or building. Samples are
untracked. No network or API use in this run.

## Reproduction

```bash
python3 Tools/Models/fixup_eval.py
python3 Tools/Audit/label_quality.py
python3 Tools/Audit/error_analysis.py
```

Seed 42; grouped OOF by cluster; see `Docs/FINAL_RESULTS.md` for the run id and
script hash.

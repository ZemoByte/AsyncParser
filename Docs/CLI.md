# Static single-EXE prototype

**NOT VALIDATED — dataset gate FAIL; research prototype; not a detector.**
Static parsing only. The CLI never executes, loads, uploads or builds a file.

## Commands

```bash
# Regenerate the frozen model artifacts (writes Data/Models/, gitignored)
python3 Tools/Models/export_model.py

# One file, human-readable
python3 Tools/Models/predict.py --file /path/to/file.exe

# One file, JSON
python3 Tools/Models/predict.py --file /path/to/file.exe --json
```

`Data/Models/capability.joblib` carries the frozen capability model,
vocabulary, threshold `0.559`, abstention threshold `357`, run id
`c7a21a6c37f14f5aabcc821dd26729cd` and script hash `6598bfce…`.
`Data/Models/family_asyncrat_xworm.joblib` is the diagnostic two-family model.

## Output

Every text output starts with:

```text
NOT VALIDATED — dataset gate failed; research prototype; not a detector.
```

A weak-evidence abstention looks like:

```text
NOT VALIDATED — dataset gate failed; research prototype; not a detector.
stage1: abstain (too_few_typeref_memberref (17 < 357))
family abstain: stage 1 abstained
abstain: too_few_typeref_memberref (17 < 357)
```

A scored probability example (illustrative values):

```text
NOT VALIDATED — dataset gate failed; research prototype; not a detector.
stage1: score=0.812000 threshold=0.559 predicted=RAT
stage2: AsyncRAT=0.610000 XWorm=0.390000 predicted=AsyncRAT (diagnostic, n=29)
```

`--json` includes `validated=false`, `gate="FAIL"`, `sha256`, `stage1`,
`stage2` and `abstain`.

## Abstention rules

- No readable file / hash error → error exit 1.
- PE/CLR parse failure → abstain with the exact reason.
- No CLR header → `rejected_non_dotnet`.
- Combined TypeRef + MemberRef count below `357` (the frozen 5th-percentile
  train threshold) → `too_few_typeref_memberref`.
- Stage 1 above `0.559` → `RAT`; otherwise `benign`.
- Stage 2 is printed only for a Stage-1 RAT prediction. It is **AsyncRAT vs
  XWorm only** and is labelled `diagnostic, n=29`; other families are not
  modeled. A Stage-1 abstention or benign result prints the family abstention.

## Exit codes

| code | meaning |
|---:|---|
| 0 | Stage 1 scored (RAT or benign) |
| 2 | abstained (non-.NET, parse failure, too few references, Stage 1 abstention) |
| 1 | input/model/read error |

## Parity check

On 30 known samples (10 AsyncRAT, 10 benign, 10 other), the CLI was compared
with the cached capability row and the CLI artifact:

- **23 scored parity matches, 0 mismatches, 7 expected abstentions**
  (too few TypeRef+MemberRef references).
- **30/30 raw parses checked**; 0 parse failures. The CLI has no feature
  cache, so every run parsed the file.
- Feature-vector differences: 0; score differences: 0 (1e-6 tolerance).
- All 5 non-AsyncRAT/XWorm family samples abstained; no other-family score
  was printed.
- The 10 AsyncRAT samples: 9 scored, 1 weak-evidence abstention; the 10
  benign: 4 scored (benign), 6 weak-evidence abstentions; XWorm: 5 scored.

`Data/Audit/cli_parity.json` has sha8-only rows and the summary. No C2 or
config values are printed. This is a parity/abstention check, not a new
metric, and not a detector result.

## Limits

Not a detector; no other-malware claim; no deployment. The family output is a
two-class diagnostic, not a family classifier. The gate is FAIL and gold is
0/30.

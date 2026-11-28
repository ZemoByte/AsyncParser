# Final audit

**Snapshot:** 258 tests; `Data/DataSet.db` SHA-256
`e2db6434824f4f7952c68cda5d31ef538bfcceb122bdaac1cdf64eff1e3d1a75`;
341 split JSONs; gate **FAIL**; gold **30 rows / 0 filled**; D2 **not
applied**.

**Base commit:** `5f9d36cd`; the working tree includes Phases 9–12 (bundle
guard, CLI parity, portable bundle, thesis package). No Git action was taken
by the implementation.

## Bundle

- Path: `/tmp/opencode/asyncparser_bundle_final.tar.gz`
- Size: 51,364,477 bytes
- SHA-256: `48be48b5d42d802d6b4bed919748e11d9585fd424030afb3d74d5944b898fe50`
- Superseded old bundle: `/tmp/opencode/asyncparser_bundle.tar.gz`
  (`7d02a851…`, kept)
- Contents: `AGENTS.md`, `Docs/`, `Tools/`, `tests/`; four DBs; features
  (including policy), models, splits, clusters, structure, class carve JSONs,
  aggregated labels, gold, reports, audit; `README_BUNDLE.md`,
  `SHA256SUMS`, `BASE_COMMIT.txt`.
- Excluded: `Samples/`, `.env`, keys, `Reference/` rules, `Data/Pipeline/`,
  `Data/MB/`, `.git/`, caches.
- No `Samples/`, `.env`, `Data/Pipeline`, `Reference`, or `.git` path is in
  the tar listing.

## Verification

- Extracted to a temp directory: **258 tests, OK**.
- `predict.py --help`: OK.
- Synthetic benign fixture: NOT VALIDATED banner and abstention (exit 2).
- Bundle `DataSet.db` SHA-256 matches; **341 splits**; 10 CSV figures and the
  four Phase 12 docs are present.
- Final archive: 51,364,477 bytes, SHA-256 `48be48b5d42d802d6b4bed919748e11d9585fd424030afb3d74d5944b898fe50`; old 7d02 archive kept
  and superseded.
- DB/gate/gold unchanged after the phase.

## CLI parity

30 known samples: **23 scored matches, 0 mismatches, 7 abstentions, 30 raw
parses, 0 parse failures**. Stage 2 is AsyncRAT vs XWorm only; other families
abstain. The CLI remains a prototype.

## Safety / data

No sample bytes were copied into the bundle; no sample was executed or
uploaded. The DBs contain malware metadata/config. Gold is 0/30; the
independent static review is partial and not merged. D2 is not run.

## User commit checklist

1. Review `Docs/FINAL_RESULTS.md`, `Docs/CLAIMS.md`, `Docs/MODEL_CARD.md`,
   `Docs/THESIS_OUTLINE.md`, `Docs/THESIS_FIGURES.md`,
   `Docs/FINAL_AUDIT.md`, `Docs/HOST_SETUP.md`.
2. Confirm `python3 tests/run_tests.py` is 258 OK.
3. Check `git status`; no `Samples/`, `.env`, DB binaries outside the intended
   tracked set, or pipeline logs.
4. Suggested neutral commit message:
   `Freeze thesis package, host setup, and final audit`
5. Do not push. The bundle stays outside the repository at
   `/tmp/opencode/asyncparser_bundle_final.tar.gz`.

No Git commands were run by the implementation; the user owns the repository.

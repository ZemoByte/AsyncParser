# Portable bundle

**Bundle:** `/tmp/opencode/asyncparser_bundle_final.tar.gz` (51,364,477 bytes, `48be48b5…`)  
**Base commit:** `5f9d36cd`; working tree includes Phases 9–10b.  
**CPU only.** The 4 GB RTX 3050 is not needed; tests and the CLI run on CPU.  
**Gate FAIL. Gold 30/0. The CLI is NOT VALIDATED and is not a detector.**

## Contents

- `AGENTS.md`, `requirements.txt`, `Docs/`, `Tools/`, `tests/`.
- `Data/DataSet.db`, `Data/AsyncRAT.db`, `Data/Benign.db`,
  `Data/OtherMalwares.db`.
- `Data/Features/` (including `policy/`), `Data/Models/`, `Data/Splits/`,
  `Data/Clusters/`, `Data/Structure/`, the class carve directories
  (`Data/AsyncRAT/`, `Data/Benign/`, `Data/OtherMalwares/`),
  `Data/Aggregated/`, `Data/Gold/`, `Data/Reports/`, `Data/Audit/`.
- `README_BUNDLE.md`, `SHA256SUMS`, `BASE_COMMIT.txt`.

## Excluded

`Samples/` (malware bytes), `.env`, API keys, `Reference/` (licensed rules),
`Data/Pipeline/` (logs/state/locks), `Data/MB/` (API cache), `.git/`,
`__pycache__/`, `.pytest_cache/` and `*.pyc`.

## Host setup

Python 3.10+; install `Tools/requirements.txt`. No GPU, no network, no
database or sample execution is required for the tests/CLI smoke. The DBs
contain malware **metadata** and label evidence; they do not contain sample
bytes. Do not upload the bundle.

## Commands

```bash
python3 tests/run_tests.py
python3 Tools/Models/predict.py --help
python3 Tools/Models/predict.py --file /path/to/benign_fixture.exe
```

The CLI smoke expects a benign/synthetic fixture and prints the NOT VALIDATED
banner; a weak fixture abstains. The exported artifacts are already present;
`python3 Tools/Models/export_model.py` regenerates them CPU-only. The frozen
evaluator is not required for the bundle smoke.

## Checksums

`SHA256SUMS` lists the DBs and model artifacts. The archive checksum is in the
sibling `/tmp/opencode/asyncparser_bundle_final.tar.gz.sha256`; a checksum inside the
archive cannot include the final archive hash without changing it.

## Safety

Static parsing only. Never execute, load as a process, import or build a
sample. No network and no upload. Gold is 0/30; do not fill or merge it. This
bundle is research material, not a detector.

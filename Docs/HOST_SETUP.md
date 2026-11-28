# Host setup — portable research bundle

**Bundle:** `/tmp/opencode/asyncparser_bundle_final.tar.gz`  
**Size:** 51,364,477 bytes  
**SHA-256:** `48be48b5d42d802d6b4bed919748e11d9585fd424030afb3d74d5944b898fe50`  
**Old bundle:** `asyncparser_bundle.tar.gz` (7d02a851…) is superseded.
**CPU only.** The 4 GB RTX 3050 is not used. **Gate FAIL; CLI NOT VALIDATED.**

## Linux / WSL

```bash
mkdir -p ~/asyncparser && tar -xzf asyncparser_bundle.tar.gz -C ~/asyncparser
cd ~/asyncparser
sha256sum Data/DataSet.db   # must start e2db6434
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r Tools/requirements.txt
python3 tests/run_tests.py
```

Expected: **258 tests, OK**. No GPU, no network and no samples are required
for the test suite.

## Windows

Use Python 3.10+ and a virtual environment:

```powershell
mkdir $HOME\asyncparser
tar -xzf asyncparser_bundle.tar.gz -C $HOME\asyncparser
cd $HOME\asyncparser
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r Tools\requirements.txt
python tests\run_tests.py
```

Verify the archive with `certutil -hashfile asyncparser_bundle.tar.gz SHA256`.
If `pip install tlsh` fails (no matching wheel / missing C++ build tools),
use **WSL2** and follow the Linux instructions there. Do not spend time
building a Windows tlsh toolchain for the thesis smoke.

## Frozen commands

```bash
# full diagnostic evaluator (CPU; writes Data/Features)
python3 Tools/Models/fixup_eval.py

# one-file prototype
python3 Tools/Models/predict.py --file /path/to/file.exe
python3 Tools/Models/predict.py --file /path/to/file.exe --json
```

Figures under `Docs/figures/` are CSV. On the host, optional
`pip install matplotlib` can plot them; the 4 GB GPU is not needed.
`fixup_eval.py` is diagnostic; it does not change the frozen dataset. The CLI
prints the banner:

```text
NOT VALIDATED — dataset gate failed; research prototype; not a detector.
```

It abstains for non-.NET, parse failure, or fewer than 357 combined
TypeRef+MemberRef entries. Stage 2 is printed only for a Stage-1 RAT and is
AsyncRAT vs XWorm only (`diagnostic, n=29`); other families abstain. Exit
codes: 0 scored, 2 abstained, 1 error.

## Troubleshooting

- `tlsh` build/wheel failure: use WSL2. The rest of the bundle is pure Python
  and does not require a GPU.
- LightGBM: CPU build; the 4 GB card is not used.
- `ModuleNotFoundError`: activate the venv and install
  `Tools/requirements.txt`; `joblib` is supplied by scikit-learn.
- The bundle has no `Samples/`. Supply only files you are authorized to
  analyze; do not copy the VM's `Samples/` directory.
- The frozen JSON is diagnostic; the gate is FAIL and gold is 0/30.

## Security

The DBs contain malware **metadata** and label evidence, not sample bytes.
Do not upload the bundle or its DBs. Do not execute, load as a process,
import or build any sample. Static parsing only. No network or upload.

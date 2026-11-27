# Gold set

`build_gold_set.py` selects about 30 **clusters** (one sample per cluster),
stratified by the current `lbl_sts`. It writes `Data/Gold/gold.csv` with the
human columns blank.

The gold set is for **auditing voter precision/recall**, not for training.
Gold rows stay in `DataSet.db` only; the importer sets `is_gold=1` and keeps
them out of the class DBs and every split.

## Command

```bash
python3 Tools/Gold/build_gold_set.py
```

Use `--force` to overwrite an existing `gold.csv`. Do not run it after you
start hand-labeling unless you intend to replace the set.

## How to label

Static analysis only. Never run, load, import or build a sample.

For each row, open the sample in dnSpyEx/ILSpy and fill:

| Column | Meaning |
|---|---|
| `gold_status` | `verified`, `verified_other`, `unverified`, `rejected_non_dotnet`, `review`, `benign`, `reference_only` |
| `gold_family` | Canonical family (`AsyncRAT`, `XWorm`, `DcRat`, `QuasarRAT`, `VenomRAT`, `NjRAT`, `Remcos`, `XenoRat`, `Benign`); required for `verified_other` |
| `confidence` | `high`, `medium`, `low` |
| `analyst` | Your name/handle |
| `date` | ISO date |
| `notes` | One-line reason |
| `evidence` | Short evidence pointer (namespace, method, config, rule) |

`gold_status` and `gold_family` are the only fields the aggregator/importer
read. The rest are for the audit trail.

## dnSpyEx checklist (AsyncRAT)

- CLR header present; assembly is a .NET client, not native.
- `Client` namespace and `Settings` static class with string fields.
- `Aes256` class with `Encrypt`/`Decrypt`; decrypt path uses `Convert.FromBase64String`.
- `MutexControl.CreateMutex`, `Settings.MTX`, persistence via `schtasks` or the
  `Software\Microsoft\Windows\CurrentVersion\Run` key.
- Config-shaped class with base64 strings, `Aes256.Decrypt`, `VerifyHash`.
- Compare with the reference source in `Reference/AsyncRAT-C-Sharp/` (read-only).

## After filling

Rerun:

```bash
python3 Tools/Aggregator/aggregator.py
python3 Tools/Clustering/clusterer.py
# five carvers
python3 Tools/Importer/importer.py
```

The aggregator applies a filled gold row as `lbl_src=human_gold` (Plan rule 10).
Empty gold rows are ignored.

## Audit

Compare each voter's evidence against the filled `gold_status`/`gold_family`:
coverage, precision, recall, F1, contradiction rate, and `obf_lvl` agreement.
Record the table in `Docs/results.md`.

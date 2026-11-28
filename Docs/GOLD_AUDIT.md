# Gold audit — human reviewer instructions

The gold set is a **human audit** of voter precision, not training data. The
automation must never fill `gold_status` or `gold_family`. This sheet is read-only
preparation.

Current sheet: **30 rows, 0 missing, 0 filled** against the frozen 1,824-row
dataset. Fill it only by static review; the merge tool will not run until the
human is done.

## Files

- Input: `Data/Gold/gold.csv` (30 rows, human columns blank; a historical
  snapshot, not the current label source).
- Working sheet: `Data/Gold/review/gold_review_sheet.csv` (one row per sample;
  `current_status`/`current_family` are read from `DataSet.db`, and the old
  CSV values are preserved in `gold_snapshot_status`/`gold_snapshot_family`).
- After filling: apply with `Tools/Gold/merge_gold_review.py` (dry-run first).

## Rules

- **Static only.** Open the sample in dnSpyEx or dnSpy. Never execute, load
  as a process, or build it.
- Do not use file names, YARA names, tags or config values as *features*.
  They are evidence for the human verdict only.
- Do not guess. If unsure, use `review` and write why in `notes`.

## Verdict mapping

| Observation | gold_status | gold_family |
|---|---|---|
| AsyncRAT **client** (loader + client config/C2 logic) | `verified` | `AsyncRAT` |
| Another RAT family (DcRat, XWorm, VenomRAT, ...) | `verified_other` | that family |
| AsyncRAT server / builder / stub / plugin / panel | `reference_only` | `AsyncRAT` (or blank) |
| Benign .NET EXE | `benign` | `Benign` only if the vocabulary expects it, else blank |
| No CLR header / not .NET | `rejected_non_dotnet` | blank |
| Cannot decide, or voters contradict | `review` | blank or best guess |

Allowed `gold_status`: `verified`, `verified_other`, `unverified`,
`rejected_non_dotnet`, `rejected_hash_mismatch`, `reference_only`, `review`,
`benign`.

Allowed `gold_family`: `AsyncRAT`, `DcRat`, `NjRAT`, `Remcos`, `QuasarRAT`,
`VenomRAT`, `XWorm`, `XenoRat` (or blank).

## Fixture candidate

One gold row is a **hand-built fixture**: `EchoArgs.exe` (3,584 bytes,
`source=fixture`, `origin=fixture`). It is not a real-world sample. If the
static review confirms it is a benign .NET EXE, record `gold_status=benign`
and put `fixture` in `notes` (or `evidence`). Do not treat its file name or
size as a model feature.

Sample paths in the sheet are resolved by **SHA-256**, not by file name: a
friendly name such as `EchoArgs.exe` is found by hashing the class directories,
and the same hash appearing twice is resolved deterministically
(AsyncRAT > OtherMalwares > Benign) and reported.

## What to fill

- `gold_status` — verdict from the table.
- `gold_family` — required for `verified_other`; optional otherwise.
- `confidence` — `low`, `medium` or `high`.
- `analyst` — your handle.
- `date` — ISO date.
- `notes` — one short line (why, or what is uncertain).
- `evidence` — short pointer: config fields, TypeRef/MemberRef, imports,
  loader behaviour, family strings, rule hit.

Leave `gold_status` blank for rows you have not reviewed yet; the merge tool
preserves them.

## Applying verdicts

```bash
# always dry-run first
python3 Tools/Gold/merge_gold_review.py --dry-run
# then write (only after the pipeline rebuild has finished)
python3 Tools/Gold/merge_gold_review.py --write
```

The tool refuses duplicate/unknown sha256, unknown status/family values, and
never overwrites an already filled `gold_status` unless `--force` is given.

After merging, rerun the importer so `is_gold`/`gold_fam` reflect the audit.
Gold rows stay in `DataSet.db` only and never enter a class DB or a split.

## Refreshing after the pipeline rebuild

After the background rebuild finishes, rerun once:

```bash
python3 Tools/Gold/review_sheet.py
```

This only refreshes the review sheet (including YARAify/DIE cells), which are
read from `Data/Aggregated` and `Data/Evidence`. Do **not** rerun the
aggregator or importer just for this refresh.

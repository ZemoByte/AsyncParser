# Prompt for OpenCode — MalwareBazaar sample downloader (academic training dataset)

This document is an **implementation brief** for OpenCode. It translates a completed design interview into an actionable specification. Implement the tool exactly as described, keeping it small and free of speculative features. The earlier design-interview constraint ("paper project, no code") applied to the planning phase only; this brief is the implementation request.

## 1. Goal and context

- Build a Python automation script that downloads malware samples from the MalwareBazaar Community API.
- Purpose: build an **academic training dataset**. Intended to run in an isolated Linux VM for defensive research.
- The script is **interactive** and does **one tag query per run**: it downloads the available candidates, then stops with a summary. It is normally run **1–2 hours/day**; Ctrl+C can stop it earlier.
- Deliverable: one small Python script. No framework. No features beyond this brief.

## 2. Verified API facts (from https://bazaar.abuse.ch/api/ and /faq/)

- Endpoint: `POST https://mb-api.abuse.ch/api/v1/` with HTTP form data; every request carries the header `Auth-Key`.
- Tag search: `query=get_taginfo`, parameter `tag`, parameter `limit` (default 100, max **1,000**). There is **no pagination/offset, no time filter, and no file-type filter**. Result fields include `sha256_hash`, `file_name`, `file_type`, `first_seen`, `last_seen`, `tags`, `signature`, `file_size`. Possible statuses: `tag_not_found`, `illegal_tag`, `no_tag_provided`, `no_results`.
- Download: `query=get_file`, parameter `sha256_hash`. The response is a **raw binary ZIP** (not base64), AES-128 encrypted, password **`infected`**. Possible statuses: `illegal_sha256_hash`, `no_sha256_hash`, `file_not_found`.
- Extraction: Python's stdlib `zipfile` cannot read AES ZIPs; use **`pyzipper`**.
- Download limit: **2,000 downloads per IP per day**. Community API is free under fair-use principles (academic use is fine); commercial/for-profit use may require a paid API.
- MalwareBazaar explicitly contains **no benign files and no adware/PUA**. Never query benign tags there.
- Ordering: per the user, tag queries return the **latest-seen samples first** (`last_seen`, newest first). The API docs do not state ordering explicitly, so treat this as user-confirmed behavior to verify at runtime.

## 3. Hard constraints

- Never hardcode the Auth-Key; never print or log it.
- **Every** file/folder read, write, or creation must first check whether the path exists, create it if missing, and then continue. This applies everywhere: output folders, DB file, temp folder. The `.env` file is the single exception (see §4).
- Samples are never executed. The operator handles VM containment; do not add extra VM safety rails, disk caps, or AV-exclusion logic.
- Minimal dependencies: standard library wherever possible; exactly one third-party package (`pyzipper`).

## 4. Authentication

- Read `.env` in the script's directory (or the project root). Variable name: `MB_AUTH_KEY`.
- Parse `.env` with the **standard library only** — do not use `python-dotenv`.
- If `.env` is missing: print a clear error and exit; **do not create it** (the deliberate exception to the create-if-missing rule).
- Send the value as the `Auth-Key` header on every API request.

## 5. Interactive flow

On startup, show a 3-option menu:

1. **AsyncRAT** — preset tag `AsyncRAT` (confirmed to exist on MalwareBazaar).
2. **Other Malwares** — prompt the user to enter a tag to search.
3. **Benign** — print `source not configured` and return to the 3-option menu. No downloads. (A benign source will be supplied later; keep the folder and the option.)

Options 1 and 2 continue through a short wizard:

- Prompt for file type(s): **one file type, or several if the user enters a list** (e.g. `exe` or `exe,ps1`). Matching is case-insensitive (`exe`, `EXE`, `Exe`, `eXe` all match).
- Supported types are Windows executable/script formats that can deliver a RAT — at minimum `exe`, `dll`, `ps1`, `bat`, `js`/`javascript`, plus similar Windows executable/script formats. **Reject document files** (`pdf`, `doc`, `docx`, `xls`, etc.) **and Linux files** (`elf`, `sh`, etc.) even if the user enters them.
- Prompt: "Allow downloads of samples with additional tags?" **yes/no**.
  - **No (default):** exactly **one malware tag + one file-type tag**. Accept only samples whose tag set is the searched tag + the selected file type; samples with extra tags (`exe + AsyncRAT + RAT`, `exe + AsyncRAT + CVE-xxxx`) are rejected.
  - **Yes (advanced):** allow **multiple malware tags, but still one file-type tag**. Samples must contain the searched tag and the selected file type; extra malware tags are allowed.
  - If several file types were entered, process them one at a time so each sample still has exactly one file-type tag.
- Prompt for the download rate; default **10 downloads/minute**, adjustable.
- **No sample-count prompt.** The run ends automatically after one pass; Ctrl+C stops it earlier.

## 6. Output layout

The project root is `AsyncParser/`. Resolve all paths from the script's own location (`AsyncParser/Tools/MBDownloader/`) by walking up to that root, so behavior does not depend on the current working directory. Create every path below if it does not exist (per §3):

```
AsyncParser/
├── Samples/
│   ├── AsyncRAT/        # option 1
│   ├── OtherMalwares/   # option 2
│   └── Benign/          # option 3; stays empty until its source is configured
└── Tools/
    └── MBDownloader/
        ├── <downloader script>
        ├── samples.db          # MAIN DB: whole sample dataset + dedup (persistent)
        └── temp/
            ├── <in-progress downloads>
            └── comparison.db   # TEMP DB: per-poll cache + run log (deleted at stop)
```

- Extracted samples go into the three folders under `AsyncParser/Samples/`.
- The **main SQL DB** holds all sample data and persists across runs; it lives under `AsyncParser/Tools/MBDownloader/`.
- The **temporary comparison DB** and in-progress downloads live under `AsyncParser/Tools/MBDownloader/temp/`; the comparison DB is deleted on clean shutdown.

Saved sample name: `<sha256_hash>.<ext>`, where the extension comes from the API's `file_type`. Keep only the extracted sample; delete the downloaded ZIP after successful verification.

## 7. Data model (two separate SQLite DBs)

**Main DB — `AsyncParser/Tools/MBDownloader/samples.db` (persistent, holds all sample data):**

- `downloads` — the whole sample dataset / dedup index: `sha256_hash` as PRIMARY KEY, API `file_name` (metadata only), local filename, tag, file type, `first_seen`, download timestamp, status.
**Temporary comparison DB — `AsyncParser/Tools/MBDownloader/temp/comparison.db` (ephemeral):**

- `session_log` — run log: hash, tag, file type, timestamp, status, error text.
- Per-poll cache of retrieved metadata (hash, tag, file type, `first_seen`) used for client-side filtering and for comparing incoming samples against the main DB.

Created at startup. During the run, incoming sample metadata is written into its per-poll cache and compared against the main DB's `downloads` index; any hash already present there is **ignored — it is not downloaded again**. The whole temporary DB is **deleted at the end of the work**, however the run ends (Ctrl+C, error limit, or daily cap). It is scratch state for the current run only. The main DB is the dedup authority and is never deleted.

## 8. Search and history logic

One tag query per run; there is no polling loop.

Per run:

1. Call `get_taginfo` **once** with the selected tag and `limit=1000`, then filter the cached metadata for each selected file type.
2. Store the returned metadata in the per-poll cache in the temporary comparison DB; filter client-side there: file type first, then the tag rule from the wizard.
3. Using the temporary comparison DB, compare each cached hash against the main DB's persistent `downloads` index. Skip (ignore) every hash already present with status `success` or `adopted` — duplicate samples are not downloaded again.
4. Derive the progress marker from the latest `first_seen` and hash for the same `tag_rule` in `downloads`: **new** = greater than that marker; **backlog** = the rest. Download **new first**, then the **backlog**, breaking ties by `sha256_hash`. No `cursors` table is used.
5. For each chosen sample: if the destination file already exists, adopt it (status `adopted`) when its SHA256 matches its filename, otherwise move it to `Samples/_quarantine` and log the reason; neither case calls the API nor counts as an error. Otherwise record an attempt, call `get_file`, write the ZIP to the temp folder, extract with `pyzipper` (password `infected`), verify integrity, atomically move the sample into the destination folder and insert its success row into `downloads`; append the outcome to `session_log` in the temporary comparison DB.
6. Only the newest 1,000 samples per tag are reachable through the tag API; this limitation is accepted.

## 9. Integrity and file handling

Five values must match: **API `sha256_hash` == downloaded ZIP's filename == name of the file inside the ZIP == hash embedded in the local filename `<sha256>.<ext>` == SHA256 computed from the extracted bytes**. The user confirms MalwareBazaar names both the ZIP and the extracted file with the SHA256; keep this check in place as verification rather than trusting it blindly.

- On a match: delete the ZIP, keep the extracted sample, record success in the main DB.
- On a mismatch or corrupt archive: delete the temp ZIP and any partial extracted file, log the incident, and skip the sample.
- API `file_name` (the original malware filename, e.g. `Jamil Marzouka Co.pdf.jar`) is **stored as metadata only** and is not part of the equality check.
- Always write to a temp file first, then atomically rename into place, so a crash never leaves a partial sample.

## 10. Rate limiting, failures, shutdown

- Default **10 downloads/minute**, adjustable at startup; sleep between downloads.
- Local daily cap: **1,200 get_file attempts** (successful or failed — the API docs do not say whether failed calls count, so the local cap is conservative). Reset on a **rolling 24-hour window**, falling back to UTC midnight if that proves impractical.
- HTTP 429: honor `Retry-After`, apply exponential backoff, and stop if the throttling repeats (see §13).
- Stop the run when **more than 10** errors/corrupt downloads have occurred (i.e. on the 11th).
- Bounded retries: **5 attempts with backoff** for network errors before counting an error.
- On Ctrl+C: finish the current sample, then exit cleanly and delete the temporary comparison DB. The same deletion happens on any other clean end of the run (error limit or daily cap).

## 11. Logging

- No text log file: the run log lives in a **separate temporary comparison DB** under `temp/`, never in the main sample DB. It is created at startup, grows while incoming samples are compared against the samples already on the system and downloaded, and the whole temp DB is deleted at the end of the work, however the run ends. A new run starts with a fresh comparison DB.
- Fields to record: hash, tag, file type, timestamp, status, error text.
- The main DB's persistent `downloads` table — not the run log — is the dedup authority: it is compared against incoming samples on every run and survives across runs.
- Console: a brief progress line per sample. Never log the auth key.
- No dry-run mode.

## 12. Dependencies

- Python 3 standard library for HTTP, `.env` parsing, SQLite, and hashing. Use `urllib.request` for HTTP calls (assumption — see §13).
- `pyzipper` for AES ZIP extraction. From the project root: `python3 -m pip install -r Tools/requirements.txt`.
- No other third-party packages.

## 13. Remaining assumptions and pending input

Chosen defaults, not explicitly confirmed by the user:

- HTTP is done with stdlib `urllib.request` (no `requests`) to honor the minimal-dependency preference.
- The daily local cap default is 1,200 downloads (rolling 24 h reset, UTC midnight fallback).
- HTTP 429 behavior: `Retry-After` + exponential backoff, then stop on repeated throttling.
- Extension mapping for types other than `exe` (e.g. `dll`, `ps1`, `bat`, `js`) follows the API's `file_type` lowercased; unusual or missing values should be logged and skipped.
- Exact boundary of "similar Windows executable/script formats": beyond `exe`, `dll`, `ps1`, `bat`, `js`, it is not defined whether `vbs`, `hta`, `scr`, `msi`, `cmd`, `lnk`, etc. are included. Documents and Linux files are definitely excluded.

Confirmed in follow-up (no longer open): case-insensitive file types; five-way name/hash check; `last_seen` latest-first ordering; one query per run; 5 retries; `AsyncRAT` tag exists; tag rule (default one malware tag + one file-type tag; advanced multiple malware tags + one file-type tag).

Pending from the user: the external site for **Benign** samples. Option 3 stays a placeholder until that source is supplied.

**Comment to place inside the code (instruction only — comment text, no code):** at the logic that relies on `last_seen` ordering and on the ZIP/extracted filenames being SHA256, add a comment recording that the user asserted these are always true and that, if they turn out not to be true, the user said they cannot be true. Keep the verification checks in place regardless.

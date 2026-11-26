# DECISIONS.md — Design interview log (Phase 0: labeling)

Date: 2026-11-26
Source: interview questions Q1–Q73 with the user.
Status: **decisions only — no code written**.

## 1. Labels, not "verified for everyone" (Q1)

- Each sample gets exactly **one `label_status`** from the fixed vocabulary in `Docs/Plan.md` §4: `verified | unverified | rejected_non_dotnet | rejected_hash_mismatch | reference_only | needs_human_review | benign` (`benign` added in §31/Q71).
- `verified` is one value among many. It is not the required outcome for every sample.
- **Unverified samples are kept**, not thrown away.
- Phase 0 goal has two jobs: labels and clusters. 0.1 does labels; clusters come later (0.2).

## 2. Databases (Q2, Q4)

| File | What it holds |
|---|---|
| `Tools/MBDownloader/samples.db` | append-only download ledger — **untouched**, read-only source |
| `Data/DataSet.db` | label index only: SHA-256 → `label_status`, `suggested_family`, `obfuscation_level`, target class DB, parser version, raw parser JSON |
| `Data/AsyncRAT.db` | detailed per-class rows copied from `samples.db` |
| `Data/OtherMalwares.db` | detailed per-class rows copied from `samples.db` |
| `Data/Benign.db` | detailed per-class rows copied from `samples.db` |

- No single mixed database. The three class DBs stay separate.
- Order of work: **label first**, write the status, then copy details into the chosen class DB.
- The class is decided by the label, **not** by the MalwareBazaar tag.

## 3. The `verified` rule (Q5, Q6, Q7)

- ".NET" = static read of the PE file for a CLR/.NET header. **Never** the Bazaar `file_type` text (tags lie).
- Family hint = `yara_possible_family` from `rat_king_parser`, which comes from a **YARA rule match**, not raw config parsing.
- `verified` = CLR/.NET header present **AND** `yara_possible_family` says AsyncRAT.
- Config is stored **only if the parser returns it**. Missing or placeholder config does **not** downgrade a sample.
- Reason: config may be split into mathematical functions and built at runtime, so it cannot be a gate.
- Native binary tagged AsyncRAT → `rejected_non_dotnet`.
- **No raw `strings` over PE bytes** — mostly trash. Only the parser's structured JSON fields are used.

## 4. The parser (Q3, Q9)

- Installed in the user's shell: `rat-king-parser 4.2.4`. `-h` output was pasted and read.
- Output: a JSON list. Each report has `file_path`, `sha256`, `yara_possible_family`, `key`, `salt`, `config`.
- Match samples by `sha256` from the report — **never by filename**.
- One call accepts many paths: `rat-king-parser [-n] file_paths [file_paths ...]`.
- Flags chosen: `-n` (normalize config key names) **on**; `-p` (preserve obfuscated keys) **off** for now. Record version `4.2.4`.
- On parser exception, `config` is a string like `Exception encountered for <path>: <error>` → record parser failure and `unverified`.

## 5. Features and carving (Q6, Q8, Q10, Q12, Q15, Q16, Q18)

- Main focus: **Layer A external references** — import table (`ImplMap` / P/Invoke), TypeRef, MemberRef, AssemblyRef, ImplMap.
- These are system-wide references .NET needs; they survive obfuscation and encryption.
- **Layer B is kept, but Layer A stays primary.** Everything in Layer B and the extra signals is **[TEST]** — kept only if a stability/ablation check shows it helps: class/method signatures, inheritance, interfaces, field types, config-jar shape, byte-array hashes, resource inventory, metadata row order.
- **Class/method names and user strings** go at the **end of Layer B**, experimental only: one switch `own_names=off` by default, never in the main model, only in an ablation. This is an explicit exception to `AGENTS.md` §8; raw user strings are never stored in the DB.
- Avoid analyst-style carvings that depend on how one malware was built.
- Never use `is_dotnet` or any file-format column as a model feature (`AGENTS.md` §8).
- **One carving job per folder**: `Tools/ImportTable/`, `Tools/TypeRef/`, `Tools/MemberRef/`, `Tools/AssemblyRef/`, `Tools/ImplMap/`, with scripts inside each folder. Labeler separate under `Tools/Labeling/`. Each carver reads by SHA-256 and writes one JSON file.
- Carved JSON location: `Data/<Class>/<Tool>/<sha256>.json`, e.g. `Data/AsyncRAT/ImportTable/<sha256>.json`. §20/Q41 supersedes the earlier `Data/Carved/...` wording. Three class folders: `AsyncRAT`, `OtherMalwares`, `Benign`.
- **Label first, then carve into the class folder** (Phase 0: "before any carving").

## 6. File placement (user instruction, after Q10)

- Decisions are written under `Docs/` (this file), **not** `Tools/`.
- `Tools/MBDownloader/bazaar.md` was moved to `Docs/bazaar.md`.
- Short-name map lives in `Docs/SHORT_NAMES.md` (Q17).

## 7. Short names and family disagreement (Q11, Q14, Q17)

- Short, readable lowercase snake_case names are used in the DB. Full map: `Docs/SHORT_NAMES.md`.
- Parser names another family (e.g. DcRat) → do **not** verify as AsyncRAT; write `lbl_sts=review` (needs human review) and `sug_fam=DcRat`. The `hum_rev` flag was dropped in §11.

## 8. Config fields (Q19)

- Store only these parser fields when returned: `hosts`, `ports`, `mutex`, `key`, `salt`. Missing → empty/null. No `strings` on bytes.

## 9. `obfuscation_level` (Q20)

- `plain` = no known obfuscator fingerprint.
- `obfuscated:<Fingerprint>` = known fingerprint intact; name it, e.g. `obfuscated:ConfuserEx`. Naming it lets us revert later.
- `unknown` = parse failed or unclear.
- Never a model feature.

## 10. Obfuscator fingerprints (Q21)

- **Superseded by §30/Q61:** the vocabulary is the 8 cloned repos (BitMono, Codecepticon, Hydra, LoGiC.NET, MindLated, neo-ConfuserEx, obfuscar, Z00bfuscator). The earlier 5-name list is void.
- None found → `plain`; unclear → `unknown`; off-list → `unknown`. Marker detection remains `[TEST]` and unimplemented.

## 11. Label status value (Q22, Q26)

- `hum_rev` flag dropped. `lbl_sts=review` is the canonical short value for `needs_human_review`.
- Family disagreement example: `lbl_sts=review`, `sug_fam=DcRat`.

## 12. Carver JSON output (Q23)

- Shape: `{"sha256": "...", "kind": "<Tool>", "values": ["dll!symbol", ...]}` — sorted unique external references, presence only. For `ImplMap` the symbol is the P/Invoke import name; for `ImportTable` it comes from the PE import directory.
- Counts are **not** in carver JSON. Counts (TypeRefs, MemberRefs, P/Invokes, sections, entropy) stay in a separate group: the "trivial baseline" in `Docs/Plan.md` §6.

## 13. JSON-only tools, one importer (Q25, Q27, Q28, Q29, Q30)

- `Tools/Labeling/labeler.py`: reads `samples.db` by SHA-256, batches paths to `rat_king_parser -n`, checks CLR header statically. Writes `Data/Labels/<sha256>.json` only — never the DB.
- Label JSON fields: `sha256`, `lbl_sts`, `sug_fam`, `is_dotnet`, `obf_lvl`, `parser_version`, `config`.
- Carvers write only `Data/<Class>/<Tool>/<sha256>.json` (§20/Q41).
- `Tools/Importer/importer.py` is the **only** tool allowed to write **any** DB: `DataSet.db` plus the three class DBs (§20/Q41). It reads `Data/Labels/*.json` and `Data/<Class>/<Tool>/*.json`.
- No carver, labeler or writer imports a database module.
- Import runs explicitly after labeling + carving finish; no automatic DB writes during extraction.
- The importer knows the tools finished via `.done` markers next to their JSONs (§23), not by calling their code.

## 14. JSON envelope and auto-added columns (Q31, Q32, Q36)

- Every JSON: `{"schema_version": 1, "sha256": "...", "kind": "label"|"ImportTable"|..., "producer": "...", "fields": {...}}`. The importer reads `fields` generically.
- New fields are added to the DB with **auto-`ALTER TABLE`** (chosen over a generic key-value table).
- Column rules: name = field name from `fields`; type from value — text→`TEXT`, number→`INTEGER`, list/dict→`TEXT` (JSON string); name collision across tools → prefix with `kind` (e.g. `ImportTable_values`).

## 15. Done markers and importer run (Q33, Q37, Q39)

- Each tool writes a `<name>.done` marker **next to its JSONs**: `Data/Labels/.labeler.done`, `Data/<Class>/<Tool>/.done`.
- Importer runs only when all expected markers exist.
- Command: `python3 Tools/Importer/importer.py` — no arguments, no network, no sample execution.

## 16. Label JSON `config` shape (Q34)

- `{"hosts": [...], "ports": [...], "mutex": "...", "key": "...", "salt": "...", "parse_error": "..."}`, or `null` when the parser returns no config.

## 17. Clusters (Q35)

- After labels, before carving: compute clusters (TLSH distance + shared config keys) and store one cluster column in `DataSet.db`.
- Carved JSON folders stay by class, not by cluster.

## 18. Schema mismatch (Q38)

- JSON with `schema_version` higher than the importer supports → exact error, never a silent skip.

## 19. Success check for 0.1 (Q40)

- Synthetic tests only: hand-made label JSON + tiny carved JSONs + a fake PE with a CLR header → importer writes the expected rows. No real samples touched.

## 20. Class DB writer (Q41)

- The importer reads `Data/<Class>/<Tool>/<sha256>.json` outputs and writes all four DBs.
- Earlier §5 wrote `Data/Carved/<Class>/<Tool>/...`; Q41 corrected this to `Data/<Class>/<Tool>/...`. §24 confirms the notation.

## 21. Obfuscator fingerprints (Q43)

- Detection is **[TEST]**. If no static marker can be identified → `unknown`, never a guess.
- Fingerprints to prepare: `ConfuserEx`, `dotFuscator`, `Eazfuscator`, `Obfuscar`, `Agile.NET`. Reference repos supplied by the user; static inspection only, never run or built.

## 22. Missing vs empty vs error (Q44)

Three distinct states, with exact sentinel strings:

| State | Value |
|---|---|
| genuine empty | `null` |
| field absent because JSON `schema_version` is older | `"<schema_absent>"` |
| parser exception | `"<parse_error>"` (plus `config.parse_error` text) |

- Reject unknown values. Confirm sentinel names at build time.

## 23. Done markers (Q45)

- Tools write `.done` only on success. Crash, error, or a re-run that does not finish → no marker → importer blocks.
- Importer deletes each marker after a successful import; the next run must regenerate them.

## 24. Carved path and sentinels (Q46, Q47)

- `Data/<Class>/<Tool>/<sha256>.json` is the same thing as `Data/AsyncRAT/<tool name>/<sha256>.json` — notation only, no change.
- Sentinels locked: `null` = genuine empty, `"<schema_absent>"` = older schema, `"<parse_error>"` = parser exception.

## 25. Row placement, copied fields, errors, family string (Q49–Q52)

- `unverified`, `review`, `rejected_non_dotnet`, `reference_only` → rows in `DataSet.db` only; no class-DB row.
- Copy from `samples.db` into the class-DB row: `tag`, `secondary_tag`, `api_tags`, `tag_rule`, `file_type`, `first_seen`, `downloaded_at`; more fields may be added later.
- Conflicting field types → importer stops with an exact error, never converts.
- The exact AsyncRAT family string emitted by the packaged YARA rule must be **read** before coding and mapped, never guessed.

## 26. User's Phase 0 outline (provided, not designed yet)

- **0.2 Cluster assignment:** TLSH via the `tlsh` package, distance ~100 + shared config keys (mutex, AES key, C2 host), `cluster_id` per sample, before any split. Not started. The clusterer (`Tools/Clustering/clusterer.py`) is agreed as a general-use tool (Q48): it writes JSON and never touches the DB.
- **0.3 Benign .NET collection:** hundreds of benign .NET EXEs; sources = user's machine (Windows .NET folders, installed programs, NuGet compiled from source); never MalwareBazaar. Not started.
- **Requirement (user):** the user will supply the benign PEs. 0.3 cannot proceed until they arrive.
- **Checkpoint:** `DataSet.db` has every sample with `sha256`, `label_status`, `cluster_id`, `is_dotnet`. `is_dotnet` is metadata only — **never** a model feature.

## 27. Ledger scope, DB creation, importer errors (Q53–Q57)

- Only successfully downloaded ledger rows get the parser run. Quarantined / hash-mismatch rows get `rejected_hash_mismatch` without running the parser.
- Importer creates `DataSet.db` and the three class DBs if missing (check → create if absent → read if present), then auto-`ALTER`s columns.
- Importer stops with an exact error on: missing JSON, invalid JSON, unknown `kind`, higher `schema_version`, conflicting field type, missing `.done` marker. No silent skip.
- Planned for 0.2: `Data/Clusters/.clusterer.done` will be required before import. **Not enforced** while clustering is deferred (§26/Q73).
- `is_dotnet` is metadata in `DataSet.db` only — **never** a model feature.

## 28. Status — closed

- Historical: the 0.1 **design** was closed at Q57. Interviewing continued through Q73 during the build (§30–§33).
- 0.2 and 0.3 remain noted in §26, not designed.

## 29. Build tasks recorded (user, 2026-11-27)

- Done markers live next to their JSONs: `Data/<Class>/<Tool>/.done` (corrects §15).
- `Tools/requirements.txt` must contain: `pyzipper`, `rat-king-parser==4.2.4`, `dnfile==0.18.0`, `pefile==2024.8.26`, `tlsh` (version unknown — do not invent one). Added this turn.
- Test folder location for the synthetic tests (Q40) is still undecided.

## 30. Build review decisions (Q58–Q61, 2026-11-27)

- **Q58 — class DB mapping:** §25 stands. `review` → `DataSet.db` only, never a class-DB row. The current `review` → `OtherMalwares.db` branch in `Tools/Importer/importer.py:31-32` violates this and must be removed.
- **Q59 — benign PEs:** the user hand-built benign PEs into `Samples/Benign/` purely for testing. They are not in the MalwareBazaar ledger, so the current labeler/importer ignore them; `Benign.db` stays unreachable until a benign labeling path exists. No automation added for this yet.
- **Q60 — family vocabulary:** fixed mapping from the parser's raw family string → canonical class vocabulary; off-list → `review` with **no** class DB. The case-sensitive `OTHER_RAT_FAMILIES` check in `importer.py:20-21` is not enough.
- **Q61 — obfuscator vocabulary:** use the 8 cloned repos as the set: BitMono, Codecepticon, Hydra, LoGiC.NET, MindLated, neo-ConfuserEx, obfuscar, Z00bfuscator. Drop dotFuscator, Eazfuscator and Agile.NET (no evidence). `obf_lvl` stays `unknown` until markers are derived from the repos by static reading.
- Ledger state: 170 rows, all `status=success`; 180 `.exe` files on disk. A real end-to-end run therefore needs all 170 labels, not a 3-sample label batch, or the importer stops on missing label JSONs.

## 31. Fix-queue decisions (Q71–Q73, 2026-11-27)

- **Q71 — benign label status:** add `benign` to the `label_status` vocabulary. Benign .NET files get `lbl_sts=benign` + `sug_fam=Benign` → `Benign.db`. **Never** reuse `verified`: `verified` still means ".NET + parser reports AsyncRAT" (§3). The review's proposal to mark benign as `verified` was rejected.
- **Q72 — done-marker correctness:** `write_marker` in all five carvers must run **after** the sample loop. Writing it inside the loop lets a crashed run leave a valid `.done`, so the importer would accept partial carving data. Severity: **HIGH**, not LOW.
- **Q73 — sequencing:** no 0.2 clustering design interview now. 0.2 stays deferred while the Q71/Q72 fixes land.
- Advisor judgement on the review: #1 (review router) correct; #2 rejected as above; #10 is **not** a typo — the whole `OTHER_RAT_FAMILIES` routing branch must be removed per Q58, and canonical values are `DcRat, NjRAT, Remcos, VenomRAT, XWorm, QuasarRAT, XenoRat, OtherMalware`; #3 sample index must be keyed by SHA-256 only; #7 read `rat-king-parser --version` at runtime.
- Observed DB state **before** these fixes (read-only check): 170 rows — 48 `verified`, 76 `unverified`, 31 `rejected_non_dotnet`, 15 `review`; all 15 review rows had `target_class_db=OtherMalwares.db` and lowercase raw `sug_fam`; no carved JSONs existed, so no capability columns were imported. These are in the user's fix queue.

## 33. Fix queue and rerun — resolved (2026-11-27)

- Earlier state: `labeler.py` wrote `lbl_sts=unverified` for benign files; `importer.py` routed any `sug_fam=Benign` to `Benign.db` without checking `lbl_sts`.
- **Applied fixes:** `labeler.py` benign branch now writes `status = "benign" if is_net else "rejected_non_dotnet"` with `suggested_family = "Benign"` (`labeler.py:221-222`); `importer.py` routes to `Benign.db` only when `status == "benign" and suggested == "Benign"` (`importer.py:50-51`).
- Rerun performed in order: labeler (`--samples-root Samples --benign-root Samples/Benign`), five carvers, importer.
- **Verified after rerun (read-only):** `DataSet.db` 180 rows — 48 `verified`, 76 `unverified`, 31 `rejected_non_dotnet`, 15 `review`, 10 `benign`; `AsyncRAT.db` 48 rows; `Benign.db` 10 rows; `OtherMalwares.db` absent (no verified non-AsyncRAT label); all 15 review rows have `target_class_db=NULL`; all five carving columns present in all DBs; 0 `.done` markers left.
- Carving now complete: 134 / 5 / 10 JSONs per tool in `AsyncRAT` / `OtherMalwares` / `Benign` for each of the five carvers.
- Phase 0.1 is satisfied. Deferred by agreement: the full obfuscator fingerprint set (two markers implemented in §34; no matches in current data, so `obf_lvl=unknown`), clusters / `cluster_id`, splits, models, live downloader paths.

## 34. Fingerprint detection fix and state (2026-11-27)

- `detect_obfuscator()` in `Tools/Labeling/labeler.py` now correctly navigates `CustomAttribute` → `MemberRefRow` → `Class.row` → `TypeRef/TypeDef` to read the attribute type name. Previously it read `target.TypeName` which does not exist on `MemberRefRow`, so attribute type names were never collected.
- Scanned all 180 samples: no `ConfusedByAttribute` or `LoGiCdotNetAttribute` found. All 180 rows correctly remain `obf_lvl=unknown`.
- `obf_lvl` detection is now functional; future samples with these markers will be labeled `obfuscated:ConfuserEx` or `obfuscated:LoGiC.NET`.
- Test path fix: `/tmp/opencode/test_mb.py` line 237 updated from `REPO / "Tools/MBDownloader/bazaar.md"` to `REPO / "Docs/bazaar.md"`. All 12 downloader tests now pass.
- Outstanding: human review of 15 review rows, true live MalwareBazaar calls, clustering / `cluster_id` (tlsh not installed).

## 35. Network assumption correction (2026-11-27)

- Earlier "no network" statements were inherited from `AGENTS.md` §9 ("Assume everything runs in an isolated VM with no network and no shared folders"), **not** a measured result from this session.
- Network availability has not been tested by the assistant here, so live MalwareBazaar calls remain **untested**, not proven impossible.
- A live call uses `MB_AUTH_KEY` and may download samples; it requires explicit user authorization. Never print or log the key.
- **Decision (user, 2026-11-27): live MalwareBazaar calls are AUTHORIZED.** The user confirmed network is available inside the VM and explicitly authorizes a real API run, overriding the `AGENTS.md` §9 isolation assumption for this action.
- The 429, cap, error-limit, single-pass and Ctrl+C paths are already covered by synthetic mocked-API tests (12/12 downloader tests pass). A live call would additionally prove connectivity and API compatibility.
- Status: **authorized, not yet executed.** The user accepts that real samples may be downloaded into `Samples/`. Supply `MB_AUTH_KEY` securely; never print or log it.

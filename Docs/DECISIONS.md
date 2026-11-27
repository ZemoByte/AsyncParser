# DECISIONS.md — Design interview log (Phase 0: labeling)

Date: 2026-11-26
Source: interview questions Q1–Q73 with the user.
Status: **decisions only — no code written**.

## 1. Labels, not "verified for everyone" (Q1)

- Each sample gets exactly **one `label_status`** from the fixed vocabulary in `Docs/Plan.md` §4: `verified | verified_other | unverified | rejected_non_dotnet | rejected_hash_mismatch | reference_only | needs_human_review | benign` (`benign` added in §31/Q71; `verified_other` added in §36/Q77).
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
- **Superseded for the final label by §36/Q76:** `rat_king_parser` is now one voter, not the only decision maker. `verified` needs ≥2 independent agreements. The §3 rule remains the parser voter's own status.

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
- Command: `python3 Tools/Importer/importer.py` — no arguments; the importer does not access the network and does not execute samples.

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

## 35. Environment and network (2026-11-27)

- The working environment is a **Fedora VM**. Windows PE/.NET samples cannot execute on Linux, so "run the sample" is not a realistic risk on this machine.
- The safety rule is still **static-only**: never execute, load, import, or build a sample or any builder/server/stub component (`AGENTS.md` §9). The OS being unable to run a PE is not a licence to try.
- Network access is available. Live MalwareBazaar/YARAify/Malpedia calls are allowed when the user authorizes them. Never print or log an API key.
- **Decision (user, 2026-11-27): live MalwareBazaar calls are AUTHORIZED.** Real samples may be downloaded into `Samples/`. Supply `MB_AUTH_KEY` securely.
- The 429, cap, error-limit, single-pass and Ctrl+C paths are covered by synthetic mocked-API tests (12/12 downloader tests pass). A live call would additionally prove connectivity and API compatibility.
- Status: **authorized, not yet executed.**

## 36. Label evidence redesign (2026-11-27)

Source: user proposal (independent voters, `label_evidence`, aggregator, gold set) plus a read-only check of the actual tools, rule sets and source defaults. Applies to `Docs/Plan.md` §4, `Docs/TO-DO.md` 0.4 and the importer.

### Q74 — Independence rule (label vs feature)

- A voter must not be a model feature. Anything used to decide a label is removed from the feature matrix.
- `is_dotnet` is the exception: metadata-only, never a feature, and the first gate.
- **Consequence:** PE/.NET metadata (TypeRef, MemberRef, AssemblyRef, ImplMap) and TLSH-to-reference **cannot** be label voters. The proposal listed both; they are excluded here to avoid label leakage. YARA strings, config/default-value checks and MalwareBazaar metadata are safe because they are not in Layer A.
- Independence is counted by `independence_group`, not by rule file. Two rules from the same upstream repo count once. Own YARA must be authored from the AsyncRAT source/builder, not copied from rat-king-parser or Elastic.

### Q75 — `label_evidence` schema

Proposed columns: `sha256, source, source_version, verdict, strength, raw`. Added:

- `independence_group` — the aggregator counts distinct groups, not rows. Without it, Elastic + a copied Elastic rule would count as two votes.
- `observed_at` — ISO-8601 UTC; makes a stale lookup visible.

Table lives in `Data/DataSet.db`. `raw` is a JSON summary (rule name, matched strings, API fields), capped at about 8 KB; never sample bytes. One row per `(sha256, source, source_version)`. Voters write `Data/Evidence/<sha256>/<source>.json`; the importer remains the only DB writer.

### Q76 — Aggregator

- No CLR header → `rejected_non_dotnet`, regardless of votes.
- No match from a voter = **abstain**, never a contradiction.
- `verified` = CLR + ≥2 independent `strong`/`medium` AsyncRAT agreements + no contradiction.
- `verified_other` = the same rule for a canonical non-AsyncRAT family.
- `review` = contradiction (different known families, or family vs benign). Default counts `medium`/`strong`; `contradiction_min_strength=weak` gives the strict "any contradiction" rule. Recommended default: `medium`, otherwise noisy MB tags flood the queue.
- `unverified` = one `strong`/`medium` voter, weak voters only, or none.
- `benign` stays hand-supplied until benign voters exist.
- `reference_only` overrides everything for the reference archive.
- A human gold label overrides the aggregator and sets `label_source=human_gold`.

### Q77 — `verified_other` promotion path

- This closes the HIGH finding in `Docs/DECISIONS_PART2.md` (no hard negatives).
- `verified_other` rows go to `OtherMalwares.db` with a canonical `sug_fam`; `verified` stays AsyncRAT-only.
- `target_class_db()` in `Tools/Importer/importer.py` must add: `verified_other` → `OtherMalwares.db`.
- `FAMILY_MAP` already covers `asyncrat, dcrat, njrat, remcos, quasarrat, venomrat, xworm, xenorat`. A `verified_other` row without a canonical family is an error, not a silent skip.
- Prefer ≥2 `strong` votes for `verified_other`; one strong + human confirmation is also acceptable. Weak-only agreement stays `review`.

### Q78 — Gold set

- About 30 samples, selected by **cluster**, stratified across `verified`, `review`, `unverified`, `benign`, `rejected_non_dotnet`. Freeze the SHA-256 list before labeling.
- Storage: `Data/Gold/gold.csv` plus `.gold.done`; columns `sha256, gold_family, gold_status, confidence, analyst, date, notes, evidence`.
- Importer adds `is_gold` and `gold_family`. Gold rows stay in `DataSet.db` only and are excluded from every split and from the class DBs.
- Audit per voter: coverage, precision, recall, F1, contradiction rate, and `obf_lvl` agreement with the human label. Report in `Docs/results.md`.
- Do not tune the aggregator on the same gold set used for the final audit. Either freeze the aggregator before labeling, or split gold into dev/test (15/15 is small; report uncertainty).

### Q79 — Research findings (exact names and fields)

**rat-king-parser 4.2.4**
- Rules: `asyncrat`, `dcrat`, `quasarrat`, `xenorat`, `xworm`, `venomrat`.
- AsyncRAT condition: `(not any of ($dcrat*)) and 6 of them and #patt_config >= 10`. Strings include `AsyncClient`, `masterKey can not be null or empty`, `schtasks /create /f /sc onlogon /rl highest`.
- A positive is strong. A no-match is abstention because the rule is conservative. 60/180 samples currently fail config parsing with `Could not identify config: No valid configuration could be parsed from any .cctor methods`; 2 with `No .cctor method could be found`. Do not treat those as negative votes.

**Elastic protections-artifacts**
- `yara/rules/Windows_Trojan_Asyncrat.yar` → rule `Windows_Trojan_Asyncrat_11a11ba1`, id `11a11ba1-c178-4415-9c09-45030b500f50`, fingerprint `715ede969076cd413cebdfcf0cdda44e3a6feb5343558f18e656f740883b41b8`, 2021-08-05. Strings `$a1..$a6` include `/c schtasks /create /f /sc onlogon /rl highest /tn "`, `Stub.exe`, `get_ActivatePong`, `vmware`, the reversed `Software\Microsoft\Windows\CurrentVersion\Run`, `get_SslClient`; condition `all of them`.
- Family files: `Windows_Trojan_DCRat_1aeea1ac`, `Windows_Trojan_XWorm_732e6c12`, `_b7d6eaa8`, `_7078e1c8`, `Windows_Trojan_Quasarrat_e52df647`.
- License: Elastic License 2.0. Local use is allowed; do not redistribute as a hosted service; keep notices.

**signature-base**
- Tree scan found **no AsyncRAT-specific rule**: no `asyncrat` path and no AsyncRAT rule in `gen_rats_malwareconfig.yar`. It does have `apt_quasar_rat.yar` and `crime_cn_campaign_njrat.yar`.
- Do not count it as an AsyncRAT voter until a rule is found. License: Detection Rule License 1.1.

**Malpedia**
- `/api/find/family/<needle>` (no auth) returns: `win.asyncrat`, `win.dcrat` (alt DarkCrystal RAT), `win.xworm`, `win.quasar_rat` (alt CinaRAT, QuasarRAT, Yggdrasil), `win.venom` (Venom RAT), `win.njrat` (alt Bladabindi, Lime-Worm), `win.remcos` (alt RemcosRAT, Remvio, Socmer), `win.xenorat`.
- `/api/get/yara/<family_id>` (no auth for white TLP) returns, for `win.asyncrat`, `win.asyncrat_auto.yar` / rule `win_asyncrat_auto` (YARA-Signator, 2020-10-14, CC BY-SA 4.0). `win.venom` returns `{}` (no white rules). Registration gives green/amber rules.
- Use the rules locally; store rule name/version/date. Do not bundle CC BY-SA rules without complying.

**YARAify**
- Auth-Key required. `POST https://yaraify-api.abuse.ch/api/v1/` with `{"query":"lookup_hash","search_term":"<sha256>"}`. Response has `tasks[].rule_name`, `tasks[].description` and hashes.
- Family-specific rule names are medium; generic matches are weak. `get_tlsh`/`get_imphash` are similarity, not family; do not use them as label votes. License varies per rule; store only the verdict.

**MalwareBazaar metadata**
- Fields: `signature` (family), `tags`, `vendor_intel` (ANY.RUN, CAPE, CERT-PL, vxCube, DocGuard, ReversingLabs), `intelligence.clamav`, `code_sign.subject_cn`, `imphash`, `tlsh`, `gimphash`, `file_type`, `first_seen`, `last_seen`, `reporter`, `origin_country`, `delivery_method`, `comments`.
- Use `signature` (medium), `tags`/`vendor_intel`/ClamAV (weak). Never `file_type`. Never `tlsh`/`imphash` as a family vote (TLSH is a model feature; imphash is similarity). `signature` and tags share one uploader, so one `metadata:mb` group.
- **Live DB gap:** `Tools/MBDownloader/samples.db` has 13 columns and no `signature`; `api_tags` is empty for all 170 rows. The code defines the column but the live DB predates the migration. Rerun the downloader schema migration or `ALTER` before the voter.

**Detect It Easy**
- CLI: `diec -j -d -e <file>` (`-j` JSON, `-d` deep, `-e` entropy). Avoid `-u` (heuristic false positives).
- JSON shape: `{"records":[{"fileType","filePart","type","name","version","info"}],"errors":[...]}`.
- `type` values include `.NET obfuscator`, `Protector`, `Packer`, `.NET compressor`, `Compiler`.
- Signatures exist for `db/PE/protector_Confuser.2.sg`, `protector_Dotfuscator.2.sg`, `protector_Eazfuscator.2.sg`, `protector_Agile.2.sg`, `protector_BitMono.2.sg`, `protector_LoGiC.NET.2.sg`, `protector_Obfuscar.2.sg`, `protector_Smart_Assembly.2.sg`, `protector_NetReactor.2.sg`.
- Map any `.NET obfuscator`/`Protector`/`Packer` record to `obfuscated:<name>`. A clean scan → `plain` (means "no known fingerprint", not proof). Scan error → `unknown`.
- DIE is **not installed**. Reference guide version: `die 3.10`; read `diec --version` at runtime.
- capa v4+ supports .NET (`capa -f dotnet -j <file>`, `--backend dotnet`), but it is optional and not installed. Keep it out of labeling: capa rules overlap with the capability features.

**AsyncRAT source defaults (reference-only, never build)**
- Client `Settings.cs` placeholders: `%Ports%`, `%Hosts%`, `%Version%`, `%Install%`, `%Folder%`, `%File%`, `%Key%`, `%MTX%`, `%Certificate%`, `%Serversignature%`, `%Anti%`, `%Pastebin%`, `%BDOS%`, `%Delay%`, `%Group%`.
- Debug build: `Ports=6606`, `Hosts=127.0.0.1`, `Version=0.5.7B`, `Key=NYAN CAT`, `MTX=%MTX%`.
- Default ports in `FormPorts.cs`: `6606`, `7707`, `8808`.
- Mutex: `FormBuilder.cs` generates a random 12-char string when empty (`Helper.Methods.GetRandomString(12)`). **No fixed mutex prefix.** `%MTX%` is the only stable marker.
- Certificate: `CreateCertificateAuthority(caName, 4096)`, CN is user-supplied; `ServerCertificate.p12` is server-side. **No fixed cert subject.** Do not use cert subject as a default-value check.
- Server version string: `AsyncRAT 0.5.8`.
- Stable client strings for own YARA: `masterKey can not be null or empty`, `AsyncClient`, `get_ActivatePong`, `get_SslClient`, `schtasks /create /f /sc onlogon /rl highest`, reversed `Software\Microsoft\Windows\CurrentVersion\Run`, `NYAN CAT`. Avoid AssemblyRef/TypeRef/MemberRef (model features).

**AVClass**
- `malicialab/avclass` `default.tagging` has `quasarrat → quasar`, `njrat → bladabindi`, `rescoms → remcos`, and `xworm → loveletter` (wrong for our purpose). `default.taxonomy` has `FAM:asyncrat`, `FAM:dcrat`, `FAM:quasar`, `FAM:remcos`.
- AVClass is built for AV-label normalization and does not cover all RATs. Do not use `xworm → loveletter`. Build the alias table from Malpedia `common_name`/`alt_names` plus the rat-king family strings, and map to the fixed vocabulary in `Docs/Plan.md` §4.

### Q80 — Starting voters and suggested order

- The proposal says three voters: own YARA, MalwareBazaar metadata, DIE. DIE is an **attribute** voter, not a family voter, so it cannot count toward the ≥2 family agreements.
- Recommended starting set: **four** voters — rat-king-parser (already implemented), own YARA, MalwareBazaar metadata, DIE. Without rat-king-parser the first run will produce almost no `verified` rows.
- Build order: (1) fix the MB ledger `signature` column; (2) own YARA rules from the source strings; (3) DIE `obf_lvl`; (4) aggregator + `label_evidence`; (5) gold set; (6) Elastic/Malpedia/YARAify voters.
- Keep the first run conservative: `verified` only on ≥2 `strong`/`medium` agreements; `verified_other` only with a canonical family; everything else stays `unverified`/`review`.

## 37. Phase 0.4 offline core — implementation decisions (2026-11-27)

Scope: evidence contract, rat-king voter, own-YARA voter, aggregator, importer
routing, tests, real-data run, docs. No MalwareBazaar voter, no DIE, no
Elastic/Malpedia/YARAify voter, no gold set, no carver/feature/vocabulary
changes, no model code, no commits.

### Q81 — Evidence contract

- Path: `Data/Evidence/<sha256>/<source>.json`.
- Envelope: `{"schema_version":1,"sha256","kind":"evidence","producer","fields"}`.
- `fields`: `source`, `source_version`, `independence_group`, `verdict`,
  `strength`, `raw`, `observed_at`.
- `verdict` is a canonical family or `no_match`; `strength` is
  `strong|medium|weak`; `raw` is a JSON summary capped at about 8 KB and never
  contains sample bytes.
- Done markers: `Data/Evidence/.rat_king_parser.done` and
  `Data/Evidence/.own_yara.done`. The importer refuses to run without them.
- The aggregator writes `Data/Aggregated/<sha256>.json` (kind `aggregate`) and
  `Data/Aggregated/.aggregator.done`; the importer requires that marker too.

### Q82 — rat-king voter

- The labeler keeps its `Data/Labels/*.json` output byte-identical.
- It additionally writes one `rat_king_parser` evidence file per target:
  group `yara:rat-king`, strength `strong`, `source_version` = parser version.
- The parser family is canonicalised through `Tools/_label_common.py`
  (`canonical_family`); the map was moved there so the labeler, aggregator,
  clusterer and importer share one copy.
- `no_match` for empty/`No match`; parser error text is truncated to 1000
  chars in `raw.config_error`; `raw.config_present` records whether a config
  dict was returned.
- Hand-supplied benign samples are not parsed; their rat-king evidence is
  `no_match` with `raw.reason=benign_not_parsed`. Non-.NET samples use
  `raw.reason=not_dotnet`.
- No duplicate `is_dotnet` implementation was added.

### Q83 — Own-YARA voter

- Source: `Reference/AsyncRAT-C-Sharp/`, commit
  `0f0cba4ec3985c38082c6abb3e1e01895120ffb6`, read as text only.
- `Reference/` is gitignored; the user authorised the source download. The
  main vx-underground page is Cloudflare-protected (403); the mirror
  `mirrors.gpmidi.net/vx-underground/Builders/AsyncRAT/` was used to save the
  version READMEs. Builder `.7z` archives are listed in
  `Reference/README.md` but were **not** downloaded (they are builder binaries,
  not source).
- Rule: `Tools/Voters/OwnYara/asyncrat_own.yar`, 13 client strings, condition
  `uint16(0) == 0x5A4D and 4 of them`, `wide ascii`.
- Rejected strings and reasons are in `Tools/Voters/OwnYara/README.md`:
  rat-king/Elastic overlaps, unconfigured-stub placeholders, DEBUG-only
  defaults, ImplMap names, type-name strings.
- `yara-python 4.5.4` is installed; no CLI wrapper was needed. The rule was
  compiled and matched against a synthetic file before the real run.
- The rule is a **lineage** detector: it also hits AsyncRAT-derived forks
  (XWorm, DcRat, VenomRAT, QuasarRAT). Those become contradictions against the
  rat-king family, not automatic AsyncRAT labels.

### Q84 — Aggregator

- `Tools/Aggregator/aggregator.py` implements Plan.md §4 rules 1-10.
- Independence is counted by distinct `independence_group`, not by evidence
  row. Two rules in the same group count once.
- `no_match` is abstention; it never contradicts.
- `contradiction_min_strength` defaults to `medium`; `weak` gives the strict
  any-contradiction rule. A weak disagreement is recorded in `lbl_reason` but
  does not override two strong groups.
- On an AsyncRAT-vs-fork contradiction, `sug_fam` is set to the **non-AsyncRAT**
  family. This keeps the clusterer from merging XWorm/DcRat/VenomRAT forks back
  into the AsyncRAT partition. `lbl_sts` is still `review`.
- Benign rows pass through with `lbl_src=hand_benign`; `reference_only` passes
  through with `lbl_src=parser_only`.
- Gold override (rule 10) is a stub: no gold file exists, so the aggregator
  does not read or apply one.
- `lbl_reason` contains `votes`, `groups`, `contradictions`, `abstentions`,
  `evidence_count`, and `contradiction_min_strength`.

### Q85 — Shared final label and importer

- `Tools/_label_common.py` holds the family map and `load_final_label`.
- `load_final_label` merges `Data/Aggregated/<sha>.json` over
  `Data/Labels/<sha>.json`, so `is_dotnet`, `config` and `obf_lvl` survive.
- The clusterer reads the final label through this loader; the importer does
  the same.
- Importer `label_evidence` table:
  `sha256, source, source_version, independence_group, verdict, strength, raw, observed_at`,
  primary key `(sha256, source, source_version)`, `INSERT OR REPLACE` upsert.
- Importer adds `lbl_src`, `lbl_reason`, `is_gold` (0), `gold_fam` (NULL).
- `target_class_db`: `verified_other` routes to `OtherMalwares.db`; a
  `verified_other` row without a canonical family raises an error.
- Empty class folders are skipped in `collect_markers`, so an empty
  `Data/OtherMalwares` cannot block the importer.
- Importer reruns now preserve existing `split` values instead of writing
  NULL. This fixes the latent split-wipe found earlier.

### Q86 — Tests

- `tests/run_tests.py` is the one command. 25 tests pass.
- Coverage: aggregator rules 1-10, abstention vs contradiction, weak-vs-strong
  contradiction threshold, independence counting, `verified_other` routing,
  no-family error, evidence upsert idempotency, marker requirement, empty class
  folder skip, final-label merge, clusterer family read, own-YARA 4-of-13
  threshold and benign-like non-match.
- No tests existed in `/tmp/opencode` to copy (only a snapshot helper).

### Q87 — Real-data run (2026-11-27)

Before (45 clusters, previous labels):

| lbl_sts | count |
|---|---:|
| verified | 48 |
| unverified | 76 |
| rejected_non_dotnet | 31 |
| review | 15 |
| benign | 10 |

After:

| lbl_sts | count |
|---|---:|
| verified | 48 |
| unverified | 78 |
| rejected_non_dotnet | 31 |
| review | 13 |
| benign | 10 |

- `sug_fam` after: 146 none, 10 Benign, 9 XWorm, 9 AsyncRAT, 3 QuasarRAT,
  2 DcRat, 1 VenomRAT.
- Clusters containing at least one `verified` AsyncRAT: **2 of 45 before and
  after**. The new voters confirm the existing 48 but do not add a second
  independent voter for the 9 own-YARA-only AsyncRAT samples, so cluster
  coverage does not improve.
- `verified_other`: **0**. `OtherMalwares.db` is absent. Only one family voter
  (rat-king) exists for non-AsyncRAT families; a second family-specific voter
  (Malpedia/Elastic) is needed before promotion.
- 13 contradictions, all AsyncRAT vs fork: 9 XWorm, 2 DcRat, 1 VenomRAT,
  1 QuasarRAT. The 2 QuasarRAT samples not hit by own YARA became `unverified`
  with `sug_fam=QuasarRAT`.
- Own YARA: 0 benign hits; 3 `rejected_non_dotnet` raw matches (7-8 wide
  AsyncRAT strings, no CLR header; rule 1 rejects them).
- `label_evidence`: 360 rows (180 rat-king + 180 own-YARA), 0 raw values over
  717 bytes. `lbl_src`: 170 `auto_aggregator`, 10 `hand_benign`.
- Data-loss check: `samples.db` hash unchanged; 180 label JSONs byte-identical;
  `DataSet.db` 180 rows, 0 NULL `cluster_id`; `AsyncRAT.db` 48; `Benign.db` 10;
  no missing/extra samples; 45 clusters, 14 multi-member, 0 mixed-family.

### Q88 — Deviations and open items

- The source download was a deliberate, user-authorised deviation from the
  original "no network" wording. The source is reference-only and gitignored.
- MalwareBazaar metadata, DIE, Elastic/Malpedia/YARAify voters and the gold set
  are not implemented; they remain in `Docs/TO-DO.md` 0.4.
- `verified_other` routing is implemented and tested, but no real row exists
  because the second family voter is out of scope.
- The own-YARA rule is a lineage detector. It is independent in rule strings
  from rat-king/Elastic, but not independent in the statistical sense for
  forks; that is why contradicting forks stay in `review`.

## 38. Remaining voters, lineage scope, gold set and real promotion (2026-11-27)

Scope: MalwareBazaar, Detect It Easy, Elastic, Malpedia, YARAify voters; the
gold-set workflow; real `verified_other` promotion; no commits.

### Q89 — Voters built and run

- **Elastic**: `Reference/Elastic/rules/` (gitignored), rules
  `Windows_Trojan_Asyncrat_11a11ba1`, `Windows_Trojan_DCRat_1aeea1ac`,
  `Windows_Trojan_XWorm_*`, `Windows_Trojan_Quasarrat_e52df647`. 48/180 hits.
  Elastic License 2.0, local use only.
- **Malpedia**: white-TLP rules from `/api/get/yara/<family_id>` under
  `Reference/Malpedia/rules/` (gitignored). Families with white rules:
  `win.asyncrat`, `win.dcrat`, `win.xworm`, `win.quasar_rat`, `win.njrat`,
  `win.remcos`, `win.xenorat`; `win.venom` has none. 71/180 hits.
- **MalwareBazaar**: reads the ledger read-only. `signature` is used as medium
  when present, otherwise `tag`/`secondary_tag`/`api_tags` are weak. The live
  ledger has no `signature`, so this run is weak-only: 165/180 hits. Optional
  per-sample cache and API paths exist; no live API call was made.
- **Detect It Easy**: `Tools/Voters/DIE/die_voter.py`. `diec` is not installed,
  so all 180 samples are `no_match` with `raw.reason=diec_not_installed` and
  `raw.obf_lvl=unknown`. The importer already knows how to read
  `raw.obf_lvl` from this evidence and override `obf_lvl` when `diec` exists.
- **YARAify**: `Tools/Voters/YARAify/yaraify_voter.py`. `YARAIFY_AUTH_KEY` is
  not set, so all 180 are `no_match` with `raw.reason=auth_key_missing`. The
  `lookup_hash` client is implemented for later use.
- The aggregator and importer now require seven sources:
  `rat_king_parser, own_yara, elastic, malpedia, malwarebazaar,
  detect_it_easy, yaraify`.

### Q90 — Lineage scope (important)

- `own_yara`, `elastic`, `malpedia`, `malwarebazaar` and `yaraify` set
  `raw.scope="lineage"` when their verdict is AsyncRAT. Their AsyncRAT rules
  also hit AsyncRAT-derived forks.
- `rat_king_parser` AsyncRAT remains `scope="family"`.
- Lineage AsyncRAT counts toward `verified` but is **not** a contradiction
  against a family-specific fork vote.
- `verified_other` requires two **family-scoped** groups for the fork.
- Contradictions and review `sug_fam` use family-scoped groups only, so a
  DcRat/VenomRAT conflict is not labelled AsyncRAT.
- This is why the 9 XWorm rows promoted and `review` fell from 13 to 1.

### Q91 — Gold set

- `Tools/Gold/build_gold_set.py` selects one sample per cluster, stratified by
  `lbl_sts`, and writes `Data/Gold/gold.csv` with human fields blank.
- Real selection: 30 samples from 30 distinct clusters — 3 verified,
  1 review, 1 verified_other, 18 unverified, 1 benign, 6 rejected_non_dotnet.
- `is_gold=1` excludes a row from every class DB. The importer deletes stale
  gold rows from the class DBs after an earlier import. Verified after the
  run: `AsyncRAT.db` 55 (was 58), `OtherMalwares.db` 8 (was 9), `Benign.db` 9
  (was 10), 0 gold overlap.
- `gold_fam` is NULL until a human fills the CSV. The aggregator applies rule
  10 (`lbl_src=human_gold`) only when `gold_status` is non-empty.
- No sample was hand-labeled in dnSpyEx in this run; the template and checklist
  are in `Tools/Gold/README.md`.

### Q92 — Real run results

Before (Phase 0.4): 48 verified, 78 unverified, 31 rejected_non_dotnet,
13 review, 10 benign; 2 of 45 clusters had a verified AsyncRAT.

After the remaining voters:

| label | count |
|---|---:|
| verified | 58 |
| verified_other | 9 (all XWorm) |
| unverified | 71 |
| rejected_non_dotnet | 31 |
| review | 1 |
| benign | 10 |

- `sug_fam`: 155 empty, 10 Benign, 9 XWorm, 3 DcRat, 2 QuasarRAT, 1 AsyncRAT.
- Clusters: 45, 14 multi-member, 0 mixed-family.
- Clusters containing ≥1 verified AsyncRAT: **3 of 45** (was 2).
- `OtherMalwares.db`: **9 rows** before gold exclusion, **8** after; carved
  columns present (`ImportTable_values`, `TypeRef_values`, `MemberRef_values`,
  `AssemblyRef_values`, `ImplMap_values`).
- The one remaining review is
  `10102a03f784`: Elastic DcRat strong vs rat-king VenomRAT strong. This is a
  real family disagreement, not a lineage artefact.
- DcRat (2) and QuasarRAT (2) remain `unverified` because only rat-king votes
  for them; Elastic/Malpedia did not provide a second family-scoped group.
- `obf_lvl` remains `unknown` for all 180 because `diec` is not installed.
- `label_evidence`: 1260 rows (7 × 180), max `raw` 1246 bytes.
- Gold: 30 rows, `is_gold=1`, `gold_fam` NULL, 0 class-DB overlap.
- Data-loss check: 180 labels byte-identical, all 15 carved directories
  byte-identical, `samples.db` hash unchanged, `DataSet.db` 180 rows / 0 NULL
  clusters.

### Q93 — Deviations and open items

- The Ultimate-Rat-Collection AsyncRAT builder `.7z` archives
  (<https://github.com/Cy-Shadow/Ultimate-Rat-Collection/tree/main/AsyncRAT>)
  were downloaded to `Reference/Ultimate-Rat-Collection/AsyncRAT/` (gitignored,
  not extracted, not run). The client **source** is still
  `NYAN-x-CAT/AsyncRAT-C-Sharp` at `0f0cba4`; the collection contains builder
  archives, not source.
- `diec`, `YARAIFY_AUTH_KEY` and the MalwareBazaar `signature` column are the
  three external gaps. `obf_lvl` enrichment and MB medium evidence cannot be
  demonstrated until they exist.
- Gold rows are not hand-labeled; the audit precision/recall table is pending.
- No commits.

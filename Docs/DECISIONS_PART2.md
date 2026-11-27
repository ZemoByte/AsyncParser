# DECISIONS_PART2.md — Step 0.2: Clustering

Status: **clustering implemented (2026-11-27); label-evidence follow-up pending.**
All decisions made in the interview are appended here; the implementation summary is at the end.

## Context

Phase 0's checkpoint lacks `cluster_id`. Every later step — vocabulary, splits, models — depends on clusters. The 15-row human review can wait; it does not block the pipeline.

Follow `AGENTS.md` strictly: no commits, surgical changes, simplicity first, goal-driven execution.

## Plan with verifiable checks

### 1. Verify `tlsh` is installable / importable

- **Action:** confirm `py-tlsh` can be imported and used.
- **Check:** compute TLSH on one sample successfully.
- **Safeguard:** log a warning if a file is smaller than 256 bytes (TLSH minimum) so failures are not silent.

### 2. Design `Tools/Clustering/clusterer.py` as a general, file-based tool

- **Constraint:** no DB access. Match the existing carver pattern.
- **Action:** read samples / carved data by SHA-256.
- **Clustering rule:** TLSH distance `<= 100` **AND/OR** shared config keys (`mutex`, `AES key`, `C2 host`).
- **Transitive matches:** use Connected Components (Union-Find), so `A=B`, `B=C` → `A=C` share one cluster.
- **Deterministic IDs:** `cluster_id` = lexicographically smallest SHA-256 among cluster members. Reproducible runs.
- **Singletons:** a sample matching nothing gets `cluster_id = its own sha256`.
- **Graceful degradation:** if config keys are missing/empty, fall back to TLSH-only clustering.
- **Output:** `Data/Clusters/<sha256>.json` containing `cluster_id`, plus a `.done` marker.

### 3. Extend `Tools/Importer/importer.py`

- **Action:** read the new cluster JSONs.
- **Action:** auto-`ALTER` `DataSet.db` to add a `cluster_id TEXT` column if absent.
- **Check 1:** `SELECT COUNT(*) FROM DataSet WHERE cluster_id IS NULL` must return `0`; exactly 180 rows have a non-NULL `cluster_id`.
- **Check 2:** log the number of distinct `cluster_id` values — this is the effective cluster count for reporting.

### 4. Prepare for future split validation

- **Action:** schema must support the invariant that no cluster spans splits.
- **Check (later):** `SELECT cluster_id, COUNT(DISTINCT split) FROM DataSet GROUP BY cluster_id HAVING COUNT(DISTINCT split) > 1;` must return 0 rows.
- Keep this constraint in mind when designing the JSON schema.

## Interview decisions — batch 1 (Q1–Q3)

- **Q1 — matching rule:** connect two samples if **TLSH distance ≤ 100 OR any one config key matches** (`mutex`, AES key, C2 host). Compare after trimming whitespace and lowercasing. Ignore empty or placeholder values (`%...%`, `obfuscated_key_*`). Transitive matches share one cluster via Union-Find.
- **Q2 — small file / TLSH failure:** log a clear warning, skip TLSH for that sample, still allow config-key matching; if nothing matches → singleton with `cluster_id = its own sha256`. User notes most samples are larger than 256 bytes; the safeguard still applies.
- **Q3 — importer/schema:** importer requires `Data/Clusters/.clusterer.done`, adds `cluster_id TEXT` and `split TEXT` (NULL) columns now, and does not compute splits. The later "no cluster spans splits" query works unchanged.

## Interview decisions — batch 2 (Q4–Q8)

- **Q4 — scope:** cluster **all 180 rows**, including `rejected_non_dotnet` and `benign`. Native samples simply have no config keys and fall back to TLSH.
- **Q5 — config source:** read `Data/Labels/<sha256>.json` → `fields.config`; use `mutex`, `key`, `hosts`; any one match after trim + lowercase; ignore empty/placeholder values; hosts compared exactly as stored (including any port).
- **Q6 — TLSH metric:** use plain TLSH distance, ignoring file-size difference. The exact `tlsh` API will be read before coding, not guessed.
- **Q7 — cluster JSON:** standard envelope `{"schema_version":1,"sha256":...,"kind":"cluster","producer":"clusterer","fields":{"cluster_id":...,"tlsh":"...","config_keys":{...}}}`.
- **Q8 — rerun:** each run overwrites all cluster JSONs and writes a fresh `.done`; importer requires that marker and refuses without it.

## Why these decisions

- **Q1 (OR, not AND):** TLSH catches near-identical builds; config keys catch builds that were recompiled or repacked but reuse the same campaign config. Requiring both would miss either case.
- **Q1 (case-fold + trim, ignore placeholders):** MalwareBazaar metadata and parser output vary in case/whitespace; `%...%` and `obfuscated_key_*` values are noise from unconfigured stubs, not real shared keys.
- **Q2 (warn + skip, not crash):** one small or unhashable file must not break a 180-sample run. A singleton still gets a deterministic ID, so coverage stays complete and no sample is silently dropped.
- **Q3 (marker + both columns now):** the `.done` marker follows the carver/labeler pattern and prevents partial imports (the Q72 lesson). Adding `split TEXT` now avoids a later schema migration and makes the "no cluster spans splits" query possible without changing the importer again.
- **Q4 (all samples):** Phase 0's checkpoint says every sample has a `cluster_id`. Excluding native or benign rows would leave NULLs and break Check 1.
- **Q5 (label JSON only):** labels are the authoritative parser output; re-parsing samples for config would duplicate work and violate the "one extraction path" rule. Any one shared key is enough because campaigns commonly reuse a single mutex or C2 host.
- **Q6 (plain distance):** file size is already a separate structural feature; folding it into TLSH distance could split near-identical builds that differ only by padding. Reading the installed API avoids inventing a function name.
- **Q7 (envelope with `tlsh` and `config_keys`):** keeps cluster JSONs consistent with every other tool and makes a run auditable/reproducible without opening a sample again.
- **Q8 (overwrite + required marker):** makes reruns idempotent and stops the importer from consuming stale data from an earlier clustering attempt.
- **Deterministic ID (plan):** the lexicographically smallest member SHA-256 is stable across machines and reruns, unlike a random cluster number or first-seen order.

## Interview decisions — batch 3 (Q9–Q13)

- **Q9 — missing label JSON:** stop with an exact error naming the SHA-256; no silent skip.
- **Q10 — TLSH source:** compute from the **raw sample file bytes**, not carved JSON (`Docs/Plan.md` §6).
- **Q11 — `config_keys` contents:** store the **raw values used for matching** (mutex, key, hosts) for audit; labeling metadata only, never model features.
  - User noted they had not seen the config keys. Read-only check of `Data/Labels/*.json`: 180 files, 113 non-null `config` — 51 with `mutex`/`key`/`ports`, 50 with `hosts`, 62 `parse_error`, 67 null. So config-key matching can apply to only about 51 samples; the rest fall back to TLSH.
- **Q12 — `split` ownership:** the clusterer never writes `split`; a later split tool writes its own JSON and only the importer fills the column.
- **Q13 — `tlsh` installation:** the user does not authorize me to make a network install; the fixer guy installs it. Code checks the import at startup and fails with an exact message if missing.

## Why (batch 3)

- **Q9:** clustering needs authoritative config from labels; a missing label means an unverifiable sample, so failing loudly beats producing a wrong cluster.
- **Q10:** raw-byte TLSH is what the kNN baseline will use later; hashing carved JSON would create a second, incompatible similarity signal.
- **Q11:** raw values make a cluster decision auditable without re-opening a sample; they never enter the feature matrix, so storing them does not violate capability-only rules.
- **Q12:** keeping `split` owned by a future tool prevents the clusterer from accidentally leaking split information into clustering.
- **Q13:** a clear import error is safer than guessing an API or making a network install without authorization.

## Reminder for the fixer guy

> if you reading this install tlsh

## Interview decisions — batch 4 (Q14–Q18)

- **Q14 — `"None"` placeholder:** treat the literal string `"None"` as a missing/placeholder value; never match on it.
- **Q15 — sample discovery:** build a SHA-256 → path index from `Samples/<Class>/` (same pattern as `labeler.py`), then process only hashes present in `DataSet.db`.
- **Q16 — class boundaries:** cluster across classes; no class filter. Class labels remain in the DB and are not a clustering input.
- **Q17 — cluster count reporting:** print to stdout **and** record the count formally in `Docs/results.md` (created when clustering runs). No other new file in 0.2.
- **Q18 — TLSH error on a normal-sized file:** warn with the exact error and SHA-256, skip TLSH, allow config-key matching, singleton if nothing matches. User note: a stronger similarity method may replace this later; keep the fallback simple for now.

## Why (batch 4)

- **Q14:** the parser writes `"None"` for absent key/salt; matching on it would falsely merge unrelated samples.
- **Q15:** reuses the existing hash-only lookup pattern and guarantees one row per ledger sample, avoiding filename-based lookups.
- **Q16:** similarity is a property of the binary and its config, not of the label; filtering by class could hide cross-family forks that should be grouped.
- **Q17:** stdout gives an immediate check; `Docs/results.md` is the project's planned reporting file, so the effective cluster count belongs there rather than in a new ad-hoc file.
- **Q18:** identical failure policy for small files and corrupt files keeps the rule simple and preserves 180-row coverage.

## Post-0.1 review findings (reported by fixer guy, 2026-11-27)

These are **reported findings and recommended fixes**, not decisions. None are implemented here unless stated.

### Applied fix (verified read-only)

- `Tools/Importer/importer.py` `FAMILY_MAP` (lines 20–32) now includes `njrat → NjRAT`, `remcos → Remcos`, `othermalware → OtherMalware`. Reported: synthetic importer test still passes (not independently run by me).

### Logical errors / recommended fixes

1. **HIGH — no path for other-RAT hard negatives.** `label_status` only emits `verified` for AsyncRAT; every other family becomes `review`, and Q58 keeps `review` in `DataSet.db` only. `OtherMalwares.db` stays empty, so Stage 1/2 never see hard negatives. **Recommended fix:** define a promotion status (e.g. human-approved `verified_other`) that turns a reviewed row into a training row, and implement that transition in `labeler.py` / `importer.py`. Everything downstream depends on this. **Resolved by design (2026-11-27):** `verified_other` + independent-voter aggregator in `Docs/DECISIONS.md` §36 and `Docs/Plan.md` §4. Importer change still pending.
2. Benign rows have `obf_lvl=unknown` because the parser is skipped for benign. Internally consistent; per-obfuscation reporting cannot distinguish plain vs obfuscated benign. Acceptable, just document.
3. `detect_obfuscator` covers only 2 of 8 repos (ConfuserEx, LoGiC.NET), `[TEST]`; obfuscation split reporting is currently meaningless.
4. Tests live in `/tmp/opencode`, not in the repo; carvers have no automated tests. Recommended: move/add tests to the repo so a fresh clone can reproduce them.
5. `is_dotnet` is duplicated in `Tools/Labeling/labeler.py` and `Tools/_carver_common.py`; they agree today but could drift. Recommended: one source.
6. A class directory that exists with zero samples would make the importer fail on a missing `.done`. Unlikely today, but note the assumption.
7. Downloader strict tag filtering drops samples with extra tags (e.g. `upx`). Intentional, but abstain/coverage reporting must account for the reduced coverage.

### Strategic risks

- Pipeline stops at Phase 0.1; 0.2, 0.3, vocabulary, splits, models, abstention gate and Stage 2 are not started. `tlsh` not installed, so clustering cannot run yet.
- Severe class imbalance: 48 AsyncRAT vs 10 benign, no hard negatives.
- `OtherMalwares.db` is empty by design after Q58, yet `Data/OtherMalwares/` still receives carved JSONs. Document or clean up this "carved but not imported" split.
- `FAMILY_MAP` was the only crash-level bug found; the rest of the importer/labeler logic matches the docs.

### Verified / not tested (as reported)

- Verified by fixer: `test_mb.py` 12/12, `test_labeler.py` PASS, `test_importer.py` PASS; carvers produce 134 / 5 / 10 JSONs per tool; DB state 180 / 48 / 10 / no `OtherMalwares.db`.
- Not tested: live MalwareBazaar calls (authorized but not run), clustering/splits/models/abstention (not implemented), carver automated tests (none).
- **Recommended next step:** resolve the hard-negative promotion question (#1) before any model work.

## Status

- 0.2 clustering is implemented: 180 samples → 45 clusters, 14 multi-member, 0 mixed-family, 0 NULL `cluster_id`.
- Batches 5 (mixed-cluster/non-.NET), 6 (Q21–Q25) and Q26–Q30 are answered below.
- Post-0.1 findings are resolved by design where noted; the label-evidence follow-up is in `Docs/DECISIONS.md` §36 and the implementation summary is at the end of this file.

## Interview questions — batch 5 (pending, 10 questions)

Context: one cluster of 63 members mixes 47 `verified` AsyncRAT + 7 XWorm + 9 `unverified`; non-.NET rows carry `rejected_non_dotnet`. All questions below have the recommended default **yes**.

### Mixed-cluster questions

1. **Find the cause first** — report whether those 63 were joined by TLSH ≤100 or by a shared config key.
2. **Family guard** — never union two samples when both have a known parser family and the families differ.
3. **Unverified bridge** — an `unverified` sample may attach to one known-family group but must not bridge two known families.
4. **Empirical check** — run the clusterer at 100, 50 and 25; report cluster count, largest cluster, family purity.
5. **Acceptance rule** — accept a threshold only if no cluster contains more than one known family; report singleton count.

### Non-.NET questions

6. **Partition boundary** — never union a .NET sample with a non-.NET sample, even if TLSH is close.
7. **Non-.NET clustering** — TLSH-only among themselves; config matching does not apply.
8. **Singleton handling** — a non-.NET sample with no TLSH match gets `cluster_id = its own sha256`.
9. **Importer check** — all 180 rows must have non-NULL `cluster_id`.
10. **Split time** — filter out `rejected_non_dotnet` rows before `GroupShuffleSplit`.

Answers will be recorded here before any 0.2 code is written.

---

## Interview results (2026-11-27)

### Q1 — TLSH threshold validation
- **Decision:** Validate empirically first. Done.
- **Result:** TLSH computed for all 180 samples. Distance distribution shows a gap between 99 and 100 (208 vs 224 pairs). Threshold 100 produces 43 clusters, 13 multi-member, 2 mixed-family. Threshold 50 produces 87 clusters, 16 multi-member, 0 mixed-family, largest 56.
- **Action:** Keep 100 as default. Add family-consistency guard. Test 50 available for future comparison.

### Q2 — Config-key matching
- **Decision:** Any shared key (mutex OR key OR hosts). Config keys are a secondary signal; all 17 config-sharing pairs already have TLSH <= 58, so config adds no new clusters beyond TLSH at threshold 100.
- **Rule:** Cluster if (TLSH <= 100) OR (share any config key). In practice, config only confirms existing TLSH clusters.

### Q3 — TLSH input
- **Decision:** Raw file bytes. TLSH designed for binary similarity.

### Q4 — Large cluster (63 members, mixed families)
- **Decision:** Keep threshold 100. Add family-consistency guard (log warning on mixed-family clusters). Test 50 empirically before changing global threshold. No automatic splitting.

### Q5 — Non-.NET samples
- **Decision:** Include in clustering, same directory (`Data/Clusters/<sha>.json`), tagged. Family-consistency guard reports mixed-family clusters including non-.NET members.

### Q6 — Family-consistency guard
- **Decision:** Log warning only. Clusterer writes cluster_id as planned. A separate validation step reports mixed-family clusters. No automatic splitting.

### Q7 — Non-.NET part
- **Decision:** Same directory, tagged. All samples in `Data/Clusters/<sha>.json`. The "separate part" is a log/report section, not a separate directory.

### Q8 — Architecture
- **Decision:** File-based, no DB access. Matches carver pattern. Reads samples by SHA-256. Writes `Data/Clusters/<sha>.json` + `.done` marker. Importer reads cluster JSONs.

### Summary of clustering rules
1. Compute TLSH hash on raw file bytes for each sample.
2. Two samples are in the same cluster if TLSH distance <= 100 OR they share any config key (mutex, key, or host).
3. Transitive closure via Union-Find (connected components).
4. `cluster_id` = lexicographically smallest SHA-256 among cluster members.
5. Singletons get `cluster_id = their own sha256`.
6. Graceful degradation: if config keys missing/empty, TLSH-only clustering.
7. Family-consistency guard: log warning if a cluster contains mixed families.
8. Non-.NET samples included, same directory, tagged.
9. Output: `Data/Clusters/<sha256>.json` with `cluster_id` field + `.done` marker.
10. Importer auto-ALTERs `DataSet.db` to add `cluster_id TEXT` column.

### Empirical threshold comparison
| Threshold | Clusters | Multi-member | In multi | Mixed-family | Largest |
|-----------|----------|--------------|----------|--------------|---------|
| 25 | 112 | 12 | 80 | 0 | 46 |
| 50 | 87 | 16 | 109 | 0 | 56 |
| 75 | 63 | 17 | 134 | 0 | 56 |
| 100 | 43 | 13 | 150 | 2 | 63 |

### Next steps
1. Install `tlsh` (cached wheel available: `python_tlsh-4.5.0`).
2. Implement `Tools/Clustering/clusterer.py`.
3. Extend `Tools/Importer/importer.py` to read cluster JSONs and add `cluster_id` column.
4. Verify: 180 rows with non-NULL cluster_id, log distinct cluster count.

---

## Interview decisions — batch 6 (Q21–Q25, yes to all)

These five were labelled Q11–Q15 when asked in chat, but Q11–Q18 already existed in earlier batches, so they are renumbered Q21–Q25 here. They are also separate from the "Interview results Q1–Q8" numbering above.

- **Q21 — family guard:** log a warning only. No suffix IDs (`<sha>__Family`); `cluster_id` stays the lexicographically smallest member SHA-256. The union-time guard is the prevention, the warning is the safety net.
- **Q22 — mixed cluster found:** continue the run, log the exact warning with member hashes, and report it in `Docs/results.md`. Do not fail the pipeline and do not auto-split the cluster.
- **Q23 — non-.NET storage:** all samples use `Data/Clusters/<sha256>.json`; `fields.is_dotnet` is the tag; one shared `.clusterer.done` marker. No `dotnet/` or `non_dotnet/` subfolders.
- **Q24 — importer read:** glob `Data/Clusters/*.json` and require exactly 180 cluster JSONs.
- **Q25 — reporting:** `Docs/results.md` has a non-.NET section with cluster count and singletons. No extra folders or files.

### Why

- **Q21/Q22:** suffixes would break the deterministic ID rule and make IDs depend on family labels, but clusters are for split leakage, not family labels. A warning plus a results entry keeps the rule intact while making violations visible.
- **Q23/Q24:** one JSON path per SHA-256 and one marker match the carver/labeler pattern; separate directories would need two globs, two markers and a more complex importer without adding safety.
- **Q25:** "separate part" means a report section, not a filesystem split — keeps the data layout simple and reproducible.

## Review decisions — Q26–Q30 (yes to all)

- **Q26 — guard fix:** in the family guard, treat `lbl_sts=verified` as family `AsyncRAT`, not as an empty family. Reason: `verified` rows carry no `sug_fam`, so the current guard lets XWorm join them.
- **Q27 — rerun:** after the guard fix, rerun clusterer + importer and report cluster count, largest cluster, and mixed-family warnings.
- **Q28 — cluster JSON:** add `is_dotnet` into `fields` of every cluster JSON (Q23 compliance).
- **Q29 — importer strictness:** make `Data/Clusters/` mandatory — require `.done` and exactly 180 JSONs; no silent skip (Q24 compliance).
- **Q30 — docs:** update the "Implementation complete" section after the rerun with real numbers.

### Why

- **Q26/Q27:** the 63-member cluster (47 verified + 7 XWorm + 9 unverified) survived because `verified` has no `sug_fam`; the guard must use `lbl_sts` too. Otherwise cluster IDs remain valid but the mixed-family warning is blind to the actual problem.
- **Q28:** `is_dotnet` is the non-.NET partition tag required by Q23; without it the JSON is not self-describing.
- **Q29:** a silent skip would leave `cluster_id` NULL and break Phase 0's checkpoint; strict failure matches every other importer check.
- **Q30:** the current doc claims one mixed warning on a singleton, which the DB does not support; it must reflect the post-fix run.

---

## Implementation complete (2026-11-27, post Q26–Q30)

### Tools/Clustering/clusterer.py
- File-based, no DB access. Reads samples by SHA-256 from `Samples/`.
- Computes TLSH hash on raw file bytes (min 256 bytes; warns if smaller).
- Reads config from `Data/Labels/<sha>.json`.
- Clusters if TLSH distance <= 100 OR shared config key (mutex, key, or host).
- Partition guards: never union .NET with non-.NET; never union samples with differing known families; bridge guard prevents merging components with differing families.
- Transitive closure via Union-Find (connected components).
- `cluster_id` = lexicographically smallest SHA-256 among members.
- Singletons get `cluster_id = their own sha256`.
- Family-consistency guard (Q26): treats `lbl_sts=verified` as family `AsyncRAT` in **both** the union-time guard and the post-run warning; family strings are lowercased before comparison. Logs a warning on mixed-family clusters.
- Cluster JSON fields (Q28): `cluster_id`, `is_dotnet`, `tlsh`, `config_keys`.
- Writes `Data/Clusters/<sha256>.json` + `Data/Clusters/.done`.

### Tools/Importer/importer.py (extended, Q29)
- Reads cluster JSONs from `Data/Clusters/` (mandatory: requires `.done` and exactly 180 JSONs).
- Auto-ALTERs `DataSet.db` to add `cluster_id TEXT` and `split TEXT` columns.
- Sets `cluster_id` on each dataset row.
- Verified: 180 rows, 0 NULL, 45 distinct clusters.

### Run results
- 180 samples clustered into 45 clusters (14 multi-member), **0 mixed-family** after the Q26 union-guard fix.
- The earlier `053fa0de7562` 63-member AsyncRAT + xworm cluster split into a 56-member AsyncRAT component and a 7-member xworm component. All 7 moved samples are `lbl_sts=review`, `sug_fam=xworm`.
- Full pipeline (labeler → clusterer → 5 carvers → importer) completes successfully.
- All synthetic tests pass (labeler, importer, downloader 12/12, live paths 6/6).

### Fresh-run bug fix (2026-11-27)

- The fresh run reproduced the mixed-family warning. Cause: the union-time guard built `families` from `sug_fam` only, so `lbl_sts=verified` rows looked family-less and could join an xworm component. The post-run warning used `family_of()` (which maps `verified` → AsyncRAT), so it reported the mix only after the merge.
- Fix: the union guard now uses the same mapping (`verified` → `asyncrat`) and lowercases family strings. Rerun: 45 clusters, 14 multi-member, 0 mixed-family.
- Fresh-run data-loss check: `samples.db` hash unchanged; 180 label JSONs byte-identical; all 15 carved directories byte-identical; `DataSet.db` 180 rows, 0 NULL `cluster_id`; `AsyncRAT.db` 48 rows; `Benign.db` 10 rows; no missing or extra samples.

### Label-evidence follow-up (2026-11-27)

- The HIGH hard-negative finding is resolved and tested on real data: independent-voter aggregator + `verified_other` routing (`Docs/DECISIONS.md` §36-38, `Docs/Plan.md` §4). Result: 9 XWorm `verified_other` rows.
- `OtherMalwares.db` has 8 rows after gold exclusion (9 before); `review` still stays in `DataSet.db` only. The one remaining review is a real Elastic DcRat vs rat-king VenomRAT conflict.
- Pipeline order is now `labeler -> voters -> aggregator -> clusterer -> carvers -> importer`. The clusterer reads the final label through `Tools/_label_common.load_final_label`, so `verified_other` families stay partitioned.
- Two proposed voters are excluded to avoid label leakage: PE/.NET metadata (Layer A features) and TLSH-to-reference (kNN feature). Config/default-value checks, YARA strings, MB metadata and DIE are safe.
- The MalwareBazaar voter is implemented and run; the live ledger has no `signature` column and empty `api_tags`, so its evidence is weak-only until a backfill.

# TO-DO.md — master checklist

Legend: `[x]` done, `[ ]` not done. Sub-bullets are status notes on the step above them — no new top-level items.

## What The Docs Say (context)

- Build order step 1 deferred the dataset DB design: `samples.db` stays the append-only download ledger and a separate dataset database comes later.
- The two-level DB proposal (one general DB + one DB per sample) was rejected. Implemented instead: one `Data/DataSet.db` index, three class DBs, and per-sample carved JSONs (`Docs/DECISIONS.md` §2, §20).

---

## Phase 0: Foundation (before any carving)

**Goal:** Every sample has a verified label and a cluster assignment.

- [x] **0.1 — Label verification with `rat_king_parser`**
  - [x] Add a `labels` table to `dataset.db` (or a new `labels.db`)
    - Implemented as the `Data/DataSet.db` label index, not a separate `labels` table.
  - [x] For each downloaded sample: run `rat_king_parser`, store result
  - [x] Per Plan.md: `verified` = .NET AND parser reports AsyncRAT AND config has non-placeholder hosts/ports
    - Rule changed by decision: config is stored only if returned; missing/placeholder config does not downgrade (`Docs/DECISIONS.md` §3).
    - **Superseded for the final label by 0.4:** `rat_king_parser` is now one voter, not the only decision maker. `verified` requires ≥2 independent agreements.
  - [x] Store `label_status`, `suggested_family`, `obfuscation_level`
    - Also stores `is_dotnet`, `parser_version`, `config`, `target_class_db`.

- [x] **0.2 — Cluster assignment**
  - [x] Compute TLSH for every sample (use `tlsh` Python package)
  - [x] Cluster by TLSH distance (~100 threshold) + shared config keys (mutex, AES key, C2 host)
  - [x] Store `cluster_id` per sample
  - [x] This must happen before any split
    - Result at the time: 180 samples → 45 clusters, 14 multi-member, 0 mixed-family, 0 NULL `cluster_id`.
    - After the benign expansion (380 samples): 94 clusters at threshold 100, 33 multi-member, 0 mixed-family; 100/50/25 sweep in `Docs/results.md`.

- [x] **0.3 — Benign .NET collection**
  - [x] You need hundreds of benign .NET executables
    - 200 collected from the .NET SDK (21 EXE + 179 DLL) + 10 hand-built = 210.
  - [x] Sources: `dotnet-sdk`, `nuget`, `chocolatey`, `dike` (local benign folder only)
    - `Tools/BenignCollect/collect.py`; no execution; writes only Samples/Benign and the CSV.
  - [x] Never from MalwareBazaar (it has no benign files)
    - Constraint respected.

- [ ] **0.4 — Label evidence and aggregation**
  - Seven voters, aggregator, importer, tests and gold template are done.
    External gaps closed in Phase 1.7: `diec` 4.1.0, YARAify shared key, MB `signature` (0 NULL). Gold is still not hand-labeled.
  - [x] Add `label_evidence` table (`sha256, source, source_version, independence_group, verdict, strength, scope, raw, observed_at`)
    - 2660 rows (7 voters × 380 samples); scope 649 lineage + 2011 family.
  - [x] Voter 1: own YARA rules derived from the AsyncRAT source (strings, not Layer A metadata)
    - `Tools/Voters/OwnYara/`; 13 strings, 4-of-13, benign hits 0. Source commit `0f0cba4`, reference-only.
  - [x] Voter 2: MalwareBazaar metadata (`signature` medium; tags/vendor_intel/ClamAV weak)
    - Implemented and run; ledger has no `signature`, so this run is weak-only (165 hits).
  - [x] Voter 3: Detect It Easy `diec -j -d -e` for `obf_lvl` only (not a family vote)
    - Voter built and run; `diec` is not installed, so all 380 are `unknown`.
  - [x] Voter 4 (existing): `rat_king_parser`; no match is abstention, not a negative
    - 380 evidence files; parser version 4.2.4; benign-only mode used for hand-supplied rows.
  - [x] Aggregator: `verified` = CLR + ≥2 independent strong/medium AsyncRAT agreements + no contradiction
    - Real result: 58 `verified` (was 48); 3 of 94 clusters contain a verified AsyncRAT.
  - [x] Aggregator: `verified_other` routing for XWorm/DcRat/QuasarRAT/VenomRAT/NjRAT/Remcos/XenoRat → `OtherMalwares.db`
    - Real result: 9 XWorm `verified_other`; `OtherMalwares.db` 9 rows (gold candidates are not filled).
  - [x] Aggregator: `review` on contradiction; `unverified` on one/weak/no votes
    - Real result: 1 genuine review (`10102a03f784`, Elastic DcRat vs rat-king VenomRAT).
  - [x] Importer: add `lbl_src`, `lbl_reason`, `is_gold`, `gold_fam`; route `verified_other`
  - [x] Tests inside the repo: `python3 tests/run_tests.py` → 47 pass
  - [x] Gold template: 30 samples from 30 distinct clusters, all `is_gold=0` until filled
    - `Tools/Gold/README.md`; human fields are blank; class DBs 58/9/210.
  - [ ] Hand-label the 30 gold rows in dnSpyEx, then run the audit
  - [ ] Audit: per-voter coverage/precision/recall/F1, contradiction rate, `obf_lvl` agreement → `Docs/results.md`
    - Coverage and contradiction report started; precision/recall need the hand-labeled gold set.
  - [x] Add Elastic (`Windows_Trojan_Asyncrat_11a11ba1`), Malpedia (`win.asyncrat`), YARAify `lookup_hash` as voters
    - Elastic 48 hits, Malpedia 71 hits; YARAify key present in Phase 1.7 (0 rule hits on the corpus).

- [ ] **Checkpoint:** `dataset.db` has every sample with `sha256`, `label_status`, `cluster_id`, `is_dotnet`, `label_source`
  - 1,293 rows, 734 clusters, 0 NULL. `lbl_src` 589 `auto_aggregator` + 704 `hand_benign`; `is_gold=0`. Final labels: 152 `verified`, 9 `verified_other`, 4 `reference_only`, 316 `unverified`, 2 `review`, 106 `rejected_non_dotnet`, 704 `benign` (139 primary + 565 external holdout).

---

## Phase 1: Feature Extraction (the "carvers")

**Goal:** Convert each PE binary into a structured feature record.

- [x] **1.1 — `is_dotnet` check (simple, reliable)**
  - [x] Check for CLR header directory in PE optional header
    - Done with `pefile` data directory 14, statically.
  - [x] Don't use a heavy library for this — just parse the PE header directly
  - [x] Store in `dataset.db`

- [x] **1.2 — Capability extractor (Layer A from Plan.md)**
  - [x] Use `dnfile` (pure Python .NET metadata parser)
  - [x] Extract: `TypeRef`, `MemberRef` (as `Namespace.Type::Method`), `AssemblyRef`, `ImplMap` (as `dll!ImportName`)
    - Plus the native PE import table (`ImportTable` carver), distinct from `ImplMap`.
  - [x] Binary presence only — no counts, no call locations
  - [x] Output: one JSON per sample, or rows in `capabilities` table
    - `Data/<Class>/<Tool>/<sha256>.json`; the importer writes capability columns into the DBs.

- [x] **1.3 — Structural counts**
  - [x] Number of types, methods, TypeRefs, MemberRefs, P/Invoke entries, resources, sections, file size, section entropy
  - [x] `Tools/Structure/structure.py` writes `Data/Structure/<sha>.json` + `.done`; importer adds `structure_*` columns.
  - [x] 1,187 .NET structure JSONs after export batch 1.

- [x] **1.4 — TLSH hash**
  - [x] Already computed in 0.2; stored in `Data/Clusters/<sha>.json`.

- [ ] **Checkpoint:** Every sample has a feature record. You can inspect a few in dnSpyEx to validate.
  - Capability JSONs exist for .NET samples (1,187 per tool); structure JSONs 1,187; TLSH is in cluster JSONs. The Stage 1 gate still fails.

---

## Phase 2: Vocabulary and Split

**Goal:** Training-ready feature matrix with no leakage.

- [x] **2.1 — Build vocabulary (training split only!)**
  - [x] Collect unique `ImportTable`/`TypeRef`/`MemberRef`/`AssemblyRef`/`ImplMap` values from **training split only**
  - [x] Keep only those appearing in ≥3 distinct training clusters
  - [x] Save as `Docs/vocab.json` (2,048 items in the current build)

- [x] **2.2 — Create splits**
  - [x] Cluster split (70/15/15) with `GroupShuffleSplit`, fixed seed
  - [x] Temporal split by `first_seen` (ledger/CSV fallback)
  - [x] Refuse if a cluster spans the cluster split: 0 spans
  - [x] Val/test marked degenerate when positive clusters <2; temporal spans reported (10)

- [x] **2.3 — Feature matrix builder**
  - [x] Pivot capability values into a sparse binary matrix (samples × vocab)
  - [x] Add 11 structural counts as the only dense numeric features
  - [x] `Data/Features/{train,val,test}.npz`, `feature_names.json`, `metadata.json`
  - [x] Current primary matrix: 290 rows / 161 positives / 108 clusters

- [ ] **Checkpoint:** You have `X_train`, `X_val`, `X_test`, `y_train`, `y_val`, `y_test` as numpy/scipy arrays.
  - Arrays exist, but the Stage 1 gate fails; test has 1 positive and is diagnostic only.

---

## Phase 3: Baseline Models

**Goal:** Working predictions with honest evaluation.

- [x] **3.1 — Trivial baseline**
  - [x] Majority class + logistic regression on structural counts only
  - [x] Shows what the capability table adds (diagnostic only)

- [x] **3.2 — LightGBM (mandatory)**
  - [x] Binary capability vectors + structural counts; capability-only and structural-only ablations
  - [x] Reports precision, recall, F1, PR-AUC, confusion matrix, cluster-level CIs
  - [x] LightGBM 4.7.0 installed; no fallback used

- [x] **3.3 — TLSH kNN baseline**
  - [x] Nearest neighbor by TLSH distance from `Data/Clusters/<sha>.json`
  - [x] Diagnostic only; Phase 1.6 test has 24 positives in 17 clusters

- [ ] **3.4 — Abstention gate**
  - [ ] Calibrate threshold from data (TypeRef + MemberRef count distributions)
  - [ ] Report abstain rate per class

- [ ] **Checkpoint:** `Docs/results.md` with confusion matrices, per-class coverage, ablation table.
  - Diagnostic section written; not a result because the gate fails.

---

## Phase 1.5 — positive diversity and gate

- [x] **P0.0 — retire DLLs:** 179 DLLs and derived artifacts moved to `Samples/_aux/`; 309 rows / 139 benign; evidence 2,163.
- [x] **P0.1 — MB contains batch:** non-interactive `--batch --tag AsyncRAT --file-type exe --tag-mode contains` added (`--limit`, `--rate`, `downloads_rejected` audit table, post-run ledger check). Pool 500 → 267 tag-filter, 164 duplicate, 1 wrong type, **68 new**; all 68 downloaded (plus the 1 smoke sample), 69 new ledger rows, 69 signatures stored. Transient `sqlite3` readonly error lost 6 rows on one run; the files were re-adopted (hash-checked) and a ledger check now flags any file without a row.
- [x] **P0.2 — Hassan benign holdout:** 565 unique .NET EXEs (192 duplicates); `source=clrheader2023`, `origin=github`; out of train/val/test; holdout FPR 2/565 = 0.35% (diagnostic).
- [x] **P0.3 — full pipeline:** 943 rows; 0 NULL cluster_id; evidence 6,601 = 7 × 943; class DBs 103 / 9 / 704.
- [x] **P0.4 — gate/LOCO fixes:** Stage 2 counts AsyncRAT + each `verified_other` family with share; LOCO triggers on positive clusters <10; split reports positive clusters/degenerate; 0 cluster spans.
- [x] **P0.5 — report:** Phase 1.5 section in `Docs/results.md`; marked DIAGNOSTIC ONLY.
- [ ] **Still failing:** AsyncRAT 103 positives in 6 clusters, 79 in one (76.7%). The `contains AsyncRAT` pool is exhausted (68 candidates); more MB downloads will not add clusters. Stage 1 is not trainable until independent positive clusters increase.

---

## Phase 1.6 — historical export, split validity, scope, repo hygiene

- [x] **P0.1 — `--from-export` batch 1:** streamed 1,181,317 export rows → 10,922 signature → 7,930 exe → 233 ledger overlap → **350 selected (50/year 2020-2026)**, 350 downloaded, 0 failed; 557 TLSH rejects; manifest `Data/Exports/mb_full_selection.json`; export TLSH re-verified 15/15.
- [x] **P0.2 — rebuild and gate:** 1,293 rows; 152 verified in 36 clusters; largest 88 (57.9%) → Stage 1 FAIL (share only); Stage 2 FAIL (XWorm 9/2/77.8%); benign primary PASS. Batch yield: 50 verified in 34 new clusters (largest new cluster 9 = 18%); .NET 286/350; 232 .NET samples unverified (only MB signature supports them).
- [x] **P0.3 — batch 2:** **not run** (P0.2 stop rule: pooled share 57.9% > 50%). No further downloads.
- [x] **P1 — split validity:** greedy whole-cluster row-target packing (70/15/15, largest first, ties by `cluster_id`); 290 primary rows → train 203/113 (3 clusters, 77.9%, degenerate), val 43/24 (18), test 44/24 (17); 0 cluster spans; validity flags (`test_positives`, `test_positive_clusters`, structural confound, LOCO inspect, split degenerate) force DIAGNOSTIC; per-cluster recall and nearest-train TLSH distance reported (one 7-row test cluster at distance 17 → leakage flag).
- [x] **P2 — server/builder audit:** `Tools/Audit/reference_only.py` flags file names (metadata only, never a feature); 4 verified `stub` samples marked `reference_only` (previous status preserved), excluded from class DBs/splits; static spot-check of 20 verified EXEs found no server/builder types.
- [x] **P3 — repo hygiene:** 4,958 tracked JSONs → **0**; generated `Data/` dirs, DBs and `.done` markers untracked (`git rm --cached`, files intact); `.gitignore` extended; `Docs/REPRODUCE.md` added.
- [x] **P4 — docs:** Phase 1.6 section in `Docs/results.md`; this block.
- [ ] **Open:** Stage 2 XWorm diversity; 232 unverified historical .NETs; train remains dominated by the 88-sample cluster; one TLSH leakage pair (distance 17).

---

## Phase 1.7 — YARAify, DIE, family queue, gate

- [x] **P0.1 — YARAify shared key:** `YARAIFY_AUTH_KEY` preferred, `MB_AUTH_KEY` fallback; key present, never logged.
- [x] **P0.1b — YARAify parser bug/fix:** `lookup_hash` returns `data` as a dict (`metadata`, `tasks`), not a list; the old parser returned `[]` for every sample. The parser now reads `static_results[].rule_name`/`malpedia_family`, `clamav_results[]`, `unpacked_yara_matches[]` and metadata signatures, for both dict and list response shapes. Curated ClamAV/metadata names only disambiguate conflicting static rules (sample `4902c56dfa` resolves to AsyncRAT/medium). 10 synthetic tests.
- [x] **P0.1c — YARAify rerun:** all 1,505 samples at ≤1 req/s; hit counts in `Docs/results.md` Phase 1.7.
- [x] **P0.2 — DIE:** official Detect It Easy 4.1.0 (Fedora 45 RPM + distro Qt5 + current db); voter updated for the 4.x JSON schema; `obf_lvl` 1,359 plain / 146 obfuscated / 0 unknown.
- [x] **P0.3 — signatures:** 801/801 non-null (170 backfilled from the export; no invented values).
- [x] **P0.4 — gold:** `Data/Gold/review/gold_review_sheet.{csv,md}` (30 rows, 0 missing after SHA-based path resolution) + `Tools/Gold/merge_gold_review.py`; human audit pending (0/30).
- [x] **P0.5 — verified_other:** 9 XWorm at the start of the phase; after the fork-label fix it is 40 (XWorm 32, VenomRAT 5, QuasarRAT 2, DcRat 1), all with two family-scoped voters.
- [x] **P1 — family queue:** `--family-queue` + `families.json` + `Docs/FAMILY_TREE.md`; 181 selected/downloaded (target-capped), 23 families `unavailable_mb`; no AsyncRAT relabeling.
- [x] **P2 — AsyncRAT batch 2:** 350/350 downloaded (319 resumed); 24 new verified (6.9%), 66 new non-.NET. Dataset 1,824 rows. Gate measured; no batch 3.
- [x] **P3 — rebuild and gate:** 1,505 rows; 0 NULL; evidence 10,535; class DBs 130/40/704. Gate FAIL: AsyncRAT 130/32/86 (66.2%); benign PASS 70/14.7%; Stage 2 FAIL (XWorm 32/11/59.4%, Venom 5/4/40% PASS, Quasar 2/1, DcRat 1/1).
- [x] **P4/P5 — split validity / leakage / server audit:** 299 primary rows; train 209/119/16 clusters (72.3%, degenerate), val 44/25/20, test 46/26/13 (53.8%); 0 spans; stale cleanup 17 files; leakage 14-row AsyncRAT test cluster at TLSH 86 to XWorm train (family guard, reported); 2 `reference_only` remain.
- [x] **P6 — git/docs:** 0 generated JSONs tracked; only `Tools/MBDownloader/families.json` (source) is tracked as JSON; dataset DBs are tracked; Phase 1.7/1.9 written in `Docs/results.md`.
- [x] **Orchestrator:** cold 22 stages (~43 min stage work) → warm 14.7 s, 20 skipped, importers only. State 22/22 ok.

## Phase 2.0 — pipeline cache and git tracking

- [x] Schema versions, `Data/Pipeline/state.json` fingerprints, reuse in labeler/carvers/structure/voters, DIE workers, YARAify trivial-skip, single carver pass.
- [x] Git: the four dataset DBs are tracked; generated JSONs/logs/markers and `Samples/` are ignored; tests stay tracked; only `families.json` is tracked as JSON.

## Phase 4 (evaluation) — LOCO, abstention, explainability

- [x] Cluster-level LOCO over all 152 clusters (82 positive): full 0.981, capability 0.983, structural 0.915, TLSH kNN 0.773 F1; per-cluster recall/CIs/obf strata.
- [x] Abstention threshold 357 (train-only); verified coverage 90.9%, other 96.6%, benign 34.1%.
- [x] Explainability: gain + per-sample `pred_contrib` top-10 + TLSH nearest templates.
- [x] Hassan-style non-name CLR-header baseline (14 features): F1 0.874 vs capability 0.983; methodology comparison only.
- [x] Stage 2 rules/kNN with abstention: 24/58 abstain; 33/34 decided correct; Quasar/DcRat abstain.
- [x] Data decision: freeze at 1,824 rows; no batch 3, no family queue.

## Fixup evaluation (Phase 2.1d, 2026-11-28)

- [x] WS0 snapshot: all brief numbers reproduced; tests were 202, not 192 (Phase 4 added 10); 227 after the fixup, methodfix and OOF tests.
- [x] WS1 decisions: §40 records D1 approved, D2 not approved, P1–P3 approved, WS6b.
- [x] WS2 labeler bias: all 498 unverified AsyncRAT rows are MB-signature-only; obfuscated and plain show the same pattern.
- [x] WS4 cap: train-only 89→10 rows (79 removed); 238/148 → 159/69; DB/splits unchanged.
- [x] WS5 feature policy: separate `Data/Features/policy/` matrix; four container fields dropped from models.
- [x] WS6/6b fixup evaluation: grouped OOF threshold (5-fold by cluster); capability OOF F1 .903 [.800,.971] vs P/Invoke .788 [.677,.904] (overlap); PR .988 vs .695 and ROC .980 vs .645 (separate); random leak .960 (+.057); mixed LOCO at 0.5, capability recall .981 FPR .016/.023, P/Invoke FPR .636; see `Docs/results.md`.
- [x] WS7 Stage 2 eligibility: only AsyncRAT and XWorm qualify; test macro F1 .931 [.807,1.000] on 29 rows; wording says diagnostic 2-family LightGBM, not a result.
- [x] WS8 temporal caveat: benign dates are 10 collection batches; formats differ; diagnostic only.
- [x] WS9 gold: 30 rows, 0 filled, 30/30 paths resolve; dry-run reports 0 updates; no `--write`.
- [ ] WS3/D2 70/30 partition: **not run**, awaiting explicit "approve D2".
- [x] WS10 docs: results, limitations, REPRODUCE, Plan status lines; §41 OOF method.
- [x] P4 label audit: 1,540 rows, MB-only 530, multi-source 263, conflicts 107; gold 30/0, no merge.
- [x] P5 deletion: Data/Gold/review_sheet.md only (review/gold_review_sheet.md kept).

## Phase 5 — matched operating points, errors, thesis package (2026-11-28)

- [x] Matched 95%/90% target recall on train OOF; test/holdout/LOCO tables; P/Invoke and file size use raw thresholds, never 0.5.
- [x] Single evaluator run: `run_id=c7a21a6c…`, script `6598bfce`, 5 OOF folds; all sections same run.
- [x] Error analysis: 0 FP / 7 FN at matched 95; F1-optimal 2 FP / 4 FN; 31 matched-95 LOCO misses (24 fold-threshold; 3/5 old positive-only); 2 Stage-2 XWorm→AsyncRAT errors, not `00fe40a8`; 0 holdout FP; 4 obfuscated positives, 2 caught.
- [x] Label audit refined: 107 conflicts = 14 support / 20 different / 73 tie; verified_other 14/0/42; unverified 20/31.
- [x] `Docs/FINAL_RESULTS.md`, `Docs/MODEL_CARD.md`, `Docs/CLAIMS.md`; results pointer; limitations/REPRODUCE updated.
- [x] Tests 234; no deletions, staging or commits; gold 30/0.
- [ ] D2/WS3: not run; requires explicit approval.

## Phase 4: Stage 2 (Family Classification)

**Goal:** Distinguish AsyncRAT from Quasar/DcRat/njRAT/etc.

- [ ] **4.1 — Family-discriminative features**
  - [ ] Only features that differ between RAT families
  - [ ] Exclude packer, loader, campaign artifacts
  - [ ] May end up being rules/kNN rather than a trained model

- [ ] **4.2 — Evaluation**
  - [ ] Confusion matrix between families
  - [ ] Abstention when confidence is low

---

## Phase 5: Explainability

- [ ] **5.1 — LightGBM feature importance**
  - [ ] Global: which capabilities matter most
  - [ ] Per-sample: top-10 contributing references

- [ ] **5.2 — kNN explanation**
  - [ ] Nearest training sample + TLSH distance

- [ ] **5.3 — Template sentences**
  - [ ] "Flagged as AsyncRAT-family: references [X + Y], config-shaped static class. Confidence 0.87."

---

## Where Your Plan Deviates From The Docs

- Individual DB per sample → rejected; implemented as three class DBs plus per-sample carved JSONs.
- `is_dotnet` in general DB → stored in `DataSet.db`, but never fed to the model.
- "Carvers, collectors, DB uploaders" → implemented as separate tools plus one importer, not one extractor script (`Docs/DECISIONS.md` §13).

---

## Immediate Next Steps

- [x] Tasks 1–7 are complete
  - 0.1 labeling/carving/import is finished.
- [x] **Install `dnfile`**: `pip install dnfile` — start reading its docs
  - Listed in `Tools/requirements.txt`.
- [x] **Install `tlsh`**: `pip install tlsh` — test it on a few samples
  - Installed (`python_tlsh-4.5.0`); clustering runs.
- [ ] **Install Detect It Easy** (`diec`) — needed for `obf_lvl`; read `diec --version` and `diec -h`
- [ ] **Fix the MalwareBazaar ledger**: add `signature`, `file_size`, `last_seen` to the live `downloads` table and populate `api_tags`
- [x] **Write own AsyncRAT YARA rules** from the source strings (not from rat-king-parser or Elastic)
  - `Tools/Voters/OwnYara/`; benign hits 0.
- [x] **Freeze the gold-set SHA-256 list** before hand-labeling, so the audit is not tuned on the same samples
  - `Data/Gold/gold.csv`, 30 clusters, human fields blank.
- [x] **Set `YARAIFY_AUTH_KEY`** (or reuse `MB_AUTH_KEY`) — done in Phase 1.7; 0 hits, auth_key_present=true
  - The user notes it is the same value as the MalwareBazaar key; it was not used because this task forbids MB/YARAify/Malpedia API calls.
- [ ] **Hand-label the 30 gold rows** in dnSpyEx and run the precision/recall audit
- [x] **Sketch `dataset.db` schema** on paper before coding
  - Recorded in `Docs/DECISIONS.md` §2.
- [x] **Collect benign .NET files** with `Tools/BenignCollect/collect.py`
  - 200 collected (21 EXE, 179 DLL) + 10 hand-built = 210; `Data/BenignSources.csv` 200 rows.
- [x] **Threshold sweep and dataset report**
  - 100/50/25 sweep on 380 samples; `Tools/Report/dataset_report.py` output in `Docs/results.md`.

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
    External gaps: `diec`, `YARAIFY_AUTH_KEY`, MB `signature`; gold is not hand-labeled.
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
    - Elastic 48 hits, Malpedia 71 hits; YARAify client built but no auth key in this run.

- [ ] **Checkpoint:** `dataset.db` has every sample with `sha256`, `label_status`, `cluster_id`, `is_dotnet`, `label_source`
  - 380 rows, 94 clusters, 0 NULL. `lbl_src` 170 `auto_aggregator` + 210 `hand_benign`; `is_gold=0`. Final labels: 58 `verified`, 9 `verified_other`, 71 `unverified`, 1 `review`, 31 `rejected_non_dotnet`, 210 `benign`.

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

- [ ] **1.3 — Structural counts**
  - [ ] Number of types, methods, TypeRefs, MemberRefs, P/Invoke entries, resources, sections, file size, section entropy
  - [ ] These go in `structures` table

- [ ] **1.4 — TLSH hash**
  - [ ] Already computed in 0.2, store it

- [ ] **Checkpoint:** Every sample has a feature record. You can inspect a few in dnSpyEx to validate.
  - Capability JSONs exist for all samples; structural counts and TLSH are missing.

---

## Phase 2: Vocabulary and Split

**Goal:** Training-ready feature matrix with no leakage.

- [ ] **2.1 — Build vocabulary (training split only!)**
  - [ ] Collect all unique `MemberRef`/`TypeRef` values from **training split only**
  - [ ] Keep only those appearing in ≥3 distinct clusters (cluster-based MDF)
  - [ ] Save as `Docs/vocab.json`

- [ ] **2.2 — Create splits**
  - [ ] Cluster split (70/15/15) with `GroupShuffleSplit`
  - [ ] Temporal split by `first_seen`
  - [ ] Refuse to run if a cluster spans splits

- [ ] **2.3 — Feature matrix builder**
  - [ ] Pivot `capabilities` into a sparse binary matrix (samples × vocab)
  - [ ] Add structural counts as dense features
  - [ ] Save as `features/train.npz`, `features/val.npz`, `features/test.npz`

- [ ] **Checkpoint:** You have `X_train`, `X_val`, `X_test`, `y_train`, `y_val`, `y_test` as numpy/scipy arrays.

---

## Phase 3: Baseline Models

**Goal:** Working predictions with honest evaluation.

- [ ] **3.1 — Trivial baseline**
  - [ ] Logistic regression on structural counts only
  - [ ] Shows what the capability table adds

- [ ] **3.2 — LightGBM (mandatory)**
  - [ ] Binary capability vectors + structural counts
  - [ ] Report: precision, recall, F1, PR-AUC, full confusion matrix

- [ ] **3.3 — TLSH kNN baseline**
  - [ ] Nearest neighbor by TLSH distance
  - [ ] Report nearest sample and distance as explanation

- [ ] **3.4 — Abstention gate**
  - [ ] Calibrate threshold from data (TypeRef + MemberRef count distributions)
  - [ ] Report abstain rate per class

- [ ] **Checkpoint:** `Docs/results.md` with confusion matrices, per-class coverage, ablation table.

---

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

## Immediate Next Steps (while the agent finishes)

- [x] **Wait for the agent** to finish Tasks 1–7
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
- [ ] **Set `YARAIFY_AUTH_KEY`** to enable the YARAify hash lookup voter
  - The user notes it is the same value as the MalwareBazaar key; it was not used because this task forbids MB/YARAify/Malpedia API calls.
- [ ] **Hand-label the 30 gold rows** in dnSpyEx and run the precision/recall audit
- [x] **Sketch `dataset.db` schema** on paper before coding
  - Recorded in `Docs/DECISIONS.md` §2.
- [x] **Collect benign .NET files** with `Tools/BenignCollect/collect.py`
  - 200 collected (21 EXE, 179 DLL) + 10 hand-built = 210; `Data/BenignSources.csv` 200 rows.
- [x] **Threshold sweep and dataset report**
  - 100/50/25 sweep on 380 samples; `Tools/Report/dataset_report.py` output in `Docs/results.md`.

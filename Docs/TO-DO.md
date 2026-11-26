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
  - [x] Store `label_status`, `suggested_family`, `obfuscation_level`
    - Also stores `is_dotnet`, `parser_version`, `config`, `target_class_db`.

- [ ] **0.2 — Cluster assignment**
  - [ ] Compute TLSH for every sample (use `tlsh` Python package)
  - [ ] Cluster by TLSH distance (~100 threshold) + shared config keys (mutex, AES key, C2 host)
  - [ ] Store `cluster_id` per sample
  - [ ] This must happen before any split

- [ ] **0.3 — Benign .NET collection**
  - [ ] You need hundreds of benign .NET executables
    - Only 10 hand-built test PEs in `Samples/Benign/` so far.
  - [ ] Sources: your own machine's `C:\Windows\Microsoft.NET\`, installed programs, NuGet packages compiled from source
  - [x] Never from MalwareBazaar (it has no benign files)
    - Constraint respected.

- [ ] **Checkpoint:** `dataset.db` has every sample with `sha256`, `label_status`, `cluster_id`, `is_dotnet`
  - `cluster_id` is still missing (0.2).

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
- [ ] **Install `tlsh`**: `pip install tlsh` — test it on a few samples
- [x] **Sketch `dataset.db` schema** on paper before coding
  - Recorded in `Docs/DECISIONS.md` §2.
- [ ] **Collect 10–20 benign .NET exes** from your own machine to test the extractor
  - Only 10 hand-built test PEs exist so far.

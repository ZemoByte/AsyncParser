# Plan.md — AsyncRAT .NET Payload Detector

Status tags: **[DECIDED]** locked, **[TEST]** keep only if an ablation shows it helps, **[TODO]** not started or open.

## 1. Goal
Detect AsyncRAT .NET client payloads from static metadata, using capability features and similarity analysis. Project title: "Reverse Engineering of Binary/Assembly codes of malware with similarity analysis". Keep TLSH nearest-neighbor visible in the results so the title still matches.

## 2. Scope
- **In**: .NET AsyncRAT client payloads. **[DECIDED]**
- **Out** (label and exclude, never "solve"): droppers, loaders, PowerShell/VBS stagers, native (Go/C++) builds, steganography, runtime-decrypted payloads, dynamic analysis. **[DECIDED]**
- **Hardware**: 4GB RTX 3050 laptop. Classical ML first. No LLM fine-tuning. **[DECIDED]**

## 3. Core philosophy [DECIDED]
1. No code reading or decompilation in the automated pipeline. Humans use ILSpy/dnSpyEx only for validation (about 20 samples), error analysis and label audits.
2. One uniform automated extraction for every sample.
3. Structured metadata beats raw bytes. No raw-byte tokenization.
4. Discrimination over similarity: ask "what does AsyncRAT have that benign software and other RATs do not", trained against hard negatives. Similarity (TLSH kNN) stays as a baseline and as the "nearest known sample" explanation.
5. Trust external references (framework types/methods, P/Invoke imports). They cannot be renamed without breaking the program. Ignore the sample's own names.

## 4. Data and labels
### Class vocabulary (`Tools/common/families.py`) [DECIDED]
`AsyncRAT_Client`, `AsyncRAT_Plugin`, `AsyncRAT_Server`, `AsyncRAT_Reference`, `QuasarRAT`, `DcRat`, `NjRAT`, `Remcos`, `VenomRAT`, `XWorm`, `OtherMalware`, `Benign`, `Unverified`, `Excluded`.

### Label verification [DECIDED]
- `rat_king_parser` (pip `rat-king-parser`; supports AsyncRAT, DcRAT, VenomRAT, QuasarRAT, XWorm, XenoRat per its README). Used at **labeling time only, never as a model feature**. Check real CLI flags with `-h` before coding.
- `verified` = .NET AND parser reports AsyncRAT AND config has non-placeholder hosts/ports (not `%...%`, not `obfuscated_key_*`).
- .NET but failed → `unverified`. Native tagged AsyncRAT → `Unverified` + `rejected_non_dotnet`.
- If the parser reports another family, store it in `suggested_family`; do not force AsyncRAT.
- Optional second check: CAPE's AsyncRAT config extractor **[TODO: confirm it can run standalone before depending on it]**. Disagreement between tools = `needs_human_review`, checked in dnSpyEx. Never auto-label a disagreement as "fork".
- Manifest columns to add: `label_status` (verified | unverified | rejected_non_dotnet | rejected_hash_mismatch | reference_only | needs_human_review), `label_source`, `suggested_family`, `obfuscation_level` (plain | obfuscated | unknown), config columns (hosts, ports, mutex, key, salt).

### Data needs (the real bottleneck) [TODO]
- Pull a larger MalwareBazaar AsyncRAT set. Audit tags for fork contamination (DcRat, Quasar, VenomRAT).
- Hundreds of **benign .NET executables** (not DLLs, or the model learns file type).
- Other .NET RATs as hard negatives (Quasar, DcRat, njRAT, VenomRAT, XWorm).
- The current benign set is 100 native Sysinternals tools. It cannot teach capability combinations. Until fixed, label every result "preliminary".
- Effective sample size = number of **clusters**, not files. Report cluster counts.

### Reference archive (vx-underground builder package) [DECIDED]
Toolkit, not victim samples. Never run or build anything from it. Mapping (data file, not hardcoded):
- `Stub/*.exe` → `AsyncRAT_Reference` (inspect the actual contents first; not yet seen)
- `Plugins/*.dll` → `AsyncRAT_Plugin`
- `AsyncRAT.exe`, `BackProxyUI.exe`, `proxlib.dll` → `AsyncRAT_Server`
- `*.pdb`, `*.xml`, `*.config`, `*.bat`, `*.p12`, `*.ini`, `AnyDesk.exe` and other third-party tools → `Excluded`
- `All-In-One.dll` → manual review
Uses: derive YARA strings, similarity anchors (distance to nearest reference as an explanation, not a training feature), version-aware evaluation. Never in training. The unconfigured stub has placeholder config, so mark it `reference_only`.

## 5. Splits [DECIDED]
- Cluster by TLSH distance (default threshold about 100) AND by verified config keys (same mutex, AES key or C2 host = same cluster), plus campaign markers (byte-array hash, icon hash).
- Split by cluster (70/15/15) with GroupShuffleSplit. Also provide a temporal split by `first_seen`. Refuse to run if a cluster spans splits.
- Run the split **before** fitting anything (vocabulary, frequency filters).

## 6. Features
### Layer A — capability table [DECIDED]
From dnfile/dnlib metadata: TypeRef, MemberRef (as `Namespace.Type::Method`), AssemblyRef, ImplMap (as `dll!ImportName`).
- Binary presence only. No counts, no call locations.
- Vocabulary built from the **training split only**. Keep a reference only if it appears in **at least 3 distinct clusters** (cluster-based minimum document frequency). Save `Data/vocab.json`.
- IDF is not used for LightGBM (trees ignore per-feature scaling). IDF is only for an optional neural set encoder.
- Capability signature sets (e.g. `avicap32 + capCreateCaptureWindowA` = webcam), built from clean DLLs checked in ILSpy/dnSpyEx.
- Structural counts: number of types, methods, TypeRefs, MemberRefs, P/Invoke entries, resources, sections, file size, section entropy.
- TLSH of the raw file for kNN.

### Layer B — structural skeleton [TEST]
Class/method signatures, inheritance, interfaces, field types, anonymous "shape" distribution (e.g. static class with ~15 string fields + PBKDF2/AES refs = config jar). Do not label which container is which capability. Check that it survives ConfuserEx-style type merging and renaming before trusting it. Stage 2 only.

### Extra signals — tag each as Family / Benign / Packer / Campaign [TEST]
1. Hardcoded byte arrays (`field.InitialValue` hashes). Likely **Campaign**. Use as a cluster key first. Feature only if it generalizes across clusters.
2. Resource inventory (sizes, entropy, embedded MZ/.NET headers). Packer/Family.
3. Async state machines (`IAsyncStateMachine` nested types). Mostly a **compiler-era** confound, not a capability. Keep out of Stage 1 unless an ablation proves it.
4. Assembly identity pattern (AssemblyVersion, TargetFramework, etc.). Era confound risk.
5. Toolchain traces (VB.NET vs C#, PDB, compiler-generated types).
6. Win32 layer (version-info forgery, Authenticode, icon hash, overlay). Mostly **Campaign/Packer**.
7. Metadata row ordering as a sequence signal. Obfuscators may reshuffle it; test stability first.

Do not use: sample's own type/method/field names, user strings, `is_dotnet`, hand-written API lists, "family hints" from generic imports.

## 7. Models
### Two-stage design [DECIDED]
- **Stage 1: RAT vs benign.** Uses all capability signals, including reflection/loader artifacts. High-recall target.
- **Stage 2: family** (AsyncRAT vs other RATs). Uses only family-discriminative features (specific import combinations, structural shapes). Excludes packer, loader and campaign artifacts. High-precision target with abstention when confidence is low. With little data, a kNN or simple rules may beat a trained model here. Compare.
- Reflection hiding (`Assembly.Load`, `MethodInfo.Invoke`) may drive Stage 1 but never the family label in Stage 2.
- Encrypted config: never decrypt for features. (The parser is for labeling only.)

### Models [DECIDED]
1. Baseline: **LightGBM** on binary reference vectors + structural counts. Mandatory.
2. **TLSH kNN** baseline. Mandatory.
3. Trivial baseline on structural counts only, to show what the capability table adds.
4. Optional stretch: small from-scratch set/sequence encoder (10-50M params). Only if the baseline shows signal. Expect overfitting with few clusters.

## 8. Abstention gate [DECIDED]
Abstain (log as `out_of_envelope`, never force a prediction) when:
- the parse fails, or CLR metadata is missing;
- TypeRef + MemberRef count is below a threshold **calibrated from the data** (look at benign and RAT distributions; do not guess a number);
- (optional, only if a reliable detector exists) method bodies are encrypted with no readable resources.
Report the **abstain rate per class** next to accuracy (e.g. "abstained on 40% of verified AsyncRAT"). Abstaining on packed samples inflates scores if not reported.

## 9. Explainability [DECIDED]
- LightGBM: global feature importance, plus per-sample top-10 contributing references (SHAP if available, else gain).
- kNN: nearest training sample and its TLSH distance.
- Template sentences built from those features, e.g. "Flagged as AsyncRAT-family: references [X + Y], config-shaped static class. Confidence 0.87. Nearest known sample: [hash] (TLSH distance 12)."
- Small language model explainer (Qwen2.5-0.5B / Llama-3.2-1B) is a **stretch goal only**, strictly conditioned on the top features.
- State clearly: explanations are at capability level, not intent.

## 10. Evaluation and reporting
- Precision, recall, F1, PR-AUC, and a **full confusion matrix** (do not hide fork confusion in one accuracy number).
- Report separately for `obfuscation_level` = plain / obfuscated / unknown.
- Report coverage (abstain rate) per class.
- Ablation table: add Layer B and each extra signal one at a time; show what each adds across clusters.
- Splits: cluster split and temporal split.
- Human check: about 20 samples in dnSpyEx; error analysis; label audit.
- Write `docs/limitations.md`: native/droppers/loaders/stego out of scope; runtime-decrypted payloads and encrypted reflection hide references; padding with benign-looking references can evade a presence-based model.

## 11. Build order (each step has a check)
1. Fix dataset/label bugs (section 12 A) → check: tests pass, manifest validates, no unknown families.
2. Add `rat_king_parser` verification → check: verified/unverified counts printed, placeholders rejected.
3. Collect benign .NET and other-RAT negatives; build clusters and splits → check: no cluster spans splits; cluster counts reported.
4. Layer A extractor + vocabulary (training only, ≥3 clusters) → check: `vocab.json` reproducible.
5. LightGBM + TLSH kNN + trivial baseline → check: `Data/results.md` with confusion matrices and per-class coverage.
6. Abstention gate with data-calibrated thresholds → check: abstain rates reported.
7. Ablations for Layer B and extra signals, hand-check ~20 samples in dnSpyEx → check: ablation table.
8. Stage 2 family step and explainer templates.
9. Only then: neural encoder or language-model explainer.

## 12. Repo fix list (from the code review)
Confirm each is real before fixing. Line numbers are approximate. One commit per ID, made by the user.

### A. Dataset and labels (first)
- A1 `mb_downloader.unzip_and_save` rglobs the whole `Other_Malwares/` and takes the first `.exe`. Extract each zip into a fresh temp dir; verify sha256; move to `<sha256>.exe`.
- A2 SHA256 mismatch only warns and keeps the file. Delete, log to `Data/rejected.csv`, write no row.
- A3 Downloader: use `urlencode`; handle the 1000-result cap; do not drop samples with null `file_name`; label by MalwareBazaar signature only (tags in a separate column); fix `skipped`/`failed` counters; remove dead code; run the manifest updater once, not per download.
- A4 `manifest_updater.find_sample` falls back to `matches[0]`. Match by sha256 only; mark `file_missing`; do not overwrite columns with "unknown".
- A5 Family names disagree across scripts. One vocabulary in `Tools/common/families.py`; `manifest_check.py` rejects unknown values.
- A6 `sort_by_family.py`: remove the hardcoded 7-hit control check; fix the never-incremented counter; implement or remove the "untracked file" check; make it idempotent; match by sha256.
- A7 `extractor.py`: case-insensitive extensions; load/write the manifest once; rename to `<sha256>.exe`; fill signature/tags from MalwareBazaar; add `label_source`.
- A8 Add `label_status` column and rules (section 4).

### B. Verification
- B1 `Tools/Verify/verify_asyncrat.py` wrapping `rat-king-parser` (list args, no shell, 120s timeout, mocked tests).
- B2 Delete `config_parser.py` and `config_fields.py` (NameError, bytes-regex-on-str, plaintext assumptions, base64-decoding every field, duplicates). Store extracted config in manifest columns.
- B3 Optional loose YARA rule from names in the open-source AsyncRAT C# source, each string's source documented.

### C. .NET pipeline (`Tools/Static/DotNet/`)
- C1 `run_phase2a.py` continues on the raw binary and mixes output into `Cleaned/`. Record `source` (cleaned|raw), write raw output to `Raw/`, add a format gate.
- C2 `verify_cleaned.py` KeyErrors and requires a `type` field nobody writes.
- C3 Delete `decode_resources.py` (duplicate of `extract_resources.py`, weaker).
- C4 `extract_resources.py` fallback is always "printable". Require printable ratio over the whole blob and a minimum length; guard `res.name` being None.
- C5 `decrypt_strings.py`: `readable()` accepts `�`; XOR brute force is slow. Strict decode, `bytes.translate`, cap and time budget.
- C6 `carve_payloads.py` cuts PEs at the next `MZ` and scans quadratically. Use PE header sizes; use `data.find`.
- C7 `extract_steganography.py` treats everything after any PNG `IEND` as hidden data; unguarded `pefile.PE`.
- C8 `protector_detect.py`: weak "reactor" regex, no ConfuserEx marker, wrong attribute type resolution, first-match only. Its output feeds `obfuscation_level`.
- C9 `suspicious_api.py`: hand-written list, substring matching. Replace with the data-driven vocabulary (section 6).
- C10 Wire unused tools into one features step or delete them. `assembly_metadata.py` is extended to emit the external reference table.

### D. Native files and hygiene
- D1 `native_analyze.py`: useless "first 50 strings" and generic "family hints" (remove). Native files are out of scope; the script stays for triage.
- D2 Fill `arch`/`os` from the pefile Machine field.
- D3 `requirements.txt`: use `python-tlsh`; keep `yara-python` only if B3 is done; remove `pycryptodomex` if unused.
- D4 README safety section: isolated VM, no network, no shared folders; de4dot may execute sample code during string decryption.
- D5 `.gitignore`: `Samples/`, `Reference/`, `*.exe`, `*.dll`, `*.zip`, `*.7z`, `*.p12`.

### PART E: MINIMAL ML PIPELINE (after A-D pass tests)

Design: capability-based, two-stage, with an abstention gate. Stage 1 = RAT vs benign.
Stage 2 = family. Everything is fitted on the TRAINING split only.

E1. Splits FIRST (Tools/ML/cluster_split.py). Run before any fitting.
    - Cluster by TLSH distance (configurable threshold, default ~100) AND by verified
      config keys (same mutex, AES key or C2 host => same cluster), AND by campaign
      markers (hardcoded byte-array hash, icon hash).
    - Split by cluster into train/val/test (70/15/15) with GroupShuffleSplit. Also offer a
      temporal split using first_seen. Save Data/splits.csv.
    - Refuse to run if any cluster spans splits.
    - Print the number of CLUSTERS per class and per split. Effective sample size is the
      number of clusters, not the number of files. The current AsyncRAT rows were only
      deduplicated by exact sha256, not by cluster, so expect far fewer independent
      samples than rows. Write the cluster counts into Data/results.md.

E2. Layer A features (Tools/ML/build_features.py), .NET files only.
    Positives: label_status=verified AsyncRAT_Client.
    Negatives: Benign .NET apps, other .NET RAT families, .NET OtherMalware.
    Never in training: AsyncRAT_Plugin, AsyncRAT_Server, AsyncRAT_Reference, Excluded,
    Unverified, needs_human_review, any native file.
    Features (dnfile metadata tables, no execution):
      a) External reference table per sample:
         - MemberRef as "Namespace.Type::Method" (resolve the parent TypeRef)
         - TypeRef as "Namespace.Type"
         - ImplMap (P/Invoke) as "dll!ImportName"
         - AssemblyRef names
      b) Binary presence vectors only (no counts, no locations).
      c) Structural counts: number of types, methods, TypeRefs, MemberRefs, P/Invoke
         entries, managed resources, section count, file size, average/max section entropy.
      d) TLSH of the raw file bytes (skip files too small; log them).
    DO NOT use: the sample's own type/method/field names, user strings, is_dotnet,
    hand-written API lists, IDF weighting for LightGBM (trees ignore per-feature scaling).

E3. Vocabulary and frequency filter (CLUSTER-based, training split only).
    - Build the vocabulary from the TRAINING split only.
    - Keep a reference only if it appears in at least 3 DISTINCT TRAINING CLUSTERS (not 3
      files; one campaign of 5 near-identical builds must not pass). Make 3 configurable.
    - Never compute this filter on validation/test data or on the whole dataset.
    - Save Data/vocab.json. Test: re-running with the same split gives the same vocabulary.

E4. Two-stage models (Tools/ML/train_eval.py).
    Stage 1: RAT vs benign. Uses the Layer A vocabulary and structural counts, including
      reflection/loader references (Assembly.Load, MethodInfo.Invoke). High-recall target.
      Async state-machine absence is NOT used in Stage 1 by default; it mostly dates the
      compiler era, not a capability. Include it only as an ablation candidate.
    Stage 2: family (AsyncRAT vs other RATs). Uses only family-discriminative features
      (specific reference combinations; Layer B structural shapes if the ablation supports
      them). Excludes packer, loader and campaign artifacts. High-precision target with
      abstention when confidence is low.
    Stage 2 will be severely data-starved. The safe baseline is kNN on TLSH distance
      (plus simple rules). A trained Stage 2 classifier is OPTIONAL and only kept if it
      beats the kNN baseline on the cluster-split test set.
    Models to train and compare:
      (1) LightGBM on Layer A vectors + structural counts (Stage 1; Stage 2 optional)
      (2) kNN on TLSH distance (Stage 1 and Stage 2)
      (3) trivial baseline on structural counts only, to show what the capability table adds
      (4) optional later: small neural set encoder, only if (1)-(3) show signal; IDF
          weighting is allowed ONLY here.

E5. Abstention gate (applied before either stage).
    Abstain and log as out_of_envelope (never force a prediction) when:
      - the parse fails, or CLR metadata is missing;
      - TypeRef + MemberRef count is below a threshold.
    Derive the threshold from the empirical distribution of reference counts in the
      TRAINING benign and RAT samples (e.g. a low percentile); print the distribution
      and the chosen value. Do NOT hardcode a guess such as "< 10".
    Do NOT add "all method bodies encrypted" as a trigger: there is no reliable static
      detector for it.
    MANDATORY reporting: abstain rate PER CLASS next to every accuracy number, e.g.
      "abstained on 40% of verified AsyncRAT". Also report accuracy on the covered
      samples and coverage on all samples. Accuracy without the abstain rate is misleading
      because packed samples are systematically dropped.

E6. Evaluation, ablations and explainability.
    - Report precision, recall, F1, PR-AUC and a FULL confusion matrix for both stages on
      the cluster-split test set and on the temporal split. Do not collapse fork confusion
      (AsyncRAT vs DcRat) into one number.
    - Report separately for obfuscation_level = plain / obfuscated / unknown (from C8).
    - Ablation table: add each candidate group ONE AT A TIME and report the change across
      clusters: Layer B shapes, hardcoded byte-array hashes, icon hash, version-info
      forgery, overlay, async state machines, assembly identity, toolchain traces,
      metadata row order (test its stability under obfuscation first). Tag each signal
      Family / Benign / Packer / Campaign and print the tag in the table.
    - Campaign signals (byte arrays, icon hashes, version info, overlay) are used as
      cluster keys first, and are ALSO included in the ablation. See caution 1.
    - Explainability: LightGBM global feature importance and per-sample top-10 contributing
      references (SHAP if available, else gain); for kNN print the nearest training sample
      and its TLSH distance. Generate verifiable TEMPLATE sentences from those features,
      for example "Flagged: references [X + Y]. Confidence 0.87. Nearest known sample:
      [hash] (TLSH distance 12)." No language-model explainer in the core deliverable.
    - Write Data/results.md with a "how to read this" paragraph: explanations are at
      capability level (which APIs contributed), not intent.

E7. Label disagreement (applies to Part B tools).
    - Primary verifier: rat_king_parser (labeling time only, never a feature).
    - Optional second check: CAPE's AsyncRAT config extractor. FIRST confirm it runs
      standalone (outside a full CAPE install) and record its version; if it does not,
      skip it and say so. Do not assume availability.
    - If the two tools DISAGREE, set label_status = needs_human_review. Do NOT auto-label
      a disagreement as "fork" or "variant"; parser failures have many causes (version
      drift, build quirks, unusual builds). Samples in needs_human_review are excluded
      from training and evaluation until a human checks them in dnSpyEx.

E8. Data needs and limitations.
    - Benign negatives are currently 100 native Sysinternals tools, which cannot teach
      capability combinations. Add a TODO listing the need for benign .NET executables
      (not DLLs) and other .NET RATs (Quasar, DcRat, njRAT, VenomRAT, XWorm). Do not
      fabricate samples. Until they exist, mark all results "preliminary".
    - Write docs/limitations.md: native, Go/C++, droppers, loaders and stego are out of
      scope; runtime-decrypted payloads and encrypted reflection hide references from the
      table; padding with benign-looking references can evade a presence-based model;
      numbers are only as good as the number of independent clusters.

CAUTIONS (keep verbatim):
1. The claim that campaign signals "will almost certainly fail" is a prediction. Run the
   ablation; do not preemptively exclude them.
2. Stage 2 will be severely data-starved. A kNN or simple rule-based system may
   outperform a trained classifier for family assignment. Treat learned Stage 2 as
   optional; kNN + TLSH is the safer baseline.

## 13. Open questions [TODO]
- Which benign .NET executables to use, and where from.
- Contents of the `Stub/` folder in the builder archive.
- Whether CAPE's AsyncRAT extractor runs standalone.
- Calibrated abstention threshold.
- Whether Layer B and each extra signal survive the ablations.

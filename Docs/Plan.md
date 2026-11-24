# Plan.md — AsyncRAT .NET Payload Detector

Status tags: **[DECIDED]** locked, **[TEST]** keep only if an ablation shows it helps, **[TODO]** not started or open.

## 1. Goal
Detect AsyncRAT .NET client payloads from static metadata, using capability features and similarity analysis. Project title: "Reverse Engineering of Binary/Assembly codes of malware with similarity analysis". Keep TLSH nearest-neighbor visible in the results so the title still matches.

## 2. Scope
- **In**: .NET AsyncRAT client payloads. **[DECIDED]**
- **Out** (label and exclude, never "solve"): droppers, loaders, PowerShell/VBS stagers, native (Go/C++) builds, dynamic analysis. **[DECIDED]**
- **Hardware**: 4GB RTX 3050 laptop. Classical ML first. **[DECIDED]**

## 3. Core philosophy [DECIDED]
1. No code reading or decompilation in the automated pipeline. Humans use ILSpy/dnSpyEx only for validation (about 20 samples), error analysis and label audits.
2. One uniform automated extraction and download for every sample.
3. Structured metadata beats raw bytes. No raw-byte tokenization.
4. Discrimination over similarity: ask "what does AsyncRAT have that benign software and other RATs do not", trained against hard negatives. Similarity (TLSH kNN) stays as a baseline and as the "nearest known sample" explanation.
5. Trust external references (framework types/methods, P/Invoke imports). They cannot be renamed without breaking the program. Ignore the sample's own names.

## 4. Data and labels
### Class vocabulary [DECIDED]
`AsyncRAT_Client`, `AsyncRAT_Plugin`, `AsyncRAT_Server`, `AsyncRAT_Reference`, `QuasarRAT`, `DcRat`, `NjRAT`, `Remcos`, `VenomRAT`, `XWorm`, `OtherMalware`, `Benign`, `Unverified`, `Excluded`.

### Label verification [DECIDED]
- `rat_king_parser` (pip `rat-king-parser`; supports AsyncRAT, DcRAT, VenomRAT, QuasarRAT, XWorm, XenoRat per its README). Used at **labeling time only, never as a model feature**. Check real CLI flags with `-h` before coding.
- `verified` = .NET AND parser reports AsyncRAT AND config has non-placeholder hosts/ports (not `%...%`, not `obfuscated_key_*`).
- .NET but failed → `unverified`. Native tagged AsyncRAT → `Unverified` + `rejected_non_dotnet`.
- If the parser reports another family, store it in `suggested_family`; do not force AsyncRAT.
- Optional second check: CAPE's AsyncRAT config extractor **[TODO: confirm it can run standalone before depending on it]**. Disagreement between tools = `needs_human_review`, checked in dnSpyEx. Never auto-label a disagreement as "fork".
- Manifest columns to add: `label_status` (verified | unverified | rejected_non_dotnet | rejected_hash_mismatch | reference_only | needs_human_review), `label_source`, `suggested_family`, `obfuscation_level` (plain | obfuscated | unknown), config columns (hosts, ports, mutex, key, salt).

### Data needs [TODO]
- Pull a larger MalwareBazaar AsyncRAT set. Audit tags for fork contamination (DcRat, Quasar, VenomRAT).
- Hundreds of **benign .NET executables** (not DLLs, or the model learns file type).
- Other .NET RATs as hard negatives (Quasar, DcRat, njRAT, VenomRAT, XWorm).
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
- Vocabulary built from the **training split only**. Keep a reference only if it appears in **at least 3 distinct clusters** (cluster-based minimum document frequency). Save `Docs/vocab.json`.
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
- Write `Docs/limitations.md`: native/droppers/loaders out of scope; runtime-decrypted payloads and encrypted reflection hide references; padding with benign-looking references can evade a presence-based model.

## 11. Build order (each step has a check)
1. Define the manifest schema and label vocabulary → check: manifest validates, no unknown families.
2. Add `rat_king_parser` verification → check: verified/unverified counts printed, placeholders rejected.
3. Collect benign .NET and other-RAT negatives; build clusters and splits → check: no cluster spans splits; cluster counts reported.
4. Layer A extractor + vocabulary (training only, ≥3 clusters) → check: `Docs/vocab.json` reproducible.
5. LightGBM + TLSH kNN + trivial baseline → check: `Docs/results.md` with confusion matrices and per-class coverage.
6. Abstention gate with data-calibrated thresholds → check: abstain rates reported.
7. Ablations for Layer B and extra signals, hand-check ~20 samples in dnSpyEx → check: ablation table.
8. Stage 2 family step and explainer templates.
9. Only then: neural encoder or language-model explainer.
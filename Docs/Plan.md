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
`AsyncRAT_Client`, `AsyncRAT_Plugin`, `AsyncRAT_Server`, `AsyncRAT_Reference`, `QuasarRAT`, `DcRat`, `NjRAT`, `Remcos`, `VenomRAT`, `XWorm`, `XenoRat`, `OtherMalware`, `Benign`, `Unverified`, `Excluded`.

### Label verification — independent voters [DECIDED]
Labels are decided by **independent static voters**, not by one parser. The rule is stricter than "labeling time only": **anything used to decide a label must not also be a model feature**. If a field is a voter, it is removed from the feature matrix; if it is a feature, it cannot vote.

**Voters (start small; add one only with a measured gain):**

| Voter | Independence group | Verdict | Strength | Status |
|---|---|---|---|---|
| `rat_king_parser` family YARA (`asyncrat`, `dcrat`, `quasarrat`, `xenorat`, `xworm`, `venomrat`) | `yara:rat-king` | family / no match | strong positive; **no match = abstain** | implemented |
| Own YARA rules derived from the AsyncRAT source/builder | `yara:own` | family / no match | strong | implemented — 13 strings, 4-of-13, benign 0; lineage detector, hits forks too |
| Elastic `Windows_Trojan_Asyncrat_11a11ba1` + `Windows_Trojan_DCRat_1aeea1ac`, `Windows_Trojan_XWorm_*`, `Windows_Trojan_Quasarrat_e52df647` | `yara:elastic` | family / no match | strong | implemented — 48 hits; AsyncRAT scope lineage |
| Malpedia family rules (`/api/get/yara/<family_id>`; IDs `win.asyncrat`, `win.dcrat`, `win.xworm`, `win.quasar_rat`, `win.venom`, `win.njrat`, `win.remcos`, `win.xenorat`) | `yara:malpedia` | family / no match | strong/medium | implemented — 71 hits; AsyncRAT scope lineage |
| signature-base rules | `yara:signature-base` | family / no match | medium | TODO — no AsyncRAT-specific rule found in a tree scan; verify before adding |
| MalwareBazaar metadata (`signature`, `tags`, `vendor_intel`, `intelligence.clamav`, `code_sign`) | `metadata:mb` | family / benign / unknown | medium (`signature`), weak (tags, vendor_intel, ClamAV) | implemented — weak ledger tags only; `signature` column missing |
| YARAify hash lookup (`lookup_hash`, `search_term=<sha256>`) | `lookup:yaraify` | family / no match | medium if a family-specific rule matched; weak if generic | implemented — shared abuse.ch key (`YARAIFY_AUTH_KEY` or `MB_AUTH_KEY`); 0 rule hits on the current corpus |
| Config/default-value checks (`%MTX%`, `%Ports%`, `%Hosts%`, `%Key%`, `%Certificate%`, `%Serversignature%`, ports `6606/7707/8808`, `NYAN CAT`) | `static:config` | AsyncRAT stub / unknown | medium | TODO |
| Detect It Easy (`diec -j -d -e`) | `attribute:die` | **`obf_lvl` only, never a family vote** | strong for a named obfuscator | implemented — `diec` not installed, so `obf_lvl=unknown` |

**Lineage scope:** AsyncRAT evidence from own/Elastic/Malpedia/MB/YARAify is
`raw.scope=lineage`; it counts toward `verified` but cannot contradict a
family-specific fork vote. `rat_king_parser` AsyncRAT is `scope=family`. This
is what lets `verified_other` promote real forks without losing the AsyncRAT
lineage signal.

**Excluded as label voters** because they are model features (using them would leak the label into the features):
- TypeRef / MemberRef / AssemblyRef / ImplMap vocabulary (Layer A).
- TLSH distance to reference builds (the kNN baseline).
- Any PE/.NET metadata column that is also a feature.
- `is_dotnet` is the exception: it is metadata-only, never a feature, and it is the first gate.

**Evidence storage:** `label_evidence` table in `Data/DataSet.db`:
`sha256, source, source_version, independence_group, verdict, strength, raw, observed_at`.
`raw` is a JSON summary (rule name, matched strings, API fields); never sample bytes. One row per `(sha256, source, source_version)`. Voters write JSON under `Data/Evidence/<sha256>/<source>.json`; the importer is still the only DB writer.

**Aggregator rules [DECIDED]:**
1. No CLR header → `rejected_non_dotnet`, regardless of votes.
2. A voter that returns no match **abstains**. Absence is not a contradiction.
3. Normalize family aliases to the fixed vocabulary; unknown values → `review`.
4. `verified` (AsyncRAT) = CLR header + **≥2 independent `strong`/`medium` AsyncRAT agreements** + no contradiction.
5. `verified_other` (XWorm, DcRat, QuasarRAT, VenomRAT, NjRAT, Remcos, XenoRat) = the same rule for that family. This is the promotion path for hard negatives and the only status that writes `OtherMalwares.db`.
6. `review` = any contradiction between voters that name different known families, or a family vote against a benign vote. Default counts `medium`/`strong` only; `contradiction_min_strength=weak` gives the strict "any contradiction" rule (recommended default: `medium`, so noisy MB tags do not flood the queue).
7. `unverified` = one `strong`/`medium` voter, weak voters only, or no voters.
8. `benign` stays a hand-supplied status until benign voters exist; the aggregator does not derive it.
9. `reference_only` overrides everything for the reference archive.
10. A human gold label overrides the aggregator and sets `label_source=human_gold`.

**Strength:**
- `strong`: family-specific rule from own/source-derived YARA, rat-king-parser, Elastic, Malpedia; DIE for a named obfuscator.
- `medium`: MB `signature`, a generic YARA rule, config/default-value match.
- `weak`: MB tags, `vendor_intel`, ClamAV labels, hash lookups.

**Gold set [DECIDED]:** about 30 samples hand-labeled in dnSpyEx, selected by **cluster** (not file) and stratified across `verified`, `review`, `unverified`, `benign`, `rejected_non_dotnet`. Stored in `Data/Gold/gold.csv`; the importer adds `is_gold` and `gold_family`. Only a row with a **non-empty `gold_status`** is gold; blank candidates stay in their class DB. Filled gold rows stay in `DataSet.db` only and are excluded from every split and from the class DBs. Used only to audit voter precision/recall, not to train. Freeze the SHA-256 list before labeling.

**Manifest columns to add:** `label_status` (`verified | verified_other | unverified | rejected_non_dotnet | rejected_hash_mismatch | reference_only | needs_human_review | benign`), `label_source` (`auto_aggregator | human_gold | parser_only | hand_benign`), `suggested_family`, `obfuscation_level`, `label_reason` (JSON), `is_gold`, `gold_family` (DB column `gold_fam`), config columns (hosts, ports, mutex, key, salt). Short DB names are in `Docs/SHORT_NAMES.md`.

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
1. **[DONE]** Append-only download ledger `Tools/MBDownloader/samples.db` and label vocabulary (including `benign`) are defined; separate `Data/*.db` files created by the importer.
2. **[DONE]** Label evidence: all seven voters work; the aggregator writes final labels. DIE 4.1.0 and YARAify are active. → check: labels stable after the labeler, parser exceptions captured in `config.parse_error`. Human gold audit remains 0/30.
2b. **[DONE]** Seven voters + aggregator + `label_evidence` + gold template; `diec` 4.1.0 installed, YARAify key active, ledger signatures backfilled. Only hand-labeling the 30 gold rows remains. → see `Docs/results.md` Phase 1.7.
3. **[DONE]** Clusters and cluster splits are built; 1,228 clusters, 341 primary rows, 0 cluster spans. Benign is 704 (565 external holdout + 139 other). → check: no cluster spans splits; gate and split validity reported.
4. **[DONE]** Five Layer A carvers exist (`ImportTable`, `TypeRef`, `MemberRef`, `AssemblyRef`, `ImplMap`) plus structure; the vocabulary is fitted on train clusters only.
5. **[DONE, DIAGNOSTIC]** LightGBM + TLSH kNN + trivial baseline → check: `Docs/results.md` has confusion matrices, LOCO and coverage. The gate fails, so this is not a result.
6. **[DONE, DIAGNOSTIC]** Abstention gate with train-calibrated TypeRef+MemberRef threshold → check: abstain rates reported in `Docs/results.md`.
7. **[PARTIAL]** Ablations for Layer B and extra signals are done (cap, policy, CLR-header); the ~20-sample dnSpyEx human check is still pending.
8. **[DONE, DIAGNOSTIC]** Stage 2 rules/eligibility + explainer templates; AsyncRAT/XWorm only under P2; no family model claimed.
9. **[NOT STARTED]** Only then: neural encoder or language-model explainer.

## 12. Current state (2026-11-27)

**Done — downloader and data intake (synthetic-tested, no live API run after the final changes):**
- `Tools/MBDownloader/mb_downloader.py`: interactive menu, file-type validation, primary/secondary/Surprise Me tag rule, one `get_taginfo` query per run, new-first then backlog ordering, SHA256 dedup, rate limiting, 5 retries, 429 backoff, Ctrl+C stop, clean summary, temp DB cleanup, console progress lines.
- File handling: atomic move, five-way SHA256/name check, adoption of already-present verified files, quarantine of mismatching files, no deletion of files the current attempt did not create.
- `downloads` ledger: tag rule, file type, full Bazaar tag list, attempt tracking; local cap counts every `get_file` attempt over a rolling 24 h window; `samples.db` is intentionally tracked in git. **Gap:** the code defines `signature`, `file_size` and `last_seen`, but the live 170-row DB has none of them (`PRAGMA table_info(downloads)` shows 13 columns) and `api_tags` is empty. Rerun the downloader schema migration or `ALTER` the table before the MalwareBazaar voter can use `signature`.
- `Tools/requirements.txt` (`pyzipper`), `.gitignore` excludes `Samples/` and downloaded sample extensions, `AGENTS.md` §9 forbids committing `Samples/`.

**Done — Phase 0 labeling/import (synthetic-tested; importer run on real generated data):**
- `Tools/Labeling/labeler.py`: reads the ledger by SHA-256, checks the PE CLR header, batches `rat_king_parser -n`, writes label JSON and `.labeler.done`; benign hand-made EXEs must be labeled as `benign` with `sug_fam=Benign` (§31/Q71).
- `Tools/_carver_common.py` plus `ImportTable`, `TypeRef`, `MemberRef`, `AssemblyRef`, `ImplMap`: one carver per folder, each writes `Data/<Class>/<Tool>/<sha256>.json` plus `.done`.
- `Tools/Importer/importer.py`: creates `Data/DataSet.db` and class DBs, auto-`ALTER`s columns, imports labels and carved JSONs, enforces markers and schema version, deletes markers after success, and places rows by label.
- Synthetic tests: `/tmp/opencode/test_labeler.py`, `/tmp/opencode/test_importer.py`. **Verified after the clean rerun (read-only):** `DataSet.db` 180 rows, `AsyncRAT.db` 48 rows, `Benign.db` 10 rows, `OtherMalwares.db` absent, all carving columns present, 0 `.done` markers left (`Docs/DECISIONS.md` §33).
- **Superseded by the Phase 0 finish run (2026-11-27):** `DataSet.db` 380 rows, `AsyncRAT.db` 58, `OtherMalwares.db` 9, `Benign.db` 210; 94 clusters; `is_gold=0`; 2660 evidence rows. See `Docs/results.md` and `Docs/DECISIONS.md` §39.

**Not done yet:**
- Obfuscator fingerprint detection: two markers implemented (`ConfusedByAttribute`, `LoGiCdotNetAttribute`); no matches in 380 samples. DIE (`diec -j -d -e`) is the planned replacement for `obf_lvl`; it is not installed yet.
- Label evidence: all seven voters + aggregator + `label_evidence` are built. Gaps closed in Phase 1.7: `diec` 4.1.0 (Fedora 45 RPM + Qt5 + current db), YARAify via the shared key, MB `signature` backfilled (0 NULL). The 30-row gold set is still not hand-labeled. P2.1 collected 200 benign (21 EXE/179 DLL) + 10 hand-built = 210; final dataset 380 rows. See `Docs/results.md`.
- Reference archive contents inspection and mapping. `Reference/AsyncRAT-C-Sharp` is a gitignored source checkout; `Reference/vx-underground` and `Reference/Ultimate-Rat-Collection` hold the builder archives/READMEs (not extracted or run); `Reference/Elastic` and `Reference/Malpedia` hold the local YARA rules. CAPE is no longer planned (superseded by the independent voters; do not add it unless it can run standalone).
- Layer A extractor and `Docs/vocab.json`; LightGBM, TLSH kNN and trivial baseline; `Docs/results.md`.
- Clusters: `Tools/Clustering/clusterer.py` implemented; `cluster_id` populated (94 clusters, 33 multi-member, 0 mixed-family after the benign expansion; 45 before). The fresh-run union-guard bug is fixed (see `Docs/DECISIONS_PART2.md`). Threshold sweep 100/50/25 is in `Docs/results.md`. Temporal splits still pending.
- Abstention thresholds, ablations, ~20-sample dnSpyEx human check, Stage 2 explainer templates, `Docs/limitations.md`.
- Neural encoder / language-model explainer (stretch only).
- Live verification: **AUTHORIZED by user** (`Docs/DECISIONS.md` §35); network is available in the VM and the user accepts real sample downloads. Not yet executed. Synthetic mocked-API tests already cover 429 / cap / error-limit / single-pass / Ctrl+C (12/12 downloader tests). Use `MB_AUTH_KEY` securely; never print or log it.

**Fixup state (2026-11-28):** `DataSet.db` 1,824 rows / 1,228 clusters;
Stage 1 FAIL (154/52, largest 89 = 57.8%), Stage 2 FAIL; all model numbers
diagnostic. P1 policy matrix is `Data/Features/policy/`, D1 cap is train-only
diagnostic, D2 70/30 partition is **not run** (awaiting approval), P3 temporal
results are diagnostic because benign dates are collection-batch dates.
Thresholds are grouped 5-fold OOF; Phase 5 adds matched 95%/90% target recall,
LOCO at the matched point, error analysis and the FINAL_RESULTS/MODEL_CARD/
CLAIMS package. The label audit is automated, not human gold. D2 is not run. Phase 12 thesis package and final audit written; tests: 258. No commits, no network, no new data.
# results.md — run reports

## Phase 0.5 — remaining voters, lineage scope, gold (2026-11-27)

Pipeline: `labeler -> rat-king -> own YARA -> Elastic -> Malpedia ->
MalwareBazaar -> DIE -> YARAify -> aggregator -> clusterer -> carvers ->
importer -> gold template -> importer`.

### Final `lbl_sts` (before vs after)

The malware labels were measured on 180 samples before P2.1. The final dataset
is 380 samples after adding 200 collected benign files; only `benign` changes.

| label | Phase 0.4 (180) | Phase 0.5 (180) | final (380) |
|---|---:|---:|---:|
| `verified` | 48 | **58** | 58 |
| `verified_other` | 0 | **9** (all XWorm) | 9 |
| `unverified` | 78 | 71 | 71 |
| `rejected_non_dotnet` | 31 | 31 | 31 |
| `review` | 13 | **1** | 1 |
| `benign` | 10 | 10 | **210** |

`sug_fam` final: 155 empty, 210 Benign, 9 XWorm, 3 DcRat, 2 QuasarRAT,
1 AsyncRAT.

### Voter hits (joined to the final `lbl_sts`)

| Voter | Positive hits | Final status breakdown |
|---|---:|---|
| `rat_king_parser` | 73 | AsyncRAT 48 → 48 verified; DcRat 2 → 2 unverified; QuasarRAT 3 → 2 unverified + 1 verified; VenomRAT 1 → 1 review; XWorm 9 → 9 verified_other |
| `own_yara` | 73 | AsyncRAT 73 → 58 verified, 1 review, 2 unverified, 9 verified_other, 3 rejected_non_dotnet; benign 0 |
| `elastic` | 48 | AsyncRAT 45 → 45 verified; DcRat 1 → 1 review; XWorm 2 → 2 verified_other |
| `malpedia` | 71 | AsyncRAT 59 → 58 verified + 1 unverified; XWorm 9 → 9 verified_other; XWorm 3 → 3 rejected_non_dotnet |
| `malwarebazaar` | 165 | weak AsyncRAT 165 → 56 verified, 1 review, 68 unverified, 9 verified_other, 31 rejected_non_dotnet; no_match 5 (2 verified, 3 unverified) |
| `detect_it_easy` | 0 family | 380 no_match; `obf_lvl=unknown` (no `diec`) |
| `yaraify` | 0 | 380 no_match (no `YARAIFY_AUTH_KEY`) |

Positive hit counts are unchanged by the benign expansion: all 210 benign
samples are `no_match` for every family voter.

`label_evidence`: **2660 rows** (7 × 380), max `raw` 1246 bytes.
Scope column: 649 `lineage`, 2011 `family`, 0 NULL.

### Real `verified_other` promotion

- 9 XWorm samples are `verified_other`; `OtherMalwares.db` has **9 rows**.
  The 30 gold candidates are not excluded until `gold_status` is filled, so
  they remain in the class DBs.
- The promotion is real, not synthetic: rat-king XWorm strong + Malpedia
  and/or Elastic XWorm family-scoped strong, with own-YARA/Elastic/Malpedia
  AsyncRAT evidence marked `scope=lineage` so it does not contradict the fork.
- DcRat (2) and QuasarRAT (2) remain `unverified`: only rat-king votes for
  them; no second family-scoped group matched.

### Remaining contradiction

Only one review remains:

| sha256 prefix | voters | verdicts |
|---|---|---|
| `10102a03f784` | `elastic` (family) vs `rat_king_parser` (family) | DcRat strong vs VenomRAT strong |

This is a genuine family disagreement, not a lineage artefact.

### Clusters

Final (380 samples): **94 clusters**, 33 multi-member, largest 78,
61 singletons, 0 mixed-family. Clusters containing ≥1 `verified` AsyncRAT:
**3 of 94** (the benign expansion adds benign-only clusters; the three
malware clusters are unchanged). The XWorm `verified_other` group occupies
2 clusters.

### Gold set

- `Tools/Gold/build_gold_set.py` selected **30 samples from 30 distinct
  clusters**: 3 verified, 1 verified_other, 1 review, 18 unverified, 1 benign,
  6 rejected_non_dotnet.
- `Data/Gold/gold.csv` human fields are blank; `gold_fam` is NULL.
- After the P0.1 fix, `is_gold=1` is **0** on all 380 rows; blank `gold_status`
  is a candidate, not a gold row. Class DBs are `AsyncRAT.db` 58,
  `OtherMalwares.db` 9, `Benign.db` 210. There are no filled gold rows, so no
  class-DB exclusion yet.
- Hand-labeling in dnSpyEx is pending; precision/recall audit is not done.

### Data-loss checks

- The original 180 label JSONs are byte-identical:
  `406aa42609521b0cf9c98158296c90336ad5d921f9128914030429cb5db49c88`.
- The original 745 carved JSONs are byte-identical:
  `6c8c4b86a16c9f62bce09ed63bab48f52771e0aa7830403e27aad1dbc7f1c37f`.
- `samples.db` SHA-256 is unchanged:
  `08f938c5b00d1565b7de74cc230434f42ed5e4312e06630ea5f44670130dc10d`.
- `DataSet.db` 380 rows, 0 NULL `cluster_id`, 94 clusters.
- `label_evidence` 2660 rows; scope 649 `lineage` + 2011 `family`, 0 NULL.
- `lbl_reason` valid JSON on all rows.
- New benign rows: 200 collected + 10 hand-built = 210; 200 CSV rows.

### Phase 0 finish checks (P0/P1/P2)

**P0.1 `is_gold` semantics.** `is_gold=1` only when `gold_status` is
non-empty. Blank rows are candidates and remain in their class DB. Final:
`is_gold=0` on all 380 rows; class DBs 58 / 9 / 210.

**P0.3 vote scope.** `label_evidence.scope` is persisted: 649 `lineage`,
2011 `family`, 0 NULL. Attribute voters (DIE) are stored as `family` because
they cannot promote a family.

**P1.1 single PE parser.** `Tools/_pe.py` is the only `is_dotnet`
implementation; the labeler and carver common module import it. Synthetic
tests cover .NET, native, truncated and non-MZ files.

**P1.2 threshold sweep (380 samples).**

| TLSH threshold | clusters | largest | singletons | multi-member | mixed-family |
|---:|---:|---:|---:|---:|---:|
| 25 | 277 | 46 | 243 | 34 | 0 |
| 50 | 241 | 56 | 200 | 41 | 0 |
| 100 (default) | 94 | 78 | 61 | 33 | 0 |

The acceptance rule holds at every threshold: no cluster contains more than
one known family. The default stays 100; `Data/Clusters` was not overwritten.

**P1.3 dataset report.** `python3 Tools/Report/dataset_report.py` reports
380 rows, 94 clusters, 61 singletons, largest 78, 0 mixed-family. Class DBs:
58 AsyncRAT, 9 OtherMalwares, 210 Benign. Median size: AsyncRAT 45 KiB,
Benign 705 KiB; class balance **210 benign vs 67 positive**.

**P2.1 benign collection.** NuGet dry run: 91 .NET PE candidates, 65 unique,
20 selected. .NET SDK dry run: 3,751 candidates, 3,152 unique, 20 selected.
The 10-file live run copied 10; the full run collected 200
(**21 EXE, 179 DLL**) plus 10 hand-built = **210** benign files. The SDK has
only 21 .NET EXEs; DLLs were included to reach the 200 target. `labeler
--benign-only` wrote labels/evidence without the parser; the full 7-voter
pipeline then produced 380 rows / 210 benign / 94 clusters / 2,660 evidence
rows. No sample was executed.

**P2.2 gold quota warning.** The builder now prints unmet quotas and the
substitution. On the 380-row dataset: verified 8→3, review 7→1, and 11
substituted rows (benign 9, unverified 1, verified_other 1).
`Data/Gold/gold.csv` was not changed.

### Plain conclusion

The remaining voters materially improved the result: `verified` 48→58,
`verified_other` 0→9, `review` 13→1, cluster coverage 2→3. P2.1 then expanded
benign from 10 to 210 without changing the malware labels. The external
blockers are `diec` for `obf_lvl`, `YARAIFY_AUTH_KEY`/MalwareBazaar
`signature` for stronger metadata, and a second family-scoped voter for
DcRat/QuasarRAT. The 200 collected benign files are 21 EXE + 179 DLL; DLLs
were needed because the SDK has only 21 .NET EXEs.

## Label coverage (Phase 0.4 offline core, 2026-11-27) — SUPERSEDED BY PHASE 0.5

> This section is historical. Use the Phase 0.5 numbers above.

Pipeline: `labeler -> rat_king_parser evidence -> own YARA -> aggregator ->
clusterer -> 5 carvers -> importer`.

### `lbl_sts` before vs after

| `lbl_sts` | before | after |
|---|---:|---:|
| `verified` | 48 | 48 |
| `unverified` | 76 | 78 |
| `rejected_non_dotnet` | 31 | 31 |
| `review` | 15 | 13 |
| `benign` | 10 | 10 |

### `sug_fam` before vs after

| `sug_fam` | before | after |
|---|---:|---:|
| `<none>` | 155 | 146 |
| `Benign` | 10 | 10 |
| `XWorm` | 9 | 9 |
| `AsyncRAT` | 0 | 9 |
| `QuasarRAT` | 3 | 3 |
| `DcRat` | 2 | 2 |
| `VenomRAT` | 1 | 1 |

### Clusters

| Metric | before | after |
|---|---:|---:|
| Clusters | 45 | 45 |
| Multi-member | 14 | 14 |
| Mixed-family | 0 | 0 |
| Clusters containing ≥1 `verified` AsyncRAT | 2 | 2 |

The two verified clusters are `053fa0de7562` (56 members) and
`4902c56dfa5b` (singleton). The new voters **confirmed** the existing 48
AsyncRAT samples but did not add a second independent voter for the 9
own-YARA-only AsyncRAT samples, so cluster coverage did not improve.

### `verified_other`

- Count: **0**.
- `OtherMalwares.db`: **absent** (0 rows).
- Reason: only rat-king-parser votes on non-AsyncRAT families. A second
  family-specific voter (Malpedia/Elastic) is needed before promotion. The
  routing is implemented and covered by tests, but no real row exists yet.

### Contradictions (all `review`)

Every contradiction is own-YARA `AsyncRAT` vs rat-king fork. The aggregator
keeps `sug_fam` on the fork family so the clusterer partitions it away from
AsyncRAT.

| sha256 prefix | own_yara | rat_king_parser |
|---|---|---|
| `0dda9bf0db4f` | AsyncRAT strong | DcRat strong |
| `0eec59785a5e` | AsyncRAT strong | XWorm strong |
| `10102a03f784` | AsyncRAT strong | VenomRAT strong |
| `3d3362f1bd81` | AsyncRAT strong | XWorm strong |
| `53a8bd56d87f` | AsyncRAT strong | XWorm strong |
| `5e72a6fc387d` | AsyncRAT strong | XWorm strong |
| `7813085032d6` | AsyncRAT strong | XWorm strong |
| `9b6ba2ef41d4` | AsyncRAT strong | XWorm strong |
| `ab1d3375e08f` | AsyncRAT strong | XWorm strong |
| `ac7e7f562436` | AsyncRAT strong | XWorm strong |
| `b2a0f706a39d` | AsyncRAT strong | QuasarRAT strong |
| `cbd25e49ec37` | AsyncRAT strong | DcRat strong |
| `eb8b9a20fc7d` | AsyncRAT strong | XWorm strong |

The 2 QuasarRAT samples not hit by own YARA are `unverified` with
`sug_fam=QuasarRAT`; they have one strong voter but not two.

### Own-YARA hits

| Label status | Raw matches | Evidence `AsyncRAT` |
|---|---:|---:|
| `verified` | 48 | 48 |
| `review` | 13 | 13 |
| `unverified` | 9 | 9 |
| `rejected_non_dotnet` | 3 | 3 |
| `benign` | **0** | **0** |

- Benign hits: **0**.
- The 3 `rejected_non_dotnet` matches contain 7–8 wide AsyncRAT strings but no
  CLR header. Aggregator rule 1 still labels them `rejected_non_dotnet`.
- The rule is a lineage detector: it also hits XWorm/DcRat/VenomRAT/QuasarRAT
  forks. That is why those rows are `review`, not `verified`.

### Evidence table

- `label_evidence`: 360 rows (180 `rat_king_parser` + 180 `own_yara`).
- `lbl_src`: 170 `auto_aggregator`, 10 `hand_benign`.
- `is_gold`: 180 × `0`; `gold_fam`: 180 × NULL.
- Max `raw` length: 717 bytes (limit ~8 KB).
- `lbl_reason`: valid JSON on all 170 aggregated rows.

### Data-loss checks

- `Tools/MBDownloader/samples.db` SHA-256 unchanged.
- 180 label JSONs byte-identical to the pre-run digest.
- All 15 carved directories byte-identical to the pre-run digests.
- `DataSet.db` 180 rows, 0 NULL `cluster_id`.
- `AsyncRAT.db` 48 rows; `Benign.db` 10 rows; no missing or extra samples.
- Importer reruns preserve existing `split` values (all NULL today).

### Plain conclusion

The offline core works and is auditable, but it did **not** improve the
`verified` count or cluster coverage. It made the label state more explicit:
13 contradictions are now `review` with recorded voters, and 2 single-voter
QuasarRAT rows are `unverified` instead of `review`. To improve coverage:
add a second independent AsyncRAT voter (Elastic or Malpedia) and a
family-specific voter for `verified_other`.

### Tests

- `python3 tests/run_tests.py` → **25/25 pass**.
- Covers aggregator rules 1-10, abstention vs contradiction, independence
  counting, `verified_other` routing, no-family error, evidence upsert
  idempotency, marker requirement, empty class folder, final-label merge,
  clusterer family read, and the own-YARA 4-of-13 threshold.

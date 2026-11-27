# results.md — run reports

## Label coverage (Phase 0.4 offline core, 2026-11-27)

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

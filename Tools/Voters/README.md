# Label-evidence voters

Each voter writes `Data/Evidence/<sha256>/<source>.json` and a
`Data/Evidence/.<source>.done` marker. The aggregator requires all seven
markers; the importer requires them too.

## Pipeline order

```bash
python3 Tools/Labeling/labeler.py          # labels + rat_king_parser evidence
python3 Tools/Voters/OwnYara/own_yara.py
python3 Tools/Voters/Elastic/elastic_voter.py
python3 Tools/Voters/Malpedia/malpedia_voter.py
python3 Tools/Voters/MalwareBazaar/mb_voter.py
python3 Tools/Voters/DIE/die_voter.py
python3 Tools/Voters/YARAify/yaraify_voter.py
python3 Tools/Aggregator/aggregator.py
python3 Tools/Clustering/clusterer.py
# five carvers, then:
python3 Tools/Importer/importer.py
```

## Voters

| Source | Group | Scope | Requires |
|---|---|---|---|
| `rat_king_parser` | `yara:rat-king` | family (AsyncRAT) | `rat-king-parser` CLI |
| `own_yara` | `yara:own` | lineage (AsyncRAT) | `yara-python`; rule file in `OwnYara/` |
| `elastic` | `yara:elastic` | family, AsyncRAT lineage | `Reference/Elastic/rules/` |
| `malpedia` | `yara:malpedia` | family, AsyncRAT lineage | `Reference/Malpedia/rules/` |
| `malwarebazaar` | `metadata:mb` | family, AsyncRAT lineage | read-only `samples.db`; `signature` optional |
| `detect_it_easy` | `attribute:die` | attribute | `diec`; otherwise writes `unknown` |
| `yaraify` | `lookup:yaraify` | family/lineage | `YARAIFY_AUTH_KEY`; otherwise no_match |

`scope=lineage` means the AsyncRAT rule also hits AsyncRAT-derived forks. It
counts toward `verified` but cannot contradict a family-specific fork vote.
`verified_other` needs two family-scoped votes for the fork.

## External gaps

- `diec` is not installed, so `obf_lvl` remains `unknown`.
- `YARAIFY_AUTH_KEY` is not set, so YARAify writes no_match.
- The live MalwareBazaar ledger has no `signature` column, so its evidence is
  weak tags only.

Rules under `Reference/` are gitignored and are reference material only.

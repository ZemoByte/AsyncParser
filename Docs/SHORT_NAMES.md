# SHORT_NAMES.md — short name → full name map

Source: interview Q11, Q14, Q17. Short names are DB column names only, never model features.
Values come from the fixed vocabulary in `Docs/Plan.md` §4 (plus the `obfuscated:<Fingerprint>` extension from Q20).

| Short name | Full name | Where used | Example value |
|---|---|---|---|
| `lbl_sts` | `label_status` | `Data/DataSet.db` label index | `verified`, `verified_other`, `unverified`, `review`, `benign` |
| `sug_fam` | `suggested_family` | `Data/DataSet.db` label index | `DcRat`, `XWorm`, `Benign` |
| `obf_lvl` | `obfuscation_level` | `Data/DataSet.db` label index | `plain`, `obfuscated:ConfuserEx`, `unknown` |
| `lbl_src` | `label_source` | `Data/DataSet.db` label index | `auto_aggregator`, `human_gold`, `parser_only`, `hand_benign` |
| `lbl_reason` | `label_reason` | `Data/DataSet.db` label index | JSON: votes, contradictions, evidence count |
| `is_gold` | `is_gold` | `Data/DataSet.db` label index | `0`, `1` |
| `gold_fam` | `gold_family` | `Data/DataSet.db` label index | `AsyncRAT`, `XWorm`, `Benign` |

Value aliases:

| Short value | Full value | Field |
|---|---|---|
| `review` | `needs_human_review` | `lbl_sts` |
| `benign` | `benign` | `lbl_sts` |
| `verified_other` | `verified_other` | `lbl_sts` |

Notes:

- Style: lowercase snake_case, short but readable. No hyphen-case, no camelCase.
- Class DB names are **not** shortened: `AsyncRAT.db`, `OtherMalwares.db`, `Benign.db`.
- `hum_rev` was dropped (duplicate of `lbl_sts=review`) — see `Docs/DECISIONS.md` §11.

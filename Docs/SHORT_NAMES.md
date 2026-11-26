# SHORT_NAMES.md — short name → full name map

Source: interview Q11, Q14, Q17. Short names are DB column names only, never model features.
Values come from the fixed vocabulary in `Docs/Plan.md` §4 (plus the `obfuscated:<Fingerprint>` extension from Q20).

| Short name | Full name | Where used | Example value |
|---|---|---|---|
| `lbl_sts` | `label_status` | `Data/DataSet.db` label index | `verified`, `unverified`, `needs_human_review` |
| `hum_rev` | `needs_human_review` flag | `Data/DataSet.db` label index | `yes` / `no` |
| `sug_fam` | `suggested_family` | `Data/DataSet.db` label index | `DcRat` |
| `obf_lvl` | `obfuscation_level` | `Data/DataSet.db` label index | `plain`, `obfuscated:ConfuserEx`, `unknown` |

Value aliases:

| Short value | Full value | Field |
|---|---|---|
| `review` | `needs_human_review` | `lbl_sts` |

Notes:

- Style: lowercase snake_case, short but readable. No hyphen-case, no camelCase.
- Class DB names are **not** shortened: `AsyncRAT.db`, `OtherMalwares.db`, `Benign.db`.
- `hum_rev` was dropped (duplicate of `lbl_sts=review`) — see `Docs/DECISIONS.md` §11.

# OwnYara voter

Independent AsyncRAT client-string rule used as one `yara:own` evidence voter.
The rule file is `asyncrat_own.yar`; the voter is `own_yara.py`.

## Source

- `Reference/AsyncRAT-C-Sharp/` (gitignored reference checkout)
- Upstream: <https://github.com/NYAN-x-CAT/AsyncRAT-C-Sharp>
- Commit: `0f0cba4ec3985c38082c6abb3e1e01895120ffb6`
- Read as text only. Nothing is built, run or imported.

## Accepted strings (4 of 13 required)

| YARA id | Source file:line | Why it is stable |
|---|---|---|
| `$mac_error` | `Client/Algorithm/Aes256.cs:113` | Custom AES-GCM exception text, survives the builder |
| `$input_null` | `Client/Algorithm/Aes256.cs:52` | `nameof(input)` compiles to `input can not be null.` |
| `$wmi_computer` | `Client/Helper/Anti_Analysis.cs:57` | WMI VM check |
| `$sbie_dll` | `Client/Helper/Anti_Analysis.cs:96` | Sandboxie detection |
| `$miner_flag` | `Client/Helper/CheckMiner.cs:15` | Miner command-line check |
| `$wmi_process` | `Client/Helper/CheckMiner.cs:31` | Process command-line query |
| `$security_center` | `Client/Helper/Methods.cs:39` | WMI antivirus namespace |
| `$av_product` | `Client/Helper/Methods.cs:39` | WMI antivirus query |
| `$hwid_error` | `Client/Helper/HwidGen.cs:22` | HWID failure string |
| `$send_plugin` | `Client/Handle Packet/Packet.cs:44` | Plugin protocol command |
| `$save_plugin` | `Client/Handle Packet/Packet.cs:58` | Plugin protocol command |
| `$plugin_saved` | `Client/Handle Packet/Packet.cs:61` | Plugin debug string |
| `$client_info` | `Client/Helper/IdSender.cs:14` | Client-info packet command |

The condition is `uint16(0) == 0x5A4D and 4 of them`. Three strings do not
match; the synthetic test in `tests/test_own_yara.py` proves this.

## Rejected strings and why

| Rejected string | Reason |
|---|---|
| `AsyncClient` | Already in the rat-king AsyncRAT rule; would break independence |
| `masterKey can not be null or empty` | Already in the rat-king AsyncRAT rule |
| `get_ActivatePong`, `get_SslClient` | Already in Elastic `Windows_Trojan_Asyncrat_11a11ba1` |
| `schtasks /create /f /sc onlogon /rl highest` | In both rat-king and Elastic rules |
| `Stub.exe` | In Elastic `Windows_Trojan_Asyncrat_11a11ba1` |
| Reversed `Software\Microsoft\Windows\CurrentVersion\Run` | In Elastic `Windows_Trojan_Asyncrat_11a11ba1` |
| `vmware` | In Elastic `Windows_Trojan_Asyncrat_11a11ba1` |
| `%MTX%`, `%Ports%`, `%Hosts%`, `%Key%`, `%Certificate%`, `%Serversignature%` | Unconfigured-stub placeholders; the builder replaces them in shipped payloads |
| `NYAN CAT`, `127.0.0.1`, `0.5.7B`, `Test.exe` | DEBUG-only defaults, not present in normal built payloads |
| `Plugin.Plugin` | Type-name string; rejected to avoid metadata/type-name overlap |
| `user32.dll`, `kernel32.dll`, `ntdll.dll` | ImplMap names, which are model features (Q74) |
| `AppData`, `Test.exe` | Generic/debug values |

## Measurement (2026-11-27)

- Benign: **0 hits**.
- All 180: 73 raw matches.
- By parser label: 48 `verified`, 13 `review`, 9 `unverified`, 3
  `rejected_non_dotnet`.
- The 3 non-.NET matches contain 7–8 wide AsyncRAT strings but no CLR header;
  aggregator rule 1 still labels them `rejected_non_dotnet`.
- The 13 `review` matches are AsyncRAT-derived forks (XWorm, DcRat, VenomRAT,
  QuasarRAT). The rule is a lineage detector, not a family discriminator.
- After adding `scope=lineage` and the Elastic/Malpedia family voters, 9 XWorm
  forks became `verified_other`; 1 DcRat/VenomRAT conflict remains `review`.
  DcRat/QuasarRAT need a second family-scoped voter before promotion.

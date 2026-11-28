# AsyncRAT fork tree and MalwareBazaar availability

Source: `Reference/image-151.webp` (AsyncRAT fork tree). Availability was
measured on the MalwareBazaar full export plus recent tag lookups; it is
**selection metadata only and never a model feature**.

```
AsyncRAT
├── VenomRAT
│   ├── LMTeamRAT
│   ├── Alfa Red Fox
│   ├── Bawless Remote
│   ├── Shadow X RAT
│   ├── CollapseRAT
│   └── L838 RAT
├── DcRat
│   ├── EchoRAT
│   │   └── SapphireRAT
│   ├── GhOstRAT
│   ├── BitRAT
│   ├── CyberSpike
│   ├── Dumpling RAT
│   ├── ShaShenRAT
│   │   └── DarkRAT
│   ├── ShiningForceRAT
│   │   └── ArchosaurRAT
│   ├── Anarchy Panel
│   ├── CYB3R RAT
│   ├── SantaRAT
│   ├── PegasusRAT
│   ├── BoratRAT
│   ├── MagnumRAT
│   └── XieBroRAT
├── ElegyRAT
├── JasonRAT
├── NonEuclid
├── 3LoshRAT
├── PhoenixRAT
├── SynRAT
├── FluxusRAT
├── RiMAWI
├── HotRAT
└── NecrusRAT
```

## Availability

| family | parent | MB rows | queue target |
|---|---|---:|---:|
| DcRat | AsyncRAT | 5,496 | 50 |
| BitRAT | DcRat | 913 | 50 |
| VenomRAT | AsyncRAT | 184 | 50 |
| GhOstRAT | DcRat | 29 | 29 |
| DarkRAT | ShaShenRAT | 13 | 13 |
| BoratRAT | DcRat | 4 | 4 |
| HotRAT | AsyncRAT | 3 | 3 |
| XieBroRAT | DcRat | 2 | 2 |
| Anarchy Panel | DcRat | 1 | 1 |
| JasonRAT | AsyncRAT | 1 | 1 |
| PhoenixRAT | AsyncRAT | 1 | 1 |
| SynRAT | AsyncRAT | 1 | 1 |
| LMTeamRAT | VenomRAT | 0 | unavailable |
| Alfa Red Fox | VenomRAT | 0 | unavailable |
| Bawless Remote | VenomRAT | 0 | unavailable |
| Shadow X RAT | VenomRAT | 0 | unavailable |
| CollapseRAT | VenomRAT | 0 | unavailable |
| L838 RAT | VenomRAT | 0 | unavailable |
| EchoRAT | DcRat | 0 | unavailable |
| SapphireRAT | EchoRAT | 0 | unavailable |
| CyberSpike | DcRat | 0 | unavailable |
| Dumpling RAT | DcRat | 0 | unavailable |
| ShaShenRAT | DcRat | 0 | unavailable |
| ShiningForceRAT | DcRat | 0 | unavailable |
| ArchosaurRAT | ShiningForceRAT | 0 | unavailable |
| CYB3R RAT | DcRat | 0 | unavailable |
| SantaRAT | DcRat | 0 | unavailable |
| PegasusRAT | DcRat | 0 | unavailable |
| MagnumRAT | DcRat | 0 | unavailable |
| ElegyRAT | AsyncRAT | 0 | unavailable |
| NonEuclid | AsyncRAT | 0 | unavailable |
| 3LoshRAT | AsyncRAT | 0 | unavailable |
| FluxusRAT | AsyncRAT | 0 | unavailable |
| RiMAWI | AsyncRAT | 0 | unavailable |
| NecrusRAT | AsyncRAT | 0 | unavailable |

Twelve families are available; twenty-three are recorded as
`unavailable_mb` and are never downloaded or invented. Machine-readable:
`Tools/MBDownloader/families.json`.

## Measured queue (Phase 1.7)

Export signature/filename history plus recent tag fallback selected **181**
samples (target-capped at 205): DcRat 50, BitRAT 50, VenomRAT 50, GhOstRAT 16,
DarkRAT 7, BoratRAT 4, XieBroRAT 2, JasonRAT 1, PhoenixRAT 1. HotRAT,
Anarchy Panel and SynRAT had no export rows and no recent tag results;
GhOstRAT and DarkRAT fell short of their caps after TLSH-100 dedupe. Those
are measured shortages, not failures. The 23 unavailable families were never
queried for download.

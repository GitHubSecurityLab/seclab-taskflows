# PVR Triage Taskflows — Overview

> 30-minute sync reference. Last updated: 2026-03-03.

---

## The Problem

OSS maintainers get flooded with low-quality vulnerability reports via GitHub's Private Vulnerability Reporting (PVR). Most are vague, duplicated, or AI-generated. Reviewing each one manually is expensive.

---

## The Solution: 4 Taskflows

```
┌─────────────────────────────────────────────────────────────┐
│                        INBOX                                │
│         (GHSAs in triage state via GitHub PVR)              │
└───────────────────────┬─────────────────────────────────────┘
                        │
                        ▼
          ┌─────────────────────────┐
          │   pvr_triage_batch      │  "What's in my inbox?"
          │                         │
          │  • List triage GHSAs    │
          │  • Score each by        │
          │    severity + quality   │
          │  • Show Age (days)      │
          │  • Rank: highest first  │
          │    (oldest wins ties)   │
          └────────────┬────────────┘
                       │  ranked queue saved to REPORT_DIR
                       ▼
          ┌─────────────────────────┐
          │     pvr_triage          │  "Is this real?"
          │   (one advisory)        │
          │                         │
          │  Task 1: init           │
          │  Task 2: fetch & parse  │
          │  Task 3: quality gate ──┼──► fast-close? ──► skip to Task 7
          │  Task 4: verify code    │
          │  Task 5: write report   │
          │  Task 6: save report    │
          │  Task 7: draft response │
          │  Task 8: save + record  │
          └────────────┬────────────┘
                       │  _triage.md + _response_triage.md saved
                       ▼
             Maintainer reviews
             (edits draft if needed)
                       │
              ┌────────┴────────┐
              │                 │
              ▼                 ▼
   ┌──────────────────┐  ┌──────────────────────┐
   │   pvr_respond    │  │  pvr_respond_batch   │
   │  (one at a time) │  │  (all at once)       │
   │                  │  │                      │
   │  confirm-gated:  │  │  • list_pending      │
   │  accept (→draft) │  │  • for each:         │
   │  reject (→closed)│  │    - confirm-gated   │
   │                  │  │      state change    │
   │  mark as applied │  │    - mark as applied │
   │  post draft      │  │  • post drafts       │
   │  manually via UI │  │    manually via UI   │
   └──────────────────┘  └──────────────────────┘
```

---

## The Quality Gate (Task 3) — Key Logic

```
Reporter has history?
        │
        ├── HIGH TRUST ──────────────────► Always full verification
        │   (≥60% confirmed, ≤20% low)
        │
        ├── SKEPTICISM ──────────────────► Fast-close if 0 quality signals
        │   (≤20% confirmed OR ≥50% low)     (no prior report needed)
        │
        └── NORMAL / NEW ────────────────► Fast-close only if:
                                             0 quality signals
                                             AND prior similar report exists
```

**Quality signals:** file paths cited · PoC provided · line numbers cited

**Fast-close effect:** skip code verification → use canned response template requesting specifics

---

## Scoring (batch)

```
priority_score = severity_weight + quality_weight

severity:  critical=4  high=3  medium=2  low=1
quality:   +1 per signal (files, PoC, lines)  →  max +3

≥5  Triage Immediately
≥3  Triage Soon
 2  Triage
≤1  Likely Low Quality — Fast Close
```

---

## Output Files (all in REPORT_DIR)

| File | Written by | What it is |
|---|---|---|
| `GHSA-xxxx_triage.md` | pvr_triage | Full analysis report |
| `GHSA-xxxx_response_triage.md` | pvr_triage | Draft reply to reporter |
| `GHSA-xxxx_response_sent.md` | pvr_respond / batch | State-transition applied marker (idempotent) |
| `batch_queue_<repo>_<date>.md` | pvr_triage_batch | Ranked inbox table |

---

## Reporter Reputation (background)

Every completed triage records **verdict + quality** against the reporter's GitHub login in a local SQLite DB. Score feeds back into the next triage's quality gate automatically. No manual configuration.

---

## One-liner workflow

```bash
./scripts/run_pvr_triage.sh batch          owner/repo                   # see inbox
./scripts/run_pvr_triage.sh triage         owner/repo GHSA-xxx          # analyse one
./scripts/run_pvr_triage.sh respond        owner/repo GHSA-xxx accept   # accept one (triage→draft)
./scripts/run_pvr_triage.sh respond        owner/repo GHSA-xxx reject   # reject one (triage→closed)
./scripts/run_pvr_triage.sh respond_batch  owner/repo reject            # bulk state transition
# Then post each *_response_triage.md manually via the advisory URL
```

---

## Further reading

- [`taskflows/pvr_triage/README.md`](../src/seclab_taskflows/taskflows/pvr_triage/README.md) — full usage docs for all four taskflows
- [`taskflows/pvr_triage/SCORING.md`](../src/seclab_taskflows/taskflows/pvr_triage/SCORING.md) — authoritative scoring reference and fast-close decision tables

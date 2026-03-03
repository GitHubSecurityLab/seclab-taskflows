# PVR Triage Scoring Reference

This document describes every scoring decision made by the PVR triage taskflows: batch priority scoring, single-advisory quality signals, fast-close detection, and reporter reputation thresholds. All values are authoritative — they reflect the exact constants in the taskflow YAML and MCP server code.

---

## 1. Batch Priority Score (`pvr_triage_batch`)

Used to rank unprocessed draft advisories before triage.

### Severity weight

| Severity | Weight |
|---|---|
| critical | 4 |
| high | 3 |
| medium | 2 |
| low | 1 |
| unknown | 1 |

### Quality weight

Extracted from the advisory description text. Each signal present adds 1 point.

| Signal | Condition |
|---|---|
| `has_file_references` | Description mentions at least one specific source file path |
| `has_poc` | Description includes reproduction steps or exploit code |
| `has_line_numbers` | Description cites at least one line number |

### Formula

```
priority_score = severity_weight + quality_weight   (max: 7)
```

### Suggested action thresholds

| priority_score | Suggested action |
|---|---|
| ≥ 5 | Triage Immediately |
| ≥ 3 | Triage Soon |
| 2 | Triage |
| ≤ 1 | Likely Low Quality — Fast Close |

### Score reference table

| Severity | No signals | 1 signal | 2 signals | 3 signals |
|---|---|---|---|---|
| critical | 4 — Triage Soon | 5 — **Triage Immediately** | 6 — **Triage Immediately** | 7 — **Triage Immediately** |
| high | 3 — Triage Soon | 4 — Triage Soon | 5 — **Triage Immediately** | 6 — **Triage Immediately** |
| medium | 2 — Triage | 3 — Triage Soon | 4 — Triage Soon | 5 — **Triage Immediately** |
| low | 1 — Fast Close | 2 — Triage | 3 — Triage Soon | 4 — Triage Soon |

**Key observations:**
- A bare `critical` with no quality signals scores 4 — Triage Soon, not Triage Immediately.
- `high` needs at least two quality signals to reach Triage Immediately.
- `medium` needs all three quality signals to reach Triage Immediately.
- Any `low` severity report with no quality signals is Fast Close.

### Already-triaged advisories

Advisories with an existing `_triage.md` in `REPORT_DIR` are skipped entirely and do not appear in the scored queue. Their count is noted in the batch report summary.

---

## 2. Single-Advisory Quality Signals (`pvr_triage`)

The quality gate in Task 3 extracts the same three signals as the batch scorer, plus two additional ones used for the report quality rating.

| Signal | Used in |
|---|---|
| `has_file_references` | Fast-close, report quality rating |
| `has_line_numbers` | Fast-close, report quality rating |
| `has_poc` | Fast-close, report quality rating |
| `has_version_info` | Report quality rating only |
| `has_code_snippets` | Report quality rating only |

### Report quality rating

Assigned by the analyst in the report generation task.

| Rating | Criteria |
|---|---|
| High | Specific, accurate claims; verified PoC; correct file paths and line numbers |
| Medium | Partially accurate; some details wrong or missing |
| Low | Vague, speculative, or significantly inaccurate ("AI slop") |

---

## 3. Fast-Close Detection (`pvr_triage`)

The quality gate evaluates `fast_close` via a three-path decision tree gated on the reporter's reputation.

### Path A — High-trust reporter

| Condition | Result |
|---|---|
| `reporter_score.recommendation == "high trust"` | `fast_close = false` unconditionally |

High-trust reporters always receive full code verification regardless of quality signals.

### Path B — Skepticism reporter

| Condition | Result |
|---|---|
| `reporter_score.recommendation == "treat with skepticism"` **and** all three signals absent | `fast_close = true` |
| `reporter_score.recommendation == "treat with skepticism"` **and** any signal present | `fast_close = false` |

For skepticism reporters, a prior similar report is **not** required — the three absent quality signals alone are sufficient to trigger fast-close.

### Path C — Normal / no history

All four conditions must hold simultaneously:

1. `has_file_references` is false
2. `has_poc` is false
3. `has_line_numbers` is false
4. At least one similar report already exists in `REPORT_DIR` with verdict `UNCONFIRMED` or `CONFIRMED`

Conditions 1–3 alone are not sufficient — there must also be a prior report on a similar issue. A novel low-quality report for an unseen component proceeds to full verification.

### Reputation × fast-close summary matrix

| Reputation | No quality signals, no prior similar | No quality signals, prior similar exists | Any quality signal present |
|---|---|---|---|
| high trust | full verification | full verification | full verification |
| normal / no history | full verification | **fast-close** | full verification |
| treat with skepticism | **fast-close** | **fast-close** | full verification |

When `fast_close` is true, code verification is skipped entirely. The response draft uses the fast-close template (requests specific file path, line number, and reproduction steps).

---

## 4. Reporter Reputation (`reporter_reputation.py`)

Accumulated from every completed `pvr_triage` run. Keyed by GitHub login.

### Inputs per record

| Field | Values |
|---|---|
| verdict | CONFIRMED / UNCONFIRMED / INCONCLUSIVE |
| quality | High / Medium / Low |

### Score metrics

```
confirmed_pct = confirmed_count / total_reports
low_share     = Low_count / total_reports
```

### Recommendation thresholds

| Condition | Recommendation |
|---|---|
| confirmed_pct ≥ 0.60 **and** low_share ≤ 0.20 | high trust |
| confirmed_pct ≤ 0.20 **or** low_share ≥ 0.50 | treat with skepticism |
| Otherwise | normal |
| No history | no history |

### Effect on triage

The reputation score directly influences the fast-close decision (see Section 3):

- **high trust** — always forces full code verification.
- **treat with skepticism** — lowers the fast-close bar: only three absent quality signals are needed (no prior similar report required).
- **normal / no history** — standard four-condition fast-close applies.

The score also appears in the triage report under **Reporter Reputation** for maintainer awareness.

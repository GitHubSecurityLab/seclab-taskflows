# PVR Triage Scoring Reference

This document describes every scoring decision made by the PVR triage taskflows: batch priority scoring, single-advisory quality signals, fast-close detection, and reporter reputation thresholds. All values are authoritative — they reflect the exact constants in the taskflow YAML and MCP server code.

---

## 1. Batch Priority Score (`pvr_triage_batch`)

Used to rank unprocessed advisories in triage state before analysis.

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

---

## 5. Duplicate Detection (`compare_advisories`)

The `compare_advisories` tool detects duplicate or near-duplicate advisories in a repository's triage inbox before individual triage work begins.

### Fingerprint fields

Each advisory is fingerprinted using these structural fields:

| Field | Source |
|---|---|
| CWE IDs | Advisory `cwes` metadata |
| Package (ecosystem + name) | Advisory `vulnerabilities` metadata |
| Vulnerable version range | Advisory `vulnerabilities` metadata |
| File paths | Extracted from description text via regex |
| Normalized summary | Summary lowercased, non-alphanumeric stripped |

### Match levels

| Level | Condition |
|---|---|
| strong | Same package AND (same CWE or same files or same version range) |
| moderate | Same package alone, or same CWE AND same files (no package overlap) |
| weak | Any single field overlap (CWE only, or file paths only, etc.) |
| none | No field overlap |

### Clustering

Strong and moderate matches are clustered via union-find. The batch queue output shows each cluster with its member GHSAs and match reasons.

### Effect on triage

- Batch scorer: strong-match clusters get "Likely Duplicate -- Triage Best" suggested action
- Single-advisory triage: quality gate surfaces duplicate info but does NOT auto-close. Maintainers decide.
- Triage report: Duplicate/Prior Reports section prominently flags cluster membership

### Conservative design

Dedup detection is intentionally conservative:
- Only structural field overlap, no semantic similarity
- Never auto-closes advisories based on dedup alone
- Weak matches are surfaced as informational, not clustered
- Maintainer always makes the final accept/reject decision

---

## 6. Container Validation (`pvr_triage` Task 4b)

Optional automated validation using the SAST container. Gated by `PVR_CONTAINER_VALIDATION=true`.

### Validation steps

| Step | Tool | Purpose |
|---|---|---|
| Clone + checkout | git | Clone repo at affected version into container |
| SAST scan | semgrep | Scan reported files for vulnerability patterns |
| Reachability | pyan3 / cscope / rg | Trace call graph to determine if vuln function is reachable from public entry points |
| PoC reproduction | shell_exec | Best-effort reproduction of provided PoC steps (safe commands only) |
| Patch analysis | git diff | Compare affected version to HEAD to verify patch addresses the reported vulnerability |

### Effect on triage

- Reachability results factor into severity assessment (unreachable code = lower impact)
- SAST findings corroborate or contradict the reporter's claims
- PoC reproduction provides strongest evidence for confirmation
- Patch analysis validates whether a fix exists

### Prerequisites

- Docker installed and running
- `seclab-shell-sast:latest` image built (`scripts/build_container_images.sh`)
- `PVR_CONTAINER_VALIDATION=true` set in environment

# PVR Triage Taskflows

Tools for triaging GitHub Security Advisories submitted via [Private Vulnerability Reporting (PVR)](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability). The taskflows fetch a draft advisory, verify the claimed vulnerability against actual source code, score report quality, and generate a structured analysis and a ready-to-send response draft.

Three taskflows cover the full triage lifecycle:

| Taskflow | Purpose |
|---|---|
| `pvr_triage` | Deep-analyse one advisory end-to-end |
| `pvr_triage_batch` | Score an entire inbox and produce a ranked queue |
| `pvr_respond` | Post or save the response once you've reviewed the analysis |

---

## Requirements

- Python ≥ 3.9 (or Docker via `run_seclab_agent.sh`)
- `gh` CLI installed and authenticated
- A GitHub token with **`repo`** and **`security_events`** scopes
  - Write-back actions (`pvr_respond`) additionally require **`security_events` write** scope
- AI API credentials (`AI_API_TOKEN`, `AI_API_ENDPOINT`)

### Environment variables

| Variable | Required by | Description |
|---|---|---|
| `GH_TOKEN` | all | GitHub personal access token |
| `AI_API_TOKEN` | all | API key for the AI provider |
| `AI_API_ENDPOINT` | all | Model endpoint (defaults to `https://api.githubcopilot.com`) |
| `REPORT_DIR` | all | Directory where triage reports are written. Defaults to `./reports` |
| `LOG_DIR` | all | Directory for MCP server logs. Auto-detected via `platformdirs` if not set |
| `REPORTER_DB_DIR` | `pvr_triage` | Directory for the reporter reputation SQLite database. Auto-detected if not set |

A minimal `.env` for local use:

```
GH_TOKEN=ghp_...
AI_API_TOKEN=...
AI_API_ENDPOINT=https://api.githubcopilot.com
REPORT_DIR=/path/to/reports
LOG_DIR=/path/to/logs
```

---

## Taskflow 1 — Single advisory triage (`pvr_triage`)

Runs a full analysis on one draft GHSA and produces:

- A structured triage report saved to `REPORT_DIR/<GHSA-ID>_triage.md`
- A response draft saved to `REPORT_DIR/<GHSA-ID>_response_triage.md`
- A record in the reporter reputation database

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage \
  -g repo=owner/repo \
  -g ghsa=GHSA-xxxx-xxxx-xxxx
```

### What it does (8 tasks)

1. **Initialize** — clears the in-memory cache.
2. **Fetch & parse** — fetches the advisory from the GitHub API and extracts structured metadata: vulnerability type, affected component, file references, PoC quality signals, reporter credits.
3. **Quality gate** — calls `get_reporter_score` for the reporter's history and `find_similar_triage_reports` to detect duplicates. Computes a `fast_close` flag when the report has no file references, no PoC, no line numbers, *and* a similar report already exists. Fast-close skips deep code analysis.
4. **Code verification** — resolves the claimed version to a git tag/SHA, fetches the relevant source files, and checks whether the vulnerability pattern is actually present. After verifying at the claimed version, also checks HEAD to determine patch status (`still_vulnerable` / `patched` / `could_not_determine`). Skipped automatically when `fast_close` is true.
5. **Report generation** — writes a markdown report covering: Verdict, Code Verification, Severity Assessment, CVSS 3.1 assessment, Duplicate/Prior Reports, Patch Status, Report Quality, Reporter Reputation, and Recommendations.
6. **Save report** — writes the report to `REPORT_DIR/<GHSA-ID>_triage.md` and prints the path.
7. **Response draft** — drafts a plain-text reply to the reporter (≤200 words, no markdown headers) tailored to the verdict: acknowledge + credit for CONFIRMED, cite evidence for UNCONFIRMED, explain missing info for INCONCLUSIVE, or request specific details for fast-close.
8. **Update reputation + save response** — records the triage outcome in the reporter reputation database and saves the response draft to `REPORT_DIR/<GHSA-ID>_response_triage.md`.

### Report structure

```
## PVR Triage Analysis: GHSA-xxxx-xxxx-xxxx

**Repository:** owner/repo
**Claimed Severity:** high
**Vulnerability Type:** path traversal

### Verdict
**[CONFIRMED / UNCONFIRMED / INCONCLUSIVE]**

### Code Verification
### Severity Assessment
### CVSS Assessment
### Duplicate / Prior Reports
### Patch Status
### Report Quality
### Reporter Reputation
### Recommendations
```

---

## Taskflow 2 — Batch inbox scoring (`pvr_triage_batch`)

Lists draft advisories for a repository, scores each unprocessed one by priority, and saves a ranked markdown table. Advisories with an existing triage report in `REPORT_DIR` are skipped and their count is noted in the output.

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch \
  -g repo=owner/repo
```

### Output

Saved to `REPORT_DIR/batch_queue_<repo>_<date>.md`:

```markdown
# PVR Batch Triage Queue: owner/repo

| GHSA | Severity | Vuln Type | Quality Signals | Priority | Status | Suggested Action |
|------|----------|-----------|-----------------|----------|--------|-----------------|
| GHSA-... | high | SQL injection | PoC, Files | 6 | Not triaged | Triage Immediately |
| GHSA-... | medium | XSS | None | 1 | Not triaged | Likely Low Quality — Fast Close |
```

### Priority scoring

Advisories with an existing report in `REPORT_DIR` are skipped entirely. Only unprocessed advisories are scored:

```
priority_score = severity_weight + quality_weight

severity_weight:  critical=4  high=3  medium=2  low=1  unknown=1
quality_weight:   has_file_references(+1) + has_poc(+1) + has_line_numbers(+1)
```

**Suggested actions:**

| Score | Action |
|---|---|
| ≥ 5 | Triage Immediately |
| ≥ 3 | Triage Soon |
| 2 | Triage |
| ≤ 1 | Likely Low Quality — Fast Close |

---

## Taskflow 3 — Write-back (`pvr_respond`)

Loads an existing triage report and response draft from disk and executes the chosen action against the GitHub advisory API. All write-back calls are confirm-gated — the agent will prompt for confirmation before making any change.

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
  -g repo=owner/repo \
  -g ghsa=GHSA-xxxx-xxxx-xxxx \
  -g action=comment
```

### Actions

| `action` | API call | When to use |
|---|---|---|
| `comment` | Posts the response draft as a comment on the advisory | Default for all verdicts — sends your reply without changing state |
| `reject` | Sets advisory state to `rejected`, then posts the comment | Report is clearly invalid or low quality |
| `withdraw` | Sets advisory state to `withdrawn`, then posts the comment | Your own self-submitted draft that should be removed |

> **Note:** `pvr_respond` requires that `pvr_triage` has already been run for the GHSA, so that both `<GHSA-ID>_triage.md` and `<GHSA-ID>_response_triage.md` exist in `REPORT_DIR`.

### Confirm gate

The toolbox marks `reject_pvr_advisory`, `withdraw_pvr_advisory`, and `add_pvr_advisory_comment` as `confirm`-gated. The agent will print the verdict, quality rating, and full response draft, then ask for explicit confirmation before making any change to GitHub.

---

## Typical workflow

```
1. Run pvr_triage_batch to see what's in your inbox and prioritise.

2. For each advisory you want to analyse:
   Run pvr_triage.

3. Review the saved report in REPORT_DIR:
   - Check the Verdict and Code Verification sections.
   - Edit the response draft (_response_triage.md) if needed.

4. Run pvr_respond to send the response:
   - action=comment   → post reply only (advisory stays draft)
   - action=reject    → reject + post reply
   - action=withdraw  → withdraw + post reply
```

### Example session

```bash
# Step 1: score the inbox
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch \
  -g repo=acme/widget

# Step 2: triage the highest-priority advisory
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage \
  -g repo=acme/widget \
  -g ghsa=GHSA-1234-5678-abcd

# Step 3: review the output
cat reports/GHSA-1234-5678-abcd_triage.md
cat reports/GHSA-1234-5678-abcd_response_triage.md

# Step 4a: send a comment (most common — doesn't change advisory state)
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
  -g repo=acme/widget \
  -g ghsa=GHSA-1234-5678-abcd \
  -g action=comment

# Step 4b: or reject outright
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
  -g repo=acme/widget \
  -g ghsa=GHSA-1234-5678-abcd \
  -g action=reject
```

---

## Reporter reputation

Every completed `pvr_triage` run records the verdict and quality rating against the reporter's GitHub login in a local SQLite database (`REPORTER_DB_DIR/reporter_reputation.db`).

The quality gate in Task 3 of `pvr_triage` calls `get_reporter_score` automatically before any code analysis. The score summary appears in the report under **Reporter Reputation**.

**Reputation thresholds:**

| Condition | Recommendation |
|---|---|
| confirmed_pct ≥ 60% and Low-quality share ≤ 20% | high trust |
| confirmed_pct ≤ 20% or Low-quality share ≥ 50% | treat with skepticism |
| Otherwise | normal |

A "treat with skepticism" score alone does not trigger fast-close — it is informational. Fast-close is triggered only by the combination of missing quality signals *and* an existing duplicate report.

---

## Models

The taskflows use `seclab_taskflows.configs.model_config_pvr_triage`, which defines two model roles:

| Role | Used for | Default model |
|---|---|---|
| `triage` | Code verification and report generation | `claude-opus-4.6-1m` |
| `extraction` | Fetch/parse, quality gate, save tasks | `gpt-5-mini` |

Override the model config by setting `AI_API_ENDPOINT` and `AI_API_TOKEN` to point at a compatible provider.

---

## Output files

All files are written to `REPORT_DIR` (default: `./reports`).

| File | Written by | Contents |
|---|---|---|
| `<GHSA-ID>_triage.md` | `pvr_triage` task 6 | Full triage analysis report |
| `<GHSA-ID>_response_triage.md` | `pvr_triage` task 8 | Plain-text response draft for the reporter |
| `batch_queue_<repo>_<date>.md` | `pvr_triage_batch` task 3 | Ranked inbox table |

# PVR Triage Taskflows

Tools for triaging GitHub Security Advisories submitted via [Private Vulnerability Reporting (PVR)](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability). The taskflows fetch an advisory in triage state, verify the claimed vulnerability against actual source code, detect duplicate reports, score report quality, and generate a structured analysis and a ready-to-send response draft.

Four taskflows cover the full triage lifecycle:

| Taskflow | Purpose |
|---|---|
| `pvr_triage` | Deep-analyse one advisory end-to-end |
| `pvr_triage_batch` | Score an entire inbox and produce a ranked queue |
| `pvr_respond` | Post the response for one advisory once you've reviewed the analysis |
| `pvr_respond_batch` | Scan REPORT_DIR and post all pending response drafts in a single session |

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
| `PVR_CONTAINER_VALIDATION` | `pvr_triage` | Set to `true` to enable container-based SAST and reachability validation. Requires Docker. |
| `CONTAINER_WORKSPACE` | `pvr_triage` | Host directory mounted to `/workspace` in the SAST container. Optional. |

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

Runs a full analysis on one GHSA in triage state and produces:

- A structured triage report saved to `REPORT_DIR/<GHSA-ID>_triage.md`
- A response draft saved to `REPORT_DIR/<GHSA-ID>_response_triage.md`
- A record in the reporter reputation database

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage \
  -g repo=owner/repo \
  -g ghsa=GHSA-xxxx-xxxx-xxxx

# For testing with owner-created advisories (draft state instead of triage):
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage \
  -g repo=owner/repo \
  -g ghsa=GHSA-xxxx-xxxx-xxxx \
  -g state=draft
```

### What it does (9 tasks)

1. **Initialize** — clears the in-memory cache.
2. **Fetch & parse** — fetches the advisory from the GitHub API and extracts structured metadata: vulnerability type, affected component, file references, PoC quality signals, reporter credits. Also fetches the repository's SECURITY.md security policy (if one exists) for policy compliance evaluation.
3. **Quality gate** — calls `get_reporter_score` for the reporter's history, `find_similar_triage_reports` to find prior reports, and `compare_advisories` to detect duplicates in the current triage inbox. If a security policy was found, evaluates the report against it (scope, required elements, exclusions). Computes `fast_close` using a reputation-gated decision tree:
   - **high-trust reporter** → always `fast_close = false` (full verification).
   - **skepticism reporter** → `fast_close = true` when all three quality signals are absent (prior similar report not required).
   - **normal / no history** → `fast_close = true` only when all three signals are absent *and* a prior similar report exists.
   Fast-close skips deep code analysis. Duplicate detection results are surfaced in the report but never trigger automatic fast-close.
4. **Code verification** — resolves the claimed version to a git tag/SHA, fetches the relevant source files, and checks whether the vulnerability pattern is actually present. After verifying at the claimed version, also checks HEAD to determine patch status (`still_vulnerable` / `patched` / `could_not_determine`). Skipped automatically when `fast_close` is true.
5. **Container validation** (optional) — when `PVR_CONTAINER_VALIDATION=true`, clones the repo at the affected version into an isolated SAST container and performs: semgrep scanning on reported files, call graph / reachability analysis on reported functions (pyan3 for Python, cscope for C/C++), best-effort PoC reproduction, and patch diff analysis. Skipped when not enabled or when fast-close is active.
6. **Report generation** — writes a markdown report covering: Verdict, Code Verification, Validation Results (if container validation ran), Severity Assessment, CVSS 3.1 assessment, Duplicate/Prior Reports, Patch Status, Report Quality, Reporter Reputation, and Recommendations.
7. **Save report** — writes the report to `REPORT_DIR/<GHSA-ID>_triage.md` and prints the path.
8. **Response draft** — drafts a plain-text reply to the reporter (≤200 words, no markdown headers) tailored to the verdict: acknowledge + credit for CONFIRMED, cite evidence for UNCONFIRMED, explain missing info for INCONCLUSIVE, or request specific details for fast-close.
9. **Update reputation + save response** — records the triage outcome in the reporter reputation database and saves the response draft to `REPORT_DIR/<GHSA-ID>_response_triage.md`.

### Report structure

```
## PVR Triage Analysis: GHSA-xxxx-xxxx-xxxx

**Repository:** owner/repo
**Claimed Severity:** high
**Vulnerability Type:** path traversal

### Verdict
**[CONFIRMED / UNCONFIRMED / INCONCLUSIVE]**

### Code Verification
### Validation Results          (only when container validation ran)
### Severity Assessment
### CVSS Assessment
### Duplicate / Prior Reports
### Patch Status
### Security Policy Compliance  (only when repo has SECURITY.md)
### Report Quality
### Reporter Reputation
### Recommendations
```

---

## Taskflow 2 — Batch inbox scoring (`pvr_triage_batch`)

Lists advisories in triage state for a repository, scores each unprocessed one by priority, and saves a ranked markdown table. Advisories with an existing triage report in `REPORT_DIR` are skipped and their count is noted in the output.

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch \
  -g repo=owner/repo

# For testing with owner-created advisories (draft state instead of triage):
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch \
  -g repo=owner/repo \
  -g state=draft
```

### Output

Saved to `REPORT_DIR/batch_queue_<repo>_<date>.md`:

```markdown
# PVR Batch Triage Queue: owner/repo

| GHSA | Age (days) | Severity | Vuln Type | Quality Signals | Priority | Duplicates | Status | Suggested Action |
|------|------------|----------|-----------|-----------------|----------|------------|--------|-----------------|
| GHSA-... | 14 | high | SQL injection | PoC, Files | 6 | - | Not triaged | Triage Immediately |
| GHSA-... | 7 | high | SQL injection | PoC | 4 | GHSA-... [strong] | Not triaged | Likely Duplicate -- Triage Best |
| GHSA-... | 3 | medium | XSS | None | 1 | - | Not triaged | Likely Low Quality -- Fast Close |
```

Rows are sorted by priority score descending; ties are broken by `created_at` ascending (oldest advisory first).

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

Loads an existing triage report and applies the chosen state transition to the GitHub advisory. All write-back calls are confirm-gated — the agent will prompt for confirmation before making any change.

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
  -g repo=owner/repo \
  -g ghsa=GHSA-xxxx-xxxx-xxxx \
  -g action=accept
```

### Actions

| `action` | API call | When to use |
|---|---|---|
| `accept` | Sets advisory state to `draft` (triage → draft) | Vulnerability confirmed — maintainer intends to publish an advisory |
| `reject` | Sets advisory state to `closed` | Report is clearly invalid or low quality |

> **Note:** `pvr_respond` requires that `pvr_triage` has already been run for the GHSA so that `<GHSA-ID>_triage.md` and `<GHSA-ID>_response_triage.md` exist in `REPORT_DIR`.

> **Posting the response:** The GitHub REST API has no comments endpoint for security advisories. After running `pvr_respond`, post the response draft manually via the advisory URL. See [`MANUAL_RESPONSE.md`](MANUAL_RESPONSE.md) for instructions and language.

### Confirm gate

The toolbox marks `accept_pvr_advisory` and `reject_pvr_advisory` as `confirm`-gated. The agent will print the verdict and summary, then ask for explicit confirmation before making any change to GitHub.

After a successful state transition, `pvr_respond` calls `mark_response_sent` to create a `<GHSA-ID>_response_sent.md` marker so `pvr_respond_batch` will skip this advisory in future runs.

---

## Taskflow 4 — Bulk respond (`pvr_respond_batch`)

Scans `REPORT_DIR` for advisories that have a response draft (`*_response_triage.md`) but no applied marker (`*_response_sent.md`), and applies the chosen state transition to each in a single session.

```bash
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond_batch \
  -g repo=owner/repo \
  -g action=reject

# or via the helper script:
./scripts/run_pvr_triage.sh respond_batch owner/repo reject
```

### How it works

**Task 1** calls `list_pending_responses` (local read-only, no confirm gate) to find all pending advisories and prints a summary table. If there are none it stops immediately.

**Task 2** iterates over every pending entry:
1. Reads the triage report from disk.
2. Prints a per-item summary (GHSA, verdict).
3. Executes the chosen action (`accept` / `reject`) via the confirm-gated write-back tool.
4. On success, calls `mark_response_sent` to create a `*_response_sent.md` marker so the advisory is skipped in future runs.

Prints a final count and a reminder to post each response draft manually.

### Applied markers

`pvr_respond` also calls `mark_response_sent` after a successful state transition, keeping single-advisory and bulk runs in sync. Once a marker exists, neither `pvr_respond` nor `pvr_respond_batch` will re-process it.

---

## Duplicate Detection

Both `pvr_triage` and `pvr_triage_batch` use the `compare_advisories` tool to detect duplicate or near-duplicate advisories in the triage inbox.

**How it works:** Dedup uses two layers:

1. **Structural comparison** (`compare_advisories` tool) -- fingerprints each advisory by CWE IDs, package, version range, and file paths from the description. Pairs with overlapping fields are flagged:

| Level | Meaning |
|---|---|
| strong | Same package AND (same CWE or same files or same version range) |
| moderate | Same package alone, or CWE + files overlap |
| weak | Any single field overlap |

2. **Semantic analysis** (agent judgment) -- the agent reads all advisory descriptions and identifies groups that describe the same vulnerability even when structural metadata differs. Catches duplicates that use different wording, cite different CWEs, or lack structured metadata entirely (common with low-quality reports). A structural match of "none" means insufficient metadata, not necessarily distinct vulnerabilities.

**In batch mode:** The scored queue table includes a Duplicates column showing cluster membership. Strong structural matches get the "Likely Duplicate -- Triage Best" action. Semantic duplicates identified by the agent are added with match level "semantic".

**In single-advisory mode:** The quality gate checks for both structural and semantic duplicates and surfaces the info in the report, but never auto-closes. Maintainers always decide.

See [SCORING.md](SCORING.md) Section 5 for full details.

---

## Container Validation (optional)

When `PVR_CONTAINER_VALIDATION=true`, `pvr_triage` performs automated validation in an isolated Docker container running the SAST image (`seclab-shell-sast:latest`).

### What it does

1. **Clone + checkout** — clones the repo and checks out the affected version.
2. **SAST scan** — runs semgrep on reported file paths.
3. **Reachability analysis** — traces the call graph to determine if the reported function is reachable from public entry points (pyan3 for Python, cscope for C/C++, grep-based for others).
4. **PoC reproduction** — attempts best-effort reproduction of provided PoC steps (safe commands only; no network access or destructive operations).
5. **Patch analysis** — diffs the affected version against HEAD to verify whether a fix exists and addresses the reported vulnerability.

### Prerequisites

```bash
# Build the SAST container image
./scripts/build_container_images.sh

# Enable container validation
export PVR_CONTAINER_VALIDATION=true
```

### Effect on triage

- Unreachable functions → severity downgrade in the assessment
- Semgrep findings → corroborate or contradict reporter claims
- Successful PoC reproduction → strongest confirmation evidence
- Results appear in the **Validation Results** section of the triage report

See [SCORING.md](SCORING.md) Section 6 for full details.

---

## Typical workflow

```
1. Run pvr_triage_batch to see what's in your inbox and prioritise.

2. For each advisory you want to analyse:
   Run pvr_triage.

3. Review the saved report in REPORT_DIR:
   - Check the Verdict and Code Verification sections.
   - Edit the response draft (_response_triage.md) if needed.

4a. Apply a state transition with pvr_respond:
    - action=accept    → move to draft (triage → draft)
    - action=reject    → close (triage → closed)
    Then post the response draft manually via the advisory URL.

4b. Or apply state transitions to all pending advisories at once with pvr_respond_batch:
    Scans REPORT_DIR for pending entries (no _response_sent.md marker)
    and applies the chosen action to all of them in one session.
    Then post each response draft manually via the advisory URL.
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

# Step 4a: accept (triage → draft) — vulnerability confirmed
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
  -g repo=acme/widget \
  -g ghsa=GHSA-1234-5678-abcd \
  -g action=accept

# Step 4b: or reject (triage → closed) — invalid or low-quality report
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond \
  -g repo=acme/widget \
  -g ghsa=GHSA-1234-5678-abcd \
  -g action=reject

# Step 4c: or apply state transitions to all pending advisories at once
python -m seclab_taskflow_agent \
  -t seclab_taskflows.taskflows.pvr_triage.pvr_respond_batch \
  -g repo=acme/widget \
  -g action=reject

# Step 5: post each response draft manually via the advisory URL
# See taskflows/pvr_triage/MANUAL_RESPONSE.md for instructions
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

Reputation directly gates the fast-close decision. See [SCORING.md](SCORING.md) Section 3 for the full three-path decision table and reputation × fast-close matrix.

---

## Models

The taskflows use `seclab_taskflows.configs.model_config_pvr_triage`, which defines two model roles:

| Role | Used for | Default model |
|---|---|---|
| `triage` | Code verification and report generation | `claude-opus-4.6` |
| `extraction` | Fetch/parse, quality gate, save tasks | `gpt-5-mini` |

Override the model config by setting `AI_API_ENDPOINT` and `AI_API_TOKEN` to point at a compatible provider.

---

## Output files

All files are written to `REPORT_DIR` (default: `./reports`).

| File | Written by | Contents |
|---|---|---|
| `<GHSA-ID>_triage.md` | `pvr_triage` task 6 | Full triage analysis report |
| `<GHSA-ID>_response_triage.md` | `pvr_triage` task 8 | Plain-text response draft for the reporter |
| `<GHSA-ID>_response_sent.md` | `pvr_respond` / `pvr_respond_batch` | Marker: state transition applied (contains ISO timestamp); post draft manually |
| `batch_queue_<repo>_<date>.md` | `pvr_triage_batch` task 3 | Ranked inbox table with Age column |

---

## Globals reference

| Global | Taskflow | Default | Description |
|---|---|---|---|
| `repo` | all | (required) | Repository in `owner/repo` format |
| `ghsa` | `pvr_triage`, `pvr_respond` | (required) | GHSA ID of the advisory |
| `action` | `pvr_respond`, `pvr_respond_batch` | (required) | `accept` or `reject` |
| `state` | `pvr_triage`, `pvr_triage_batch` | `triage` | Advisory state to filter. Use `draft` for testing with owner-created advisories. |

---

## Demo script

A demo script is included for live testing against a test repository:

```bash
# Test all MCP tools against live API (no AI calls, fast):
./scripts/demo_pvr_triage.sh tools

# Run batch scoring:
./scripts/demo_pvr_triage.sh batch

# Run full triage on a specific advisory:
./scripts/demo_pvr_triage.sh triage GHSA-xxxx-xxxx-xxxx

# Run everything:
./scripts/demo_pvr_triage.sh all
```

The demo script uses `gh auth token` for GitHub API access and
`passage show github/capi-token` for the AI endpoint token. Override
with `GH_TOKEN` and `AI_API_TOKEN` environment variables.

Set `ADVISORY_STATE=triage` to test against real PVR submissions
(default is `draft` for the test repository).

# Local Setup Guide

Quick guide for running seclab-taskflows locally without Codespaces.

## Prerequisites

- Python 3.10-3.13 (required by seclab-taskflow-agent; Python 3.14 not yet supported)
- GitHub CLI (`gh`) - [install here](https://cli.github.com/)
- GitHub authentication via `gh auth login`
- A Copilot API token set in `AI_API_TOKEN`

## Setup

1. **Authenticate with GitHub:**

```bash
gh auth login
```

2. **Set your Copilot API token:**

```bash
export AI_API_TOKEN=<your-copilot-api-token>
```

3. **Run setup script:**

```bash
./scripts/setup_local.sh
```

This creates a `.venv` and installs all dependencies.

**Optional:** Set custom AI endpoint (defaults to GitHub Copilot):
```bash
# Default (GitHub Copilot) - Claude Opus 4.6 + GPT-5-mini
export AI_API_ENDPOINT="https://api.githubcopilot.com"

# Or use GitHub Models (OpenAI models only, requires temperature=1)
export AI_API_ENDPOINT="https://models.github.ai/inference"
```

## Running Audits

### Single repo

```bash
./scripts/run_audit_local.sh owner/repo
```

Example:
```bash
./scripts/run_audit_local.sh owner/repo
```

### Multiple repos (cross-repo audit)

Pass multiple repos as positional arguments. Steps 1–4 run per repo, then a single cross-repo audit step (step 5) audits all issues across the workspace simultaneously, enabling the agent to trace inter-service data flows and assess exploitability in a multi-repo context.

```bash
./scripts/run_audit_local.sh owner/repo-a owner/repo-b
```

The workspace name is derived by joining repo names with `+` (e.g. `owner_repo-a+owner_repo-b`). If the combined name exceeds 60 characters it is truncated to `<first_repo>+<N>repos`.

**Note:** Audits can take several hours and make many AI requests. Uses Claude Opus 4.6 (1M context window) for code analysis and GPT-5-mini for general tasks and triage. A GitHub Copilot Pro account is recommended.

## Results

Results are stored in timestamped directories:
```
~/.local/share/seclab-taskflow-agent/audits/<repo>_<timestamp>/
```

Each audit creates:
- `data/repo_context.db` - SQLite database with audit results
- `data/vulns/` - Individual vulnerability reports
- `logs/audit.log` - Complete audit log
- `agent_out/` - Consolidated package with all outputs

View results in the `audit_result` table. Rows with `has_vulnerability=true` are most likely genuine vulnerabilities.

## Troubleshooting

**Missing dependencies:**
```bash
source .venv/bin/activate
pip install -e .
```

**Token issues:**
```bash
# Verify AI_API_TOKEN is set
echo $AI_API_TOKEN

# Verify gh CLI is authenticated
gh auth status

# Re-authenticate if needed
gh auth login
```

**View results manually:**
```bash
# Find your most recent audit
ls -lt ~/.local/share/seclab-taskflow-agent/audits/

# View results from specific audit
sqlite3 ~/.local/share/seclab-taskflow-agent/audits/<repo>_<timestamp>/agent_out/repo_context.db \
  'SELECT * FROM audit_result WHERE has_vulnerability = 1;'
```

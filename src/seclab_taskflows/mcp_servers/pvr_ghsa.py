# PVR GHSA MCP Server
#
# Tools for fetching and parsing draft GitHub Security Advisories
# submitted via Private Vulnerability Reporting (PVR).
# Uses the gh CLI for all GitHub API calls.

import json
import logging
import os
import subprocess
from pathlib import Path

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name

REPORT_DIR = Path(os.getenv("REPORT_DIR", "reports"))

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_pvr_ghsa.log"),
    filemode="a",
)

mcp = FastMCP("PVRAdvisories")


def _gh_api(path: str, method: str = "GET") -> tuple[dict | list | None, str | None]:
    """
    Call the GitHub REST API via the gh CLI.

    Returns (data, error). On success data is the parsed JSON response and
    error is None. On failure data is None and error is a string.
    """
    cmd = ["gh", "api", "--method", method, path]
    env = os.environ.copy()

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return None, "gh api call timed out"
    except FileNotFoundError:
        return None, "gh CLI not found in PATH"

    if result.returncode != 0:
        stderr = result.stderr.strip()
        stdout = result.stdout.strip()
        msg = stderr or stdout or f"gh exited with code {result.returncode}"
        logging.error("gh api error: %s", msg)
        return None, msg

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError as e:
        return None, f"JSON parse error: {e}"

    return data, None


def _parse_advisory(raw: dict) -> dict:
    """
    Extract the fields relevant to PVR triage from a raw advisory API response.
    Separates description text from structured metadata.
    """
    vulns = []
    for v in raw.get("vulnerabilities") or []:
        pkg = v.get("package") or {}
        vulns.append({
            "ecosystem": pkg.get("ecosystem", ""),
            "package": pkg.get("name", ""),
            "vulnerable_versions": v.get("vulnerable_version_range", ""),
            "patched_versions": v.get("patched_versions", ""),
        })

    cwes = [c.get("cwe_id", "") for c in (raw.get("cwes") or [])]

    credits_ = [
        {"login": c.get("user", {}).get("login", ""), "type": c.get("type", "")}
        for c in (raw.get("credits_detailed") or [])
    ]

    submission = raw.get("submission") or {}

    return {
        "ghsa_id": raw.get("ghsa_id", ""),
        "cve_id": raw.get("cve_id"),
        "html_url": raw.get("html_url", ""),
        "state": raw.get("state", ""),
        "severity": raw.get("severity", ""),
        "summary": raw.get("summary", ""),
        # Full description returned separately so metadata stays compact
        "description": raw.get("description", ""),
        "vulnerabilities": vulns,
        "cwes": cwes,
        "credits": credits_,
        # submission.accepted=true means this arrived via PVR
        "pvr_submission": {
            "via_pvr": bool(submission),
            "accepted": submission.get("accepted", False),
        },
        "created_at": raw.get("created_at", ""),
        "updated_at": raw.get("updated_at", ""),
        "collaborating_users": [
            u.get("login", "") for u in (raw.get("collaborating_users") or [])
        ],
    }


@mcp.tool()
def fetch_pvr_advisory(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
) -> str:
    """
    Fetch a single repository security advisory by GHSA ID.

    Returns structured advisory metadata and the full description text.
    Works for draft advisories (requires repo or security_events scope on GH_TOKEN).
    """
    path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    data, err = _gh_api(path)
    if err:
        return f"Error fetching advisory {ghsa_id}: {err}"
    parsed = _parse_advisory(data)
    return json.dumps(parsed, indent=2)


@mcp.tool()
def list_pvr_advisories(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    state: str = Field(
        default="draft",
        description="Advisory state to filter by: draft, published, rejected, or withdrawn. Default: draft",
    ),
) -> str:
    """
    List repository security advisories, defaulting to draft state.

    Returns a summary list (no description text). Each entry includes
    ghsa_id, severity, summary, state, pvr_submission, and created_at.
    """
    path = f"/repos/{owner}/{repo}/security-advisories?state={state}&per_page=100"
    data, err = _gh_api(path)
    if err:
        return f"Error listing advisories: {err}"
    if not isinstance(data, list):
        return f"Unexpected response: {data}"

    results = []
    for raw in data:
        submission = raw.get("submission") or {}
        results.append({
            "ghsa_id": raw.get("ghsa_id", ""),
            "severity": raw.get("severity", ""),
            "summary": raw.get("summary", ""),
            "state": raw.get("state", ""),
            "pvr_submission": {
                "via_pvr": bool(submission),
                "accepted": submission.get("accepted", False),
            },
            "created_at": raw.get("created_at", ""),
        })

    if not results:
        return f"No {state} advisories found for {owner}/{repo}."
    return json.dumps(results, indent=2)


@mcp.tool()
def resolve_version_ref(
    owner: str = Field(description="Repository owner"),
    repo: str = Field(description="Repository name"),
    version: str = Field(
        description="Version string to resolve, e.g. '1.25.4' or 'v1.25.4'. "
                    "Will try matching git tags directly and with a 'v' prefix."
    ),
) -> str:
    """
    Resolve a version string to a git commit SHA and tag name.

    Returns the tag name and commit SHA if found.
    """
    # Try both bare version and v-prefixed tag
    candidates = [version, f"v{version}"] if not version.startswith("v") else [version, version[1:]]

    for tag in candidates:
        path = f"/repos/{owner}/{repo}/git/refs/tags/{tag}"
        data, err = _gh_api(path)
        if err or not data:
            continue
        # Lightweight tags point directly to a commit; annotated tags point to a tag object
        obj = data.get("object", {})
        ref_sha = obj.get("sha", "")
        ref_type = obj.get("type", "")

        if ref_type == "tag":
            # Annotated tag: dereference to the commit
            tag_path = f"/repos/{owner}/{repo}/git/tags/{ref_sha}"
            tag_data, tag_err = _gh_api(tag_path)
            if not tag_err and tag_data:
                commit_sha = tag_data.get("object", {}).get("sha", "")
                return json.dumps({"tag": tag, "commit_sha": commit_sha, "type": "annotated"})
        elif ref_type == "commit":
            return json.dumps({"tag": tag, "commit_sha": ref_sha, "type": "lightweight"})

    return f"Could not resolve version '{version}' to a tag in {owner}/{repo}."


@mcp.tool()
def fetch_file_at_ref(
    owner: str = Field(description="Repository owner"),
    repo: str = Field(description="Repository name"),
    path: str = Field(description="File path within the repository"),
    ref: str = Field(description="Git ref (commit SHA, tag, or branch) to fetch the file at"),
    start_line: int = Field(default=1, description="First line to return (1-indexed)"),
    length: int = Field(default=50, description="Number of lines to return"),
) -> str:
    """
    Fetch a range of lines from a file at a specific git ref (commit SHA or tag).
    """
    # Use gh api with the ref query parameter
    cmd = [
        "gh", "api",
        "--method", "GET",
        f"/repos/{owner}/{repo}/contents/{path}",
        "-f", f"ref={ref}",
        "-H", "Accept: application/vnd.github.raw+json",
    ]
    env = os.environ.copy()

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    except subprocess.TimeoutExpired:
        return "Error: gh api call timed out"
    except FileNotFoundError:
        return "Error: gh CLI not found in PATH"

    if result.returncode != 0:
        return f"Error fetching {path}@{ref}: {result.stderr.strip() or result.stdout.strip()}"

    lines = result.stdout.splitlines()
    if start_line < 1:
        start_line = 1
    if length < 1:
        length = 50
    chunk = lines[start_line - 1: start_line - 1 + length]
    if not chunk:
        return f"No lines in range {start_line}-{start_line + length - 1} in {path}@{ref}"
    return "\n".join(f"{start_line + i}: {line}" for i, line in enumerate(chunk))


@mcp.tool()
def save_triage_report(
    ghsa_id: str = Field(description="GHSA ID, used as the filename stem, e.g. GHSA-xxxx-xxxx-xxxx"),
    report: str = Field(description="Full markdown report content to write to disk"),
) -> str:
    """
    Write the triage report to a markdown file in the report output directory.

    The file is written to REPORT_DIR/{ghsa_id}_triage.md.
    REPORT_DIR defaults to './reports' and can be overridden via the REPORT_DIR
    environment variable. Returns the absolute path of the written file.
    """
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    # Sanitize the GHSA ID to prevent path traversal
    safe_name = "".join(c for c in ghsa_id if c.isalnum() or c in "-_")
    out_path = REPORT_DIR / f"{safe_name}_triage.md"
    # The agent sometimes passes the report as a JSON-encoded string
    # (with outer quotes and escape sequences). Decode it if so.
    content = report
    if content.startswith('"') and content.endswith('"'):
        try:
            content = json.loads(content)
        except json.JSONDecodeError:
            pass
    out_path.write_text(content, encoding="utf-8")
    logging.info("Triage report written to %s", out_path)
    return str(out_path.resolve())


if __name__ == "__main__":
    mcp.run(show_banner=False)

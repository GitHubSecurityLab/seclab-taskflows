# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# PVR GHSA MCP Server
#
# Tools for fetching and parsing draft GitHub Security Advisories
# submitted via Private Vulnerability Reporting (PVR).
# Uses the gh CLI for all GitHub API calls.

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name

_raw_report_dir = os.getenv("REPORT_DIR")
REPORT_DIR = Path(_raw_report_dir) if _raw_report_dir and _raw_report_dir.strip() else Path("reports")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_pvr_ghsa.log"),
    filemode="a",
)

mcp = FastMCP("PVRAdvisories")


def _gh_api(
    path: str,
    method: str = "GET",
    body: dict | None = None,
) -> tuple[dict | list | None, str | None]:
    """
    Call the GitHub REST API via the gh CLI.

    Returns (data, error). On success data is the parsed JSON response and
    error is None. On failure data is None and error is a string.
    If body is provided it is passed as JSON via stdin (--input -).
    """
    cmd = ["gh", "api", "--method", method, path]
    env = os.environ.copy()
    stdin_data = None

    if body is not None:
        cmd += ["--input", "-"]
        stdin_data = json.dumps(body)

    try:
        result = subprocess.run(
            cmd,
            input=stdin_data,
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

    Returns a JSON summary list (no description text). Each entry includes
    ghsa_id, severity, summary, state, pvr_submission, and created_at.
    Returns an empty JSON list when no advisories are found.
    Paginates automatically through all pages (100 items per page).
    """
    base_path = f"/repos/{owner}/{repo}/security-advisories?state={state}&per_page=100"
    all_data: list = []
    page = 1
    max_pages = 50  # hard cap: 5000 advisories max
    while page <= max_pages:
        data, err = _gh_api(f"{base_path}&page={page}")
        if err:
            return f"Error listing advisories: {err}"
        if not isinstance(data, list):
            return f"Unexpected response: {data}"
        if not data:
            break
        all_data.extend(data)
        if len(data) < 100:
            break
        page += 1

    results = []
    for raw in all_data:
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
    length = min(length, 500)  # cap to avoid returning enormous files
    if start_line > len(lines):
        return f"start_line {start_line} exceeds file length ({len(lines)} lines) in {path}@{ref}"
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
    if not safe_name:
        return "Error: ghsa_id produced an empty filename after sanitization"
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


def _post_advisory_comment(owner: str, repo: str, ghsa_id: str, body: str) -> str:
    """
    Internal helper: post a comment on a security advisory.

    Attempts to use the GitHub advisory comments API. If that endpoint is not
    available, falls back to appending a '## Maintainer Response' section to the
    advisory description instead. Called by both the MCP tool wrapper and the
    reject/withdraw tools so they all share the same logic without going through
    the FunctionTool wrapper.
    """
    comment_path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}/comments"
    cmd = [
        "gh", "api",
        "--method", "POST",
        comment_path,
        "--input", "-",
    ]
    env = os.environ.copy()
    try:
        result = subprocess.run(
            cmd,
            input=json.dumps({"body": body}),
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
    except subprocess.TimeoutExpired:
        return "Error: gh api call timed out"
    except FileNotFoundError:
        return "Error: gh CLI not found in PATH"

    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            url = data.get("html_url", data.get("url", "posted"))
            return f"Comment posted: {url}"
        except json.JSONDecodeError:
            return "Comment posted."

    # Fall back: append maintainer response to advisory description
    logging.warning(
        "Advisory comments API unavailable (%s); falling back to description update",
        result.stderr.strip(),
    )
    adv_path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    adv_data, adv_err = _gh_api(adv_path)
    if adv_err:
        return f"Error fetching advisory for fallback comment: {adv_err}"
    existing_desc = adv_data.get("description", "") or ""
    updated_desc = existing_desc + f"\n\n## Maintainer Response\n\n{body}"
    _, patch_err = _gh_api(adv_path, method="PATCH", body={"description": updated_desc})
    if patch_err:
        return f"Error updating advisory description: {patch_err}"
    return "Comment appended to advisory description (comments API unavailable)."


@mcp.tool()
def reject_pvr_advisory(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
    comment: str = Field(description="Explanation comment to post on the advisory"),
) -> str:
    """
    Reject a draft security advisory and post a comment explaining the decision.

    Sets the advisory state to 'rejected' via the GitHub API, then posts a
    comment with the provided explanation. Requires a GH_TOKEN with
    security_events write scope.
    """
    path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    _, err = _gh_api(path, method="PATCH", body={"state": "rejected"})
    if err:
        return f"Error rejecting advisory {ghsa_id}: {err}"
    result = _post_advisory_comment(owner, repo, ghsa_id, comment)
    return f"Advisory {ghsa_id} rejected. Comment: {result}"


@mcp.tool()
def withdraw_pvr_advisory(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
    comment: str = Field(description="Explanation comment to post on the advisory"),
) -> str:
    """
    Withdraw a draft security advisory (for self-submitted drafts) and post a comment.

    Sets the advisory state to 'withdrawn' via the GitHub API, then posts a
    comment with the provided explanation. Requires a GH_TOKEN with
    security_events write scope.
    """
    path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    _, err = _gh_api(path, method="PATCH", body={"state": "withdrawn"})
    if err:
        return f"Error withdrawing advisory {ghsa_id}: {err}"
    result = _post_advisory_comment(owner, repo, ghsa_id, comment)
    return f"Advisory {ghsa_id} withdrawn. Comment: {result}"


@mcp.tool()
def add_pvr_advisory_comment(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
    body: str = Field(description="Comment text to post on the advisory"),
) -> str:
    """
    Post a comment on a security advisory.

    Attempts to use the GitHub advisory comments API. If that endpoint is not
    available, falls back to appending a '## Maintainer Response' section to the
    advisory description instead.
    """
    return _post_advisory_comment(owner, repo, ghsa_id, body)


@mcp.tool()
def find_similar_triage_reports(
    vuln_type: str = Field(description="Vulnerability class to search for, e.g. 'path traversal', 'XSS'"),
    affected_component: str = Field(description="Component, endpoint, or feature to search for"),
) -> str:
    """
    Search existing triage reports for similar vulnerability types and affected components.

    Scans REPORT_DIR for *_triage.md files and performs case-insensitive substring
    matching across the full file content for vuln_type and/or affected_component.
    A report matches if at least one non-empty search term is found anywhere in the file.
    Returns an empty list if both terms are empty/whitespace.
    Returns a JSON list of matching reports with ghsa_id, verdict, quality, and path.
    """
    if not REPORT_DIR.exists():
        return json.dumps([])

    vuln_lower = vuln_type.strip().lower()
    component_lower = affected_component.strip().lower()

    # Both terms empty → no meaningful search possible
    if not vuln_lower and not component_lower:
        return json.dumps([])

    matches = []

    for report_path in sorted(REPORT_DIR.glob("*_triage.md")):
        # Skip batch queue reports and response drafts — only match individual GHSA triage reports
        stem = report_path.stem  # e.g. "GHSA-xxxx-xxxx-xxxx_triage"
        if stem.startswith("batch_queue_") or stem.endswith("_response_triage"):
            continue
        try:
            content = report_path.read_text(encoding="utf-8")
        except OSError:
            continue

        content_lower = content.lower()
        matched = (vuln_lower and vuln_lower in content_lower) or (
            component_lower and component_lower in content_lower
        )
        if not matched:
            continue

        # Extract GHSA ID from filename: {ghsa_id}_triage.md
        ghsa_id = stem.replace("_triage", "")

        # Extract verdict from report (handles **CONFIRMED** and **[CONFIRMED]**)
        verdict = "UNKNOWN"
        verdict_match = re.search(r"\*\*\[?\s*(CONFIRMED|UNCONFIRMED|INCONCLUSIVE)\s*\]?\*\*", content)
        if verdict_match:
            verdict = verdict_match.group(1)

        # Extract quality rating — report format: "Rate overall quality: High / Medium / Low"
        quality = "Unknown"
        quality_match = re.search(r"Rate overall quality[:\s]*\**\s*(High|Medium|Low)\b", content, re.IGNORECASE)
        if quality_match:
            quality = quality_match.group(1)

        matches.append({
            "ghsa_id": ghsa_id,
            "verdict": verdict,
            "quality": quality,
            "path": str(report_path),
        })

    return json.dumps(matches, indent=2)


@mcp.tool()
def read_triage_report(
    ghsa_id: str = Field(description="GHSA ID, used to locate the report file, e.g. GHSA-xxxx-xxxx-xxxx"),
) -> str:
    """
    Read a previously saved triage report from disk.

    Reads REPORT_DIR/{ghsa_id}_triage.md and returns its content.
    Returns an error string if the file does not exist.
    """
    safe_name = "".join(c for c in ghsa_id if c.isalnum() or c in "-_")
    report_path = REPORT_DIR / f"{safe_name}_triage.md"
    if not report_path.exists():
        return f"Report not found: {report_path}"
    return report_path.read_text(encoding="utf-8")


if __name__ == "__main__":
    mcp.run(show_banner=False)

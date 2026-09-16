# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# PVR GHSA MCP Server
#
# Tools for fetching and parsing GitHub Security Advisories
# submitted via Private Vulnerability Reporting (PVR) (triage state).
# Uses the gh CLI for all GitHub API calls.

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timezone
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


# ---------------------------------------------------------------------------
# Advisory fingerprinting and comparison
# ---------------------------------------------------------------------------

# Common file path patterns in advisory descriptions
_FILE_PATH_RE = re.compile(
    r"(?:^|[\s`\"'(])([a-zA-Z0-9_.][a-zA-Z0-9_./\\-]*\.[a-zA-Z]{1,10})(?:[\s`\"'),:;]|$)",
    re.MULTILINE,
)

# Line number references like "line 42", "L42", ":42"
_LINE_REF_RE = re.compile(r"(?:line\s+|L|:)(\d{1,6})\b", re.IGNORECASE)

# Known source file extensions (filter false positives from _FILE_PATH_RE)
_SRC_EXTS = frozenset({
    "py", "js", "ts", "go", "rs", "rb", "java", "c", "cpp", "cc", "h", "hpp",
    "cs", "php", "swift", "kt", "scala", "pl", "pm", "sh", "bash", "zsh",
    "yaml", "yml", "json", "xml", "toml", "cfg", "ini", "conf", "html",
    "jsx", "tsx", "vue", "svelte", "erb", "ejs", "sql", "r", "m", "mm",
})


def _extract_file_paths(text: str) -> list[str]:
    """Extract likely source file paths from free-form text."""
    paths = []
    for m in _FILE_PATH_RE.finditer(text):
        p = m.group(1)
        ext = p.rsplit(".", 1)[-1].lower() if "." in p else ""
        if ext in _SRC_EXTS and "/" in p:
            paths.append(p)
    return sorted(set(paths))


def _fingerprint_advisory(parsed: dict) -> dict:
    """
    Build a structural fingerprint from a parsed advisory.

    Returns a dict with normalized, comparable fields:
      cwes, packages, versions, file_paths, severity, summary_norm
    """
    desc = parsed.get("description", "")

    # Normalized summary: lowercase, strip whitespace/punctuation
    summary = parsed.get("summary", "").lower().strip()
    summary_norm = re.sub(r"[^a-z0-9 ]", "", summary)

    # Packages: (ecosystem, name) tuples
    packages = set()
    for v in parsed.get("vulnerabilities", []):
        eco = v.get("ecosystem", "").lower().strip()
        pkg = v.get("package", "").lower().strip()
        if pkg:
            packages.add((eco, pkg))

    # Version ranges as normalized strings
    versions = set()
    for v in parsed.get("vulnerabilities", []):
        vr = v.get("vulnerable_versions", "").strip()
        if vr:
            versions.add(vr)

    return {
        "ghsa_id": parsed.get("ghsa_id", ""),
        "cwes": set(parsed.get("cwes", [])),
        "packages": packages,
        "versions": versions,
        "file_paths": set(_extract_file_paths(desc)),
        "severity": parsed.get("severity", "").lower(),
        "summary_norm": summary_norm,
    }


def _compare_fingerprints(a: dict, b: dict) -> dict:
    """
    Compare two advisory fingerprints and return a similarity result.

    Returns:
      match_level: "strong", "moderate", "weak", or "none"
      reasons: list of strings explaining why they matched
      overlap: dict of shared fields
    """
    reasons = []
    overlap = {}

    # CWE overlap
    cwe_shared = a["cwes"] & b["cwes"]
    if cwe_shared:
        reasons.append(f"shared CWE: {', '.join(sorted(cwe_shared))}")
        overlap["cwes"] = sorted(cwe_shared)

    # Package overlap
    pkg_shared = a["packages"] & b["packages"]
    if pkg_shared:
        reasons.append(f"same package: {', '.join(f'{e}/{p}' for e, p in sorted(pkg_shared))}")
        overlap["packages"] = [f"{e}/{p}" for e, p in sorted(pkg_shared)]

    # Version range overlap
    ver_shared = a["versions"] & b["versions"]
    if ver_shared:
        reasons.append(f"same version range: {', '.join(sorted(ver_shared))}")
        overlap["versions"] = sorted(ver_shared)

    # File path overlap
    file_shared = a["file_paths"] & b["file_paths"]
    if file_shared:
        reasons.append(f"shared files: {', '.join(sorted(file_shared))}")
        overlap["file_paths"] = sorted(file_shared)

    # Summary similarity (exact match after normalization)
    if a["summary_norm"] and a["summary_norm"] == b["summary_norm"]:
        reasons.append("identical summary")
        overlap["summary"] = True

    # Determine match level
    if not reasons:
        level = "none"
    elif pkg_shared and (cwe_shared or file_shared or ver_shared):
        level = "strong"
    elif pkg_shared or (cwe_shared and file_shared):
        level = "moderate"
    else:
        level = "weak"

    return {"match_level": level, "reasons": reasons, "overlap": overlap,
            "note": "structural comparison only; 'none' means insufficient "
                    "metadata overlap, not necessarily distinct vulnerabilities"}


@mcp.tool()
def fetch_security_policy(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
) -> str:
    """
    Fetch the repository's SECURITY.md security policy.

    Checks the standard locations in order: /SECURITY.md, /.github/SECURITY.md,
    /docs/SECURITY.md. Also checks the org-level .github repo as a fallback.
    Returns the policy content, or an empty string if no policy is found.
    """
    # Standard locations per GitHub docs
    candidates = [
        f"/repos/{owner}/{repo}/contents/SECURITY.md",
        f"/repos/{owner}/{repo}/contents/.github/SECURITY.md",
        f"/repos/{owner}/{repo}/contents/docs/SECURITY.md",
        # Org-level fallback (.github repo)
        f"/repos/{owner}/.github/contents/SECURITY.md",
    ]

    cmd_base = ["gh", "api", "--method", "GET", "-H", "Accept: application/vnd.github.raw+json"]
    env = os.environ.copy()

    for api_path in candidates:
        try:
            result = subprocess.run(
                [*cmd_base, api_path],
                capture_output=True, text=True, env=env, timeout=15,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if result.returncode == 0 and result.stdout.strip():
            logging.info("Security policy found at %s", api_path)
            return result.stdout
    return ""


@mcp.tool()
def fetch_pvr_advisory(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
) -> str:
    """
    Fetch a single repository security advisory by GHSA ID.

    Returns structured advisory metadata and the full description text.
    Works for advisories in triage state (requires repo or security_events scope on GH_TOKEN).
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
        default="triage",
        description="Advisory state to filter by: triage, draft, published, closed, or withdrawn. Default: triage",
    ),
) -> str:
    """
    List repository security advisories, defaulting to triage state.

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
def compare_advisories(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    state: str = Field(
        default="triage",
        description="Advisory state to compare. Default: triage",
    ),
    target_ghsa: str = Field(
        default="",
        description="Optional: compare only this GHSA against the others. "
                    "If empty, compares all advisories pairwise.",
    ),
) -> str:
    """
    Detect duplicate or near-duplicate advisories in a repository's inbox.

    Fetches advisories in the given state, computes structural fingerprints
    (CWE, package, version range, file paths, summary), and identifies
    pairs or clusters that likely describe the same vulnerability.

    When target_ghsa is set, only comparisons involving that advisory are returned.

    Returns JSON with:
      - clusters: list of {advisories: [...ghsa_ids], match_level, reasons}
      - singles: list of ghsa_ids with no duplicates detected
      - total: total advisory count
    """
    base_path = f"/repos/{owner}/{repo}/security-advisories?state={state}&per_page=100"
    all_raw: list = []
    page = 1
    while page <= 50:
        data, err = _gh_api(f"{base_path}&page={page}")
        if err:
            return f"Error listing advisories: {err}"
        if not isinstance(data, list) or not data:
            break
        all_raw.extend(data)
        if len(data) < 100:
            break
        page += 1

    if len(all_raw) < 2:
        return json.dumps({
            "clusters": [],
            "singles": [_parse_advisory(r).get("ghsa_id", "") for r in all_raw],
            "total": len(all_raw),
        }, indent=2)

    # Parse and fingerprint all advisories
    parsed = [_parse_advisory(r) for r in all_raw]
    fps = [_fingerprint_advisory(p) for p in parsed]

    # Pairwise comparison
    # Union-find for clustering
    id_to_idx = {fp["ghsa_id"]: i for i, fp in enumerate(fps)}
    parent = list(range(len(fps)))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(x, y):
        px, py = find(x), find(y)
        if px != py:
            parent[px] = py

    matches = []
    for i in range(len(fps)):
        for j in range(i + 1, len(fps)):
            if target_ghsa and fps[i]["ghsa_id"] != target_ghsa and fps[j]["ghsa_id"] != target_ghsa:
                continue
            result = _compare_fingerprints(fps[i], fps[j])
            if result["match_level"] != "none":
                matches.append({
                    "a": fps[i]["ghsa_id"],
                    "b": fps[j]["ghsa_id"],
                    "match_level": result["match_level"],
                    "reasons": result["reasons"],
                })
                if result["match_level"] == "strong":
                    union(i, j)

    # Build clusters from union-find
    cluster_map: dict[int, list[str]] = defaultdict(list)
    for i, fp in enumerate(fps):
        root = find(i)
        cluster_map[root].append(fp["ghsa_id"])

    clusters = []
    singles = []
    for members in cluster_map.values():
        if len(members) > 1:
            # Find the match details for this cluster
            cluster_matches = [
                m for m in matches
                if m["a"] in members and m["b"] in members
            ]
            best_level = "weak"
            all_reasons: list[str] = []
            for cm in cluster_matches:
                all_reasons.extend(cm["reasons"])
                if cm["match_level"] == "strong":
                    best_level = "strong"
                elif cm["match_level"] == "moderate" and best_level != "strong":
                    best_level = "moderate"
            clusters.append({
                "advisories": sorted(members),
                "match_level": best_level,
                "reasons": sorted(set(all_reasons)),
            })
        else:
            singles.extend(members)

    # Also include weak matches (not clustered) as informational
    weak_matches = [m for m in matches if m["match_level"] == "weak"]

    return json.dumps({
        "clusters": clusters,
        "weak_matches": weak_matches,
        "singles": sorted(singles),
        "total": len(fps),
    }, indent=2)


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
    length: int = Field(default=100, description="Number of lines to return (max 500)"),
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


@mcp.tool()
def reject_pvr_advisory(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
) -> str:
    """
    Close (reject) a security advisory.

    Sets the advisory state to 'closed' via the GitHub API. Requires a GH_TOKEN
    with security_events write scope.

    Note: the GitHub REST API has no comments endpoint for security advisories.
    Post the response draft to the reporter manually via the advisory URL.
    """
    path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    _, err = _gh_api(path, method="PATCH", body={"state": "closed"})
    if err:
        return f"Error closing advisory {ghsa_id}: {err}"
    return f"Advisory {ghsa_id} closed (state: closed)."


@mcp.tool()
def accept_pvr_advisory(
    owner: str = Field(description="Repository owner (user or org name)"),
    repo: str = Field(description="Repository name"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
) -> str:
    """
    Accept a PVR advisory by moving it from triage to draft state.

    Sets the advisory state to 'draft' via the GitHub API (triage → draft transition).
    Use this when the vulnerability is confirmed and the maintainer intends to publish
    a security advisory. Requires a GH_TOKEN with security_events write scope.

    Note: the GitHub REST API has no comments endpoint for security advisories.
    Post the response draft to the reporter manually via the advisory URL.
    """
    path = f"/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    _, err = _gh_api(path, method="PATCH", body={"state": "draft"})
    if err:
        return f"Error accepting advisory {ghsa_id}: {err}"
    return f"Advisory {ghsa_id} accepted (state: draft)."


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


@mcp.tool()
def list_pending_responses() -> str:
    """
    List advisories that have a response draft but have not yet been sent.

    Globs REPORT_DIR for *_response_triage.md files and skips any whose
    corresponding *_response_sent.md marker exists.
    Returns a JSON list of {ghsa_id, triage_report_exists} objects.
    """
    if not REPORT_DIR.exists():
        return json.dumps([])

    results = []
    for draft_path in sorted(REPORT_DIR.glob("*_response_triage.md")):
        # stem is e.g. "GHSA-xxxx-xxxx-xxxx_response_triage"
        stem = draft_path.stem
        # Extract ghsa_id: remove "_response_triage" suffix
        ghsa_id = stem.replace("_response_triage", "")
        safe_name = "".join(c for c in ghsa_id if c.isalnum() or c in "-_")

        # Skip if sent marker exists
        sent_marker = REPORT_DIR / f"{safe_name}_response_sent.md"
        if sent_marker.exists():
            continue

        triage_report = REPORT_DIR / f"{safe_name}_triage.md"
        results.append({
            "ghsa_id": ghsa_id,
            "triage_report_exists": triage_report.exists(),
        })

    return json.dumps(results, indent=2)


@mcp.tool()
def mark_response_sent(
    ghsa_id: str = Field(description="GHSA ID of the advisory whose response was sent"),
) -> str:
    """
    Create a marker file indicating that the response for this advisory has been sent.

    Writes REPORT_DIR/{ghsa_id}_response_sent.md with an ISO timestamp.
    Returns the path of the created marker, or an error string if ghsa_id is empty.
    """
    safe_name = "".join(c for c in ghsa_id if c.isalnum() or c in "-_")
    if not safe_name:
        return "Error: ghsa_id produced an empty filename after sanitization"
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    marker_path = REPORT_DIR / f"{safe_name}_response_sent.md"
    timestamp = datetime.now(timezone.utc).isoformat()
    marker_path.write_text(f"Response sent: {timestamp}\n", encoding="utf-8")
    logging.info("Response sent marker written to %s", marker_path)
    return str(marker_path.resolve())


if __name__ == "__main__":
    mcp.run(show_banner=False)

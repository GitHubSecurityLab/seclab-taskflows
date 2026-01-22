import logging

from fastmcp import FastMCP
from pydantic import Field
import re
import json
from urllib.parse import urlparse, parse_qs
from .gh_code_scanning import call_api
from seclab_taskflow_agent.path_utils import log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_ghsa.log'),
    filemode='a'
)

mcp = FastMCP("GitHubRepoAdvisories")


# The advisories contain a lot of information, so we need to filter
# some of it out to avoid exceeding the maximum prompt size.
def parse_advisory(advisory: dict) -> dict:
    logging.debug(f"advisory: {advisory}")
    return {
        "ghsa_id": advisory.get("ghsa_id", ""),
        "cve_id": advisory.get("cve_id", ""),
        "summary": advisory.get("summary", ""),
        "published_at": advisory.get("published_at", ""),
        "state": advisory.get("state", ""),
    }

async def fetch_GHSA_list_from_gh(owner: str, repo: str) -> str | list:
    """Fetch all security advisories for a specific repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories"
    params = {'per_page': 100}
    # See https://github.com/octokit/plugin-paginate-rest.js/blob/8ec2713699ee473ee630be5c8a66b9665bcd4173/src/iterator.ts#L40
    link_pattern = re.compile(r'<([^<>]+)>;\s*rel="next"')
    results = []
    while True:
        resp = await call_api(url, params)
        if isinstance(resp, str):
            return resp
        resp_headers = resp.headers
        link = resp_headers.get('link', '')
        resp = resp.json()
        if isinstance(resp, list):
            results += [parse_advisory(advisory) for advisory in resp]
        else:
            return "Could not parse response"
        m = link_pattern.search(link)
        if not m:
            break
        url = m.group(1)
        params = parse_qs(urlparse(url).query)

    if results:
        return results
    return "No advisories found."

@mcp.tool()
async def fetch_GHSA_list(owner: str = Field(description="The owner of the repo"),
                          repo: str = Field(description="The repository name")) -> str:
    """Fetch all GitHub Security Advisories (GHSAs) for a specific repository."""
    results = await fetch_GHSA_list_from_gh(owner, repo)
    if isinstance(results, str):
        return results
    return json.dumps(results, indent=2)


async def fetch_GHSA_details_from_gh(owner: str, repo: str, ghsa_id: str) -> str | dict:
    """Fetch the details of a repository security advisory."""
    url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories/{ghsa_id}"
    resp = await call_api(url, {})
    if isinstance(resp, str):
        return resp
    if resp:
        return resp.json()
    return "Not found."

@mcp.tool()
async def fetch_GHSA_details(owner: str = Field(description="The owner of the repo"),
                             repo: str = Field(description="The repository name"),
                             ghsa_id: str = Field(description="The ghsa_id of the advisory")) -> str:
    """Fetch a GitHub Security Advisory for a specific repository and GHSA ID."""
    results = await fetch_GHSA_details_from_gh(owner, repo, ghsa_id)
    if isinstance(results, str):
        return results
    return json.dumps(results, indent=2)

if __name__ == "__main__":
    mcp.run(show_banner=False)

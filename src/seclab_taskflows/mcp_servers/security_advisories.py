# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
from pydantic import Field
import httpx
import json
import os
from datetime import datetime, timedelta
from seclab_taskflow_agent.path_utils import log_file_name, mcp_data_dir
from seclab_taskflow_agent.mcp_servers.memcache.memcache_backend.sqlite import SqliteBackend

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_security_advisories.log"),
    filemode="a",
)

mcp = FastMCP("SecurityAdvisories")

GH_TOKEN = os.getenv("GH_TOKEN", default="")

# Initialize memcache backend to store advisories directly
MEMCACHE_DIR = mcp_data_dir("seclab-taskflow-agent", "memcache", "MEMCACHE_STATE_DIR")
memcache_backend = SqliteBackend(str(MEMCACHE_DIR))


def is_recent_advisory(advisory: dict, years: int = 3) -> bool:
    """
    Check if an advisory was published within the last N years.
    
    Args:
        advisory: Advisory object from the API
        years: Number of years to look back (default: 3)
        
    Returns:
        True if the advisory was published within the specified years, False otherwise
    """
    published_at = advisory.get("published_at")
    if not published_at:
        return True  # Include advisories without a published_at date
    
    try:
        published_date = datetime.fromisoformat(published_at.replace('Z', '+00:00'))
        cutoff_date = datetime.now(published_date.tzinfo) - timedelta(days=365 * years)
        return published_date >= cutoff_date
    except (ValueError, TypeError):
        return True  # Include advisories we can't parse the date for

def filter_advisories(advisories: list, years: int = 3) -> list:
    """
    Filter advisory objects to include only essential fields and recent advisories.
    
    Args:
        advisories: List of advisory objects from the API
        years: Only include advisories from the last N years (default: 3)
        
    Returns:
        Filtered list with only ghsa_id, summary, description, and severity
    """
    filtered = []
    for advisory in advisories:
        if is_recent_advisory(advisory, years):
            filtered.append({
                "ghsa_id": advisory.get("ghsa_id"),
                "summary": advisory.get("summary"),
                "description": advisory.get("description"),
                "severity": advisory.get("severity"),
            })
    return filtered


@mcp.tool()
async def get_security_advisories(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    years: int = Field(description="Only include advisories from the last N years (default: 3)", default=3),
) -> str:
    """
    Fetch security advisories for a GitHub repository.
    Returns a filtered list of security advisories with ghsa_id, summary, description, and severity for each advisory published in the last N years.
    Also stores the result in memcache under the key 'security_advisories_{owner}/{repo}'.
    """
    owner = owner.strip()
    repo = repo.strip()
    advisories = []
    page = 1
    while True:
        url = f"https://api.github.com/repos/{owner}/{repo}/security-advisories?per_page=100&page={page}"
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {GH_TOKEN}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            async with httpx.AsyncClient() as client:
                r = await client.get(url, headers=headers)
                r.raise_for_status()
                data = r.text
                page_advisories = json.loads(data)
                if not page_advisories:
                    break
                advisories.extend(page_advisories)
                if len(page_advisories) < 100:
                    break
                page += 1
        except httpx.HTTPStatusError as e:
            return f"HTTP error {e.response.status_code}: {e.response.text}"
        except json.JSONDecodeError as e:
            return f"JSON parsing error: {e}"
        except Exception as e:
            return f"Error: {e}"
    filtered = filter_advisories(advisories, years)
    
    # Store in memcache for later retrieval (store the Python object, not JSON string)
    memcache_key = f"security_advisories_{owner}/{repo}"
    try:
        memcache_backend.set_state(memcache_key, filtered)
        logging.info(f"Stored {len(filtered)} advisories in memcache under key '{memcache_key}'")
    except Exception:
        logging.exception("Failed to store advisories in memcache")
    
    # Return JSON string to the caller
    return json.dumps(filtered, indent=2)


if __name__ == "__main__":
    mcp.run(show_banner=False)

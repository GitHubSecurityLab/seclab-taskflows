# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
from pydantic import Field
import httpx
import json
import os
from pathlib import Path
import aiofiles
import zipfile
import tempfile
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_local_gh_resources.log'),
    filemode='a'
)

mcp = FastMCP("LocalGHResources")

GH_TOKEN = os.getenv('GH_TOKEN')

LOCAL_GH_DIR = mcp_data_dir('seclab-taskflows', 'local_gh_resources', 'LOCAL_GH_DIR')

def is_subdirectory(directory, potential_subdirectory):
    directory_path = Path(directory)
    potential_subdirectory_path = Path(potential_subdirectory)
    try:
        potential_subdirectory_path.relative_to(directory_path)
        return True
    except ValueError:
        return False

def sanitize_file_path(file_path, allow_paths):
    file_path = os.path.realpath(file_path)
    for allowed_path in allow_paths:
        if is_subdirectory(allowed_path, file_path):
            return Path(file_path)
    return None

async def call_api(url: str, params: dict) -> str:
    """Call the GitHub code scanning API to fetch alert."""
    headers = {"Accept": "application/vnd.github.raw+json", "X-GitHub-Api-Version": "2022-11-28",
                          "Authorization": f"Bearer {GH_TOKEN}"}
    async def _fetch_file(url, headers, params):
        try:
            async with httpx.AsyncClient(headers = headers) as client:
                r = await client.get(url, params=params, follow_redirects=True)
                r.raise_for_status()
                return r
        except httpx.RequestError as e:
            return f"Request error: {e}"
        except json.JSONDecodeError as e:
            return f"JSON error: {e}"
        except httpx.HTTPStatusError as e:
            return f"HTTP error: {e}"
        except httpx.AuthenticationError as e:
            return f"Authentication error: {e}"

    return await _fetch_file(url, headers = headers, params=params)

async def _fetch_source_zip(owner: str, repo: str, tmp_dir):
    """Fetch the source code."""
    url = f"https://api.github.com/repos/{owner}/{repo}/zipball"
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
               "Authorization": f"Bearer {GH_TOKEN}"}
    try:
        async with httpx.AsyncClient() as client:
            async with client.stream('GET', url, headers =headers, follow_redirects=True) as response:
                response.raise_for_status()
                expected_path = Path(tmp_dir) / owner / f"{repo}.zip"
                resolved_path = expected_path.resolve()
                if os.path.commonpath([resolved_path, Path(tmp_dir).resolve()]) != str(Path(tmp_dir).resolve()):
                    return f"Error: Invalid path for source code: {expected_path}"
                if not Path(f"{tmp_dir}/{owner}").exists():
                    os.makedirs(f"{tmp_dir}/{owner}", exist_ok=True)
                async with aiofiles.open(f"{tmp_dir}/{owner}/{repo}.zip", 'wb') as f:
                    async for chunk in response.aiter_bytes():
                        await f.write(chunk)
        return f"source code for {repo} fetched successfully."
    except httpx.RequestError as e:
        return f"Error: Request error: {e}"
    except httpx.HTTPStatusError as e:
        return f"Error: HTTP error: {e}"
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}"
@mcp.tool()
async def fetch_repo_from_gh(
    owner: str, repo: str
):
    """
    Download the source code from GitHub to the local file system to speed up file search.
    """
    result = await _fetch_source_zip(owner, repo, LOCAL_GH_DIR)
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    if not source_path.exists():
        return result
    return f"Downloaded source code to {owner}/{repo}.zip"

@mcp.tool()
async def clear_local_repo(owner: str, repo: str):
    """
    Delete the local repo.
    """
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    source_path = sanitize_file_path(source_path, [LOCAL_GH_DIR])
    if not source_path:
        return f"Invalid {owner} and {repo}. Check that the input is correct or try to fetch the repo from gh first."
    if source_path.exists():
        os.remove(source_path)
    return f"Cleared the locally stored {owner}/{repo}"


if __name__ == "__main__":
    mcp.run(show_banner=False)

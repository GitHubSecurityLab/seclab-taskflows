# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
from pydantic import Field
import httpx
import json
import os
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from typing import Optional
from pathlib import Path
import aiofiles
import zipfile
import tempfile
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_gh_file_viewer.log'),
    filemode='a'
)

class Base(DeclarativeBase):
    pass

class SearchResults(Base):
    __tablename__ = 'search_results'

    id: Mapped[int] = mapped_column(primary_key=True)
    path: Mapped[str]
    line: Mapped[int]
    search_term: Mapped[str]
    owner: Mapped[str]
    repo: Mapped[str]

    def __repr__(self):
        return (f"<SearchResults(path={self.path}, line={self.line}, "
                f"search_term={self.search_term}, owner={self.owner}, repo={self.repo})>")

mcp = FastMCP("GitHubFileViewer")

GH_TOKEN = os.getenv('GH_TOKEN', default='')

SEARCH_RESULT_DIR = mcp_data_dir('seclab-taskflows', 'gh_file_viewer', 'SEARCH_RESULTS_DIR')

engine = create_engine(f'sqlite:///{os.path.abspath(SEARCH_RESULT_DIR)}/search_result.db', echo=False)
Base.metadata.create_all(engine, tables = [SearchResults.__table__])


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

def remove_root_dir(path):
    return '/'.join(path.split('/')[1:])

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

def search_zipfile(database_path, term):
    results = {}
    with zipfile.ZipFile(database_path) as z:
        for entry in z.infolist():
            if entry.is_dir():
                continue
            with z.open(entry, 'r') as f:
                for i, line in enumerate(f):
                    if term in str(line):
                        filename = remove_root_dir(entry.filename)
                        if not filename in results:
                            results[filename] = [i+1]
                        else:
                            results[filename].append(i+1)
    return results


@mcp.tool()
async def fetch_file_from_gh(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the file in the repository"))-> str:
    """
    Fetch the content of a file from a GitHub repository.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        params={}
    )
    if isinstance(r, str):
        return r
    lines = r.text.splitlines()
    for i in range(len(lines)):
        lines[i] = f"{i+1}: {lines[i]}"
    return "\n".join(lines)

@mcp.tool()
async def get_file_lines_from_gh(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the file in the repository"),
    start_line: int = Field(description="The starting line number to fetch from the file", default=1),
    length: int = Field(description="The ending line number to fetch from the file", default=10)) -> str:
    """Fetch a range of lines from a file in a GitHub repository.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        params={}
    )
    if isinstance(r, str):
        return r
    lines = r.text.splitlines()
    if start_line < 1:
        start_line = 1
    if length < 1:
        length = 10
    lines = lines[start_line-1:start_line-1+length]
    if not lines:
        return f"No lines found in the range {start_line} to {start_line + length - 1} in {path}."
    return "\n".join([f"{i+start_line}: {line}" for i, line in enumerate(lines)])

@mcp.tool()
async def search_file_from_gh(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the file in the repository"),
    search_term: str = Field(description="The term to search for in the file")) -> str:
    """
    Search for a term in a file from a GitHub repository.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        params={}
    )
    if isinstance(r, str):
        return r
    lines = r.text.splitlines()
    matches = [f"{i+1}: {line}" for i,line in enumerate(lines) if search_term in line]
    if not matches:
        return f"No matches found for '{search_term}' in {path}."
    return "\n".join(matches)

@mcp.tool()
async def search_files_from_gh(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    paths: str = Field(description="A comma separated list of paths to the file in the repository"),
    search_term: str = Field(description="The term to search for in the file"),
    save_to_db: bool = Field(description="Save the results to database.", default=False)) -> str:
    """
    Search for a term in a list of files from a GitHub repository.
    """
    paths_list = [path.strip() for path in paths.split(',')]
    if not paths_list:
        return "No paths provided for search."
    results = []
    for path in paths_list:
        r = await call_api(
            url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            params={}
        )
        if isinstance(r, str):
            return r
        lines = r.text.splitlines()
        matches = [{"path": path, "line" : i+1, "search_term": search_term, "owner": owner.lower(), "repo" : repo.lower()} for i,line in enumerate(lines) if search_term in line]
        if matches:
            results.extend(matches)
    if not results:
        return f"No matches found for '{search_term}'."
    if save_to_db:
        with Session(engine) as session:
            for result in results:
                search_result = SearchResults(**result)
                session.add(search_result)
            session.commit()
        return f"Search results saved to database."
    return json.dumps(results)

@mcp.tool()
def fetch_last_search_results() -> str:
    """
    Fetch the previous search results from the database. Will delete the results after fetching.
    """
    with Session(engine) as session:
        results = session.query(SearchResults).all()
        session.query(SearchResults).delete()
        session.commit()
    return json.dumps([{"path": result.path, "line" : result.line, "search_term": result.search_term, "owner": result.owner.lower(), "repo" : result.repo.lower()} for result in results])

@mcp.tool()
async def list_directory_from_gh(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the directory in the repository")) -> str:
    """
    Fetch the content of a directory from a GitHub repository.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        params={}
    )
    if isinstance(r, str):
        return r
    if not r.json():
        return json.dumps([], indent=2)

    content = [item['path'] for item in r.json()]
    return json.dumps(content, indent=2)

@mcp.tool()
async def search_repo_from_gh(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    search_term: str = Field(description="The term to search within the repo.")
):
    """
    Search for the search term in the entire repository.
    """
    with tempfile.TemporaryDirectory() as tmp_dir:
        result = await _fetch_source_zip(owner, repo, tmp_dir)
        source_path = Path(f"{tmp_dir}/{owner}/{repo}.zip")
        if not source_path.exists():
            return json.dumps([result], indent=2)
        results = search_zipfile(source_path, search_term)
        out = []
        for k,v in results.items():
            out.append({"owner": owner, "repo": repo, "path": k, "lines": v})
        return json.dumps(out, indent=2)

if __name__ == "__main__":
    mcp.run(show_banner=False)

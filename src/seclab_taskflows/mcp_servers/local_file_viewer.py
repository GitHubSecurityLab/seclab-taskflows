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
    filename=log_file_name('mcp_local_file_viewer.log'),
    filemode='a'
)

mcp = FastMCP("LocalFileViewer")

LOCAL_GH_DIR = mcp_data_dir('seclab-taskflows', 'local_file_viewer', 'LOCAL_GH_DIR')

LINE_LIMIT_FOR_FETCHING_FILE_CONTENT = int(os.getenv('LINE_LIMIT_FOR_FETCHING_FILE_CONTENT', default=1000))

FILE_LIMIT_FOR_LIST_FILES = int(os.getenv('FILE_LIMIT_FOR_LIST_FILES', default=100))

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

def remove_root_dir(path):
    return '/'.join(path.split('/')[1:])

def strip_leading_dash(path):
    if path and path[0] == '/':
        path = path[1:]
    return path

def search_zipfile(database_path, term, search_dir = None):
    results = {}
    search_dir = strip_leading_dash(search_dir)
    with zipfile.ZipFile(database_path) as z:
        for entry in z.infolist():
            if entry.is_dir():
                continue
            if search_dir and not is_subdirectory(search_dir, remove_root_dir(entry.filename)):
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

def _list_files(database_path, root_dir = None, recursive=True):
    results = []
    root_dir = strip_leading_dash(root_dir)
    with zipfile.ZipFile(database_path) as z:
        for entry in z.infolist():
            if entry.is_dir():
                if not recursive:
                    dirname = remove_root_dir(entry.filename)
                    if Path(dirname).parent == Path(root_dir):
                        results.append(dirname + '/')
                continue
            filename = remove_root_dir(entry.filename)
            if root_dir and not is_subdirectory(root_dir, filename):
                continue
            if not recursive and Path(filename).parent != Path(root_dir):
                continue
            results.append(filename)
    return results

def get_file(database_path, filename):
    results = []
    filename = strip_leading_dash(filename)
    with zipfile.ZipFile(database_path) as z:
        for entry in z.infolist():
            if entry.is_dir():
                continue
            if remove_root_dir(entry.filename) == filename:
                with z.open(entry, 'r') as f:
                    results = [line.rstrip() for line in f]
                    return results
    return results

@mcp.tool()
async def fetch_file_content(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the file in the repository"))-> str:
    """
    Fetch the content of a file from a local GitHub repository.
    """
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    source_path = sanitize_file_path(source_path, [LOCAL_GH_DIR])
    if not source_path or not source_path.exists():
        return f"Invalid {owner} and {repo}. Check that the input is correct or try to fetch the repo from gh first."
    lines = get_file(source_path, path)
    if len(lines) > LINE_LIMIT_FOR_FETCHING_FILE_CONTENT:
        return f"File {path} in {owner}/{repo} is too large to display ({len(lines)} lines). Please fetch specific lines using get_file_lines tool."
    if not lines:
        return f"Unable to find file {path} in {owner}/{repo}"
    for i in range(len(lines)):
        lines[i] = f"{i+1}: {lines[i]}"
    return "\n".join(lines)

@mcp.tool()
async def get_file_lines(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the file in the repository"),
    start_line: int = Field(description="The starting line number to fetch from the file", default=1),
    length: int = Field(description="The ending line number to fetch from the file", default=10)) -> str:
    """Fetch a range of lines from a file in a local GitHub repository.
    """
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    source_path = sanitize_file_path(source_path, [LOCAL_GH_DIR])
    if not source_path or not source_path.exists():
        return f"Invalid {owner} and {repo}. Check that the input is correct or try to fetch the repo from gh first."
    lines = get_file(source_path, path)
    if start_line < 1:
        start_line = 1
    if length < 1:
        length = 10
    lines = lines[start_line-1:start_line-1+length]
    if not lines:
        return f"No lines found in the range {start_line} to {start_line + length - 1} in {path}."
    return "\n".join([f"{i+start_line}: {line}" for i, line in enumerate(lines)])

@mcp.tool()
async def list_files(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the directory in the repository")) -> str:
    """
    Recursively list the files of a directory from a local GitHub repository.
    """
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    source_path = sanitize_file_path(source_path, [LOCAL_GH_DIR])
    if not source_path or not source_path.exists():
        return f"Invalid {owner} and {repo}. Check that the input is correct or try to fetch the repo from gh first."
    content = _list_files(source_path, path)
    if len(content) > FILE_LIMIT_FOR_LIST_FILES:
        return f"Too many files to display in {owner}/{repo} at path {path} ({len(content)} files). Try using `list_files_non_recursive` instead."
    return json.dumps(content, indent=2)

@mcp.tool()
async def list_files_non_recursive(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    path: str = Field(description="The path to the directory in the repository")) -> str:
    """
    List the files of a directory from a local GitHub repository non-recursively.
    Subdirectories will be listed and indicated with a trailing slash.
    """
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    source_path = sanitize_file_path(source_path, [LOCAL_GH_DIR])
    if not source_path or not source_path.exists():
        return f"Invalid {owner} and {repo}. Check that the input is correct or try to fetch the repo from gh first."
    content = _list_files(source_path, path, recursive=False)
    return json.dumps(content, indent=2)


@mcp.tool()
async def search_repo(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    search_term: str = Field(description="The term to search within the repo."),
    directory: str = Field(description="The directory or file to restrict the search, if not provided, the whole repo is searched", default = '')
):
    """
    Search for the search term in the repository or a subdirectory/file in the repository.
    """
    source_path = Path(f"{LOCAL_GH_DIR}/{owner}/{repo}.zip")
    source_path = sanitize_file_path(source_path, [LOCAL_GH_DIR])
    if not source_path or not source_path.exists():
        return f"Invalid {owner} and {repo}. Check that the input is correct or try to fetch the repo from gh first."
    if not source_path.exists():
        return json.dumps([], indent=2)
    results = search_zipfile(source_path, search_term, directory)
    out = []
    for k,v in results.items():
        out.append({"owner": owner, "repo": repo, "path": k, "lines": v})
    return json.dumps(out, indent=2)

if __name__ == "__main__":
    mcp.run(show_banner=False)

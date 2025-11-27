# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT


import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='logs/mcp_codeql_python.log',
    filemode='a'
)
from seclab_taskflow_agent.mcp_servers.codeql.client import run_query, file_from_uri, list_src_files, _debug_log, search_in_src_archive

from pydantic import Field
#from mcp.server.fastmcp import FastMCP, Context
from fastmcp import FastMCP, Context # use FastMCP 2.0
from pathlib import Path
import os
import csv
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

import zipfile
import httpx
import aiofiles
from .codeql_sqlite_models import Base, Source

MEMORY = Path(os.getenv('CODEQL_SQLITE_DIR', default='/app/my_data'))
mcp = FastMCP("CodeQL-Python")

CODEQL_DBS_BASE_PATH = Path(os.getenv('CODEQL_DBS_BASE_PATH', default='/workspaces/seclab-taskflow-agent/my_data'))

# tool name -> templated query lookup for supported languages
TEMPLATED_QUERY_PATHS = {
    # to add a language, port the templated query pack and add its definition here
    'python': {
        'remote_sources': 'queries/mcp-python/remote_sources.ql'
    }
}


def source_to_dict(result):
    return {
        "source_id": result.id,
        "repo": result.repo,
        "source_location": result.source_location,
        "type": result.type,
        "notes": result.notes
    }

def _resolve_query_path(language: str, query: str) -> Path:
    global TEMPLATED_QUERY_PATHS
    if language not in TEMPLATED_QUERY_PATHS:
        raise RuntimeError(f"Error: Language `{language}` not supported!")
    query_path = TEMPLATED_QUERY_PATHS[language].get(query)
    if not query_path:
        raise RuntimeError(f"Error: query `{query}` not supported for `{language}`!")
    return Path(query_path)


def _resolve_db_path(relative_db_path: str | Path):
    global CODEQL_DBS_BASE_PATH
    # path joins will return "/B" if "/A" / "////B" etc. as well
    # not windows compatible and probably needs additional hardening
    relative_db_path = str(relative_db_path).strip().lstrip('/')
    relative_db_path = Path(relative_db_path)
    absolute_path = CODEQL_DBS_BASE_PATH / relative_db_path
    if not absolute_path.is_dir():
        _debug_log(f"Database path not found: {absolute_path}")
        raise RuntimeError(f"Error: Database not found at {absolute_path}!")
    return str(absolute_path)

# This sqlite database is specifically made for CodeQL for Python MCP.
class CodeqlSqliteBackend:
    def __init__(self, memcache_state_dir: str):
        self.memcache_state_dir = memcache_state_dir
        self.location_pattern = r'^([a-zA-Z]+)(:\d+){4}$'
        if not Path(self.memcache_state_dir).exists():
            db_dir = 'sqlite://'
        else:
            db_dir = f'sqlite:///{self.memcache_state_dir}/codeql_sqlite.db'
        self.engine = create_engine(db_dir, echo=False)
        Base.metadata.create_all(self.engine, tables=[Source.__table__])


    def store_new_source(self, repo, source_location, type, notes, update = False):
        with Session(self.engine) as session:
            existing = session.query(Source).filter_by(repo = repo, source_location = source_location).first()
            if existing:
                existing.notes = (existing.notes or "") + notes
                session.commit()
                return f"Updated notes for source at {source_location} in {repo}."
            else:
                if update:
                    return f"No source exists at repo {repo}, location {source_location}"
                new_source = Source(repo = repo,  source_location = source_location, type = type, notes = notes)
                session.add(new_source)
                session.commit()
                return f"Added new source for {source_location} in {repo}."

    def get_sources(self, repo):
        with Session(self.engine) as session:
            results = session.query(Source).filter_by(repo=repo).all()
            sources = [source_to_dict(source) for source in results]
        return sources


# our query result format is: "human readable template {val0} {val1},'key0,key1',val0,val1"
def _csv_parse(raw):
    results = []
    reader = csv.reader(raw.strip().splitlines())
    try:
        for i, row in enumerate(reader):
            if i == 0:
                continue
            # col1 has what we care about, but offer flexibility
            keys = row[1].split(',')
            this_obj = {'description': row[0].format(*row[2:])}
            for j, k in enumerate(keys):
                this_obj[k.strip()] = row[j + 2]
            results.append(this_obj)
    except (csv.Error, IndexError, ValueError) as e:
        return ["Error: CSV parsing error: " + str(e)]
    return results


def _run_query(query_name: str, database_path: str, language: str, template_values: dict):
    """Run a CodeQL query and return the results"""

    try:
        database_path = _resolve_db_path(database_path)
    except RuntimeError:
        return f"The database path for {database_path} could not be resolved"
    try:
        query_path = _resolve_query_path(language, query_name)
    except RuntimeError:
        return f"The query {query_name} is not supported for language: {language}"
    try:
        csv = run_query(Path(__file__).parent.resolve() /
                        query_path,
                        database_path,
                        fmt='csv',
                        template_values=template_values,
                        log_stderr=True)
        return _csv_parse(csv)
    except Exception as e:
        return f"The query {query_name} encountered an error: {e}"

def _get_file_contents(db: str | Path, uri: str):
    """Retrieve file contents from a CodeQL database"""
    db = Path(db)
    return file_from_uri(uri, db)

backend = CodeqlSqliteBackend(MEMORY)

@mcp.tool()
def remote_sources(owner: str, repo: str,
                   database_path: str = Field(description="The CodeQL database path."),
                   language: str = Field(description="The language used for the CodeQL database.")):
    """List all remote sources and their locations in a CodeQL database, then store the results in a database."""

    repo = f"{owner}/{repo}"
    results = _run_query('remote_sources', database_path, language, {})

    # Check if results is an error (list of strings) or valid data (list of dicts)
    if results and isinstance(results[0], str):
        return f"Error: {results[0]}"

    # Store each result as a source
    stored_count = 0
    for result in results:
        backend.store_new_source(
            repo=repo,
            source_location=result.get('location', ''),
            type=result.get('source', ''),
            notes='', #result.get('description', ''),
            update=False
        )
        stored_count += 1

    return f"Stored {stored_count} remote sources in {repo}."

@mcp.tool()
def fetch_sources(owner: str, repo: str):
    """
    Fetch all sources from the repo
    """
    repo = f"{owner}/{repo}"
    return json.dumps(backend.get_sources(repo))

@mcp.tool()
def add_source_notes(owner: str, repo: str,
                     database_path: str = Field(description="The CodeQL database path."),
                     source_location: str = Field(description="The path to the file and column info that contains the source"),
                     notes: str = Field(description="The notes to append to this source", default="")):
    """
    Add new notes to an existing source. The notes will be appended to any existing notes.
    """
    repo = f"{owner}/{repo}"
    try:
        database_path = _resolve_db_path(database_path)
    except RuntimeError:
        return f"The database path for {database_path} could not be resolved"
    return backend.store_new_source(repo, source_location, "", notes, update=True)

@mcp.tool()
def clear_codeql_repo(owner: str, repo: str):
    """
    Clear all data for a given repo from the database
    """
    repo = f"{owner}/{repo}"
    with Session(backend.engine) as session:
        deleted_sources = session.query(Source).filter_by(repo=repo).delete()
        # deleted_apps = session.query(Application).filter_by(repo=repo).delete()
        session.commit()
    return f"Cleared {deleted_sources} sources from repo {repo}."

@mcp.tool()
def get_file_contents(
        file_uri: str = Field(description="The file URI to get contents for. The URI scheme is defined as `file://path` and `file://path:region`. Examples of file URI: `file:///path/to/file:1:2:3:4`, `file:///path/to/file`. File URIs optionally contain a region definition that looks like `start_line:start_column:end_line:end_column` which will limit the contents returned to the specified region, for example `file:///path/to/file:1:2:3:4` indicates a file region of `1:2:3:4` which would return the content of the file starting at line 1, column 1 and ending at line 3 column 4. Line and column indices are 1-based, meaning line and column values start at 1. If the region is omitted the full contents of the file will be returned, for example `file:///path/to/file` returns the full contents of `/path/to/file`."),
        database_path: str = Field(description="The path to the CodeQL database.")):
    """Get the contents of a file URI from a CodeQL database path."""

    database_path = _resolve_db_path(database_path)
    try:
        # fix up any incorrectly formatted relative path uri
        if not file_uri.startswith('file:///'):
            if file_uri.startswith('file://'):
                file_uri = file_uri[len('file://'):]
            file_uri = 'file:///' + file_uri.lstrip('/')
        results = _get_file_contents(database_path, file_uri)
    except Exception as e:
        results = f"Error: could not retrieve {file_uri}: {e}"
    return results

@mcp.tool()
def list_source_files(database_path: str = Field(description="The path to the CodeQL database."),
                      regex_filter: str = Field(description="Optional Regex filter.", default = r'[\s\S]+')):
    """List the available source files in a CodeQL database using their file:// URI"""
    database_path = _resolve_db_path(database_path)
    results = list_src_files(database_path, as_uri=True)
    return json.dumps([{'uri': item} for item in results if re.search(regex_filter, item)], indent=2)

@mcp.tool()
def search_in_source_code(database_path: str = Field(description="The path to the CodeQL database."),
                          search_term: str = Field(description="The term to search in the source code")):
    """
    Search for a string in the source code. Returns the line number and file.
    """
    resolved_database_path = _resolve_db_path(database_path)
    results = search_in_src_archive(resolved_database_path, search_term)
    out = []
    if isinstance(results, dict):
        for k,v in results.items():
            out.append({"database" : database_path, "path" : k, "lines" : v})
    return json.dumps(out, indent = 2)

if __name__ == "__main__":
    mcp.run(show_banner=False, transport="http", host="127.0.0.1", port=9998)

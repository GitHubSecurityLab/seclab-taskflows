# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT


import logging
from seclab_taskflow_agent.mcp_servers.codeql.client import run_query, _debug_log

from pydantic import Field
#from mcp.server.fastmcp import FastMCP, Context
from fastmcp import FastMCP # use FastMCP 2.0
from pathlib import Path
import os
import csv
import json
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
import subprocess
import importlib.resources
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name

from .codeql_sqlite_models import Base, Source
from ..utils import process_repo

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_codeql_python.log'),
    filemode='a'
)

MEMORY = mcp_data_dir('seclab-taskflows', 'codeql', 'DATA_DIR')
CODEQL_DBS_BASE_PATH = mcp_data_dir('seclab-taskflows', 'codeql', 'CODEQL_DBS_BASE_PATH')

mcp = FastMCP("CodeQL-Python")

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
        "line": result.line,
        "source_type": result.source_type,
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
    absolute_path = (CODEQL_DBS_BASE_PATH / relative_db_path).resolve()
    if not absolute_path.is_relative_to(CODEQL_DBS_BASE_PATH.resolve()):
        raise RuntimeError(f"Error: Database path {absolute_path} is outside the base path {CODEQL_DBS_BASE_PATH}")
    if not absolute_path.is_dir():
        _debug_log(f"Database path not found: {absolute_path}")
        raise RuntimeError(f"Error: Database not found at {absolute_path}!")
    return str(absolute_path)

# This sqlite database is specifically made for CodeQL for Python MCP.
class CodeqlSqliteBackend:
    def __init__(self, memcache_state_dir: str):
        self.memcache_state_dir = memcache_state_dir
        if not Path(self.memcache_state_dir).exists():
            db_dir = 'sqlite://'
        else:
            db_dir = f'sqlite:///{self.memcache_state_dir}/codeql_sqlite.db'
        self.engine = create_engine(db_dir, echo=False)
        Base.metadata.create_all(self.engine, tables=[Source.__table__])


    def store_new_source(self, repo, source_location, line, source_type, notes, update = False):
        with Session(self.engine) as session:
            existing = session.query(Source).filter_by(repo = repo, source_location = source_location, line = line).first()
            if existing:
                existing.notes = (existing.notes or "") + notes
                session.commit()
                return f"Updated notes for source at {source_location}, line {line} in {repo}."
            else:
                if update:
                    return f"No source exists at repo {repo}, location {source_location}, line {line} to update."
                new_source = Source(repo = repo,  source_location = source_location, line = line, source_type = source_type, notes = notes)
                session.add(new_source)
                session.commit()
                return f"Added new source for {source_location} in {repo}."

    def get_sources(self, repo):
        with Session(self.engine) as session:
            results = session.query(Source).filter_by(repo = repo).all()
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
        return f"Error: CSV parsing error: {e}"
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

backend = CodeqlSqliteBackend(MEMORY)

@mcp.tool()
def remote_sources(owner: str = Field(description="The owner of the GitHub repository"),
                   repo: str = Field(description="The name of the GitHub repository"),
                   database_path: str = Field(description="The CodeQL database path."),
                   language: str = Field(description="The language used for the CodeQL database.")):
    """List all remote sources and their locations in a CodeQL database, then store the results in a database."""

    repo = process_repo(owner, repo)
    results = _run_query('remote_sources', database_path, language, {})

    # Check if results is an error (list of strings) or valid data (list of dicts)
    if isinstance(results, str):
        return f"Error: {results}"

    # Store each result as a source
    stored_count = 0
    for result in results:
        backend.store_new_source(
            repo=repo,
            source_location=result.get('location', ''),
            source_type=result.get('source', ''),
            line=int(result.get('line', '0')),
            notes=None, #result.get('description', ''),
            update=False
        )
        stored_count += 1

    return f"Stored {stored_count} remote sources in {repo}."

@mcp.tool()
def fetch_sources(owner: str = Field(description="The owner of the GitHub repository"),
                     repo: str = Field(description="The name of the GitHub repository")):
    """
    Fetch all sources from the repo
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_sources(repo))

@mcp.tool()
def add_source_notes(owner: str = Field(description="The owner of the GitHub repository"),
                     repo: str = Field(description="The name of the GitHub repository"),
                     source_location: str = Field(description="The path to the file"),
                     line: int = Field(description="The line number of the source"),
                     notes: str = Field(description="The notes to append to this source")):
    """
    Add new notes to an existing source. The notes will be appended to any existing notes.
    """
    repo = process_repo(owner, repo)
    return backend.store_new_source(repo = repo, source_location = source_location, line = line, source_type = "", notes = notes, update=True)

@mcp.tool()
def clear_codeql_repo(owner: str = Field(description="The owner of the GitHub repository"),
                     repo: str = Field(description="The name of the GitHub repository")):
    """
    Clear all data for a given repo from the database
    """
    repo = process_repo(owner, repo)
    with Session(backend.engine) as session:
        deleted_sources = session.query(Source).filter_by(repo = repo).delete()
        session.commit()
    return f"Cleared {deleted_sources} sources from repo {repo}."

if __name__ == "__main__":
    # Check if codeql/python-all pack is installed, if not install it
    if not os.path.isdir('/.codeql/packages/codeql/python-all'):
        pack_path = importlib.resources.files('seclab_taskflows.mcp_servers.codeql_python.queries').joinpath('mcp-python')
        print(f"Installing CodeQL pack from {pack_path}")
        subprocess.run(["codeql", "pack", "install", pack_path])
    mcp.run(show_banner=False, transport="http", host="127.0.0.1", port=9998)

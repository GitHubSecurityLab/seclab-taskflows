# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
from pydantic import Field
import httpx
import aiofiles
import json
import os
import re
from urllib.parse import urlparse, parse_qs
from pathlib import Path
import zipfile
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name

from .alert_results_models import AlertResults, AlertFlowGraph, Base

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_gh_code_scanning.log'),
    filemode='a'
)

mcp = FastMCP("GitHubCodeScanning")

GH_TOKEN = os.getenv('GH_TOKEN', default='')

CODEQL_DBS_BASE_PATH = mcp_data_dir('seclab-taskflows', 'codeql', 'CODEQL_DBS_BASE_PATH')
ALERT_RESULTS_DIR = mcp_data_dir('seclab-taskflows', 'gh_code_scanning', 'ALERT_RESULTS_DIR')

def parse_alert(alert: dict) -> dict:
    """Parse the alert dictionary to extract relevant information."""
    def _parse_location(location: dict) -> str:
        """Parse the location dictionary to extract file and line information."""
        if not location:
            return 'No location information available'
        file_path = location.get('path', '')
        start_line = location.get('start_line', '')
        end_line = location.get('end_line', '')
        start_column = location.get('start_column', '')
        end_column = location.get('end_column', '')
        if not file_path or not start_line or not end_line or not start_column or not end_column:
            return 'No location information available'
        return f"{file_path}:{start_line}:{start_column}:{end_line}:{end_column}"
    def _get_language(category: str) -> str:
        return category.split(':')[1] if category and ':' in category else ''
    def _get_repo_from_html_url(html_url: str) -> str:
        """Extract the repository name from the HTML URL."""
        if not html_url:
            return ''
        parts = html_url.split('/')
        if len(parts) < 5:
            return ''
        return f"{parts[3]}/{parts[4]}".lower()

    parsed = {
        'alert_id': alert.get('number', 'No number'),
        'rule': alert.get('rule', {}).get('id', 'No rule'),
        'state': alert.get('state', 'No state'),
        'location': _parse_location(alert.get('most_recent_instance', {}).get('location', 'No location')),
        'language': _get_language(alert.get('most_recent_instance', {}).get('category', 'No language')),
        'created': alert.get('created_at', 'No created'),
        'updated': alert.get('updated_at', 'No updated'),
        'dismissed_comment': alert.get('dismissed_comment', ''),
    }
    return parsed

async def call_api(url: str, params: dict) -> str | httpx.Response:
    """Call the GitHub code scanning API to fetch alert."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                          "Authorization": f"Bearer {GH_TOKEN}"}
    async def _fetch_alerts(url, headers, params):
        try:
            async with httpx.AsyncClient(headers = headers) as client:
                r = await client.get(url, params=params)
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

    r = await _fetch_alerts(url, headers = headers, params=params)
    return r


@mcp.tool()
async def get_alert_by_number(owner: str = Field(description="The owner of the repo"),
                              repo: str = Field(description="The repository name."),
                                alert_number: int = Field(description="The alert number to get the alert for. Example: 1")) -> str:
    """Get the alert by number for a specific repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
    resp = await call_api(url, {})
    resp = resp.json()
    if isinstance(resp, dict):
        parsed_alert = parse_alert(resp)
        return json.dumps(parsed_alert)
    return resp

async def fetch_alerts_from_gh(owner: str, repo: str, state: str = 'open', rule = '') -> str:
    """Fetch all code scanning alerts for a specific repository."""
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
    if state not in ['open', 'closed', 'dismissed']:
        state = 'open'
    params = {'state': state, 'per_page': 100}
    #see https://github.com/octokit/plugin-paginate-rest.js/blob/8ec2713699ee473ee630be5c8a66b9665bcd4173/src/iterator.ts#L40
    link_pattern = re.compile(r'<([^<>]+)>;\s*rel="next"')
    results = []
    while True:
        resp = await call_api(url, params)
        resp_headers = resp.headers
        link = resp_headers.get('link', '')
        resp = resp.json()
        if isinstance(resp, list):
            this_results = [parse_alert(alert) for alert in resp]
            if rule:
                this_results = [alert for alert in this_results if alert.get('rule') == rule]
            results += this_results
        else:
            return resp + " url: " + url
        m = link_pattern.search(link)
        if not m:
            break
        url = m.group(1)
        params = parse_qs(urlparse(url).query)

    if results:
        return results
    return "No alerts found."

@mcp.tool()
async def fetch_alerts(owner: str = Field(description="The owner of the repo"),
                      repo: str = Field(description="The repository name."),
                      state: str = Field(default='open', description="The state of the alert to filter by. Default is 'open'."),
                      rule: str = Field(description='The rule of the alert to fetch', default = '')) -> str:
    """Fetch all code scanning alerts for a specific repository."""
    results = await fetch_alerts_from_gh(owner, repo, state, rule)
    if isinstance(results, str):
        return results
    return json.dumps(results, indent=2)

@mcp.tool()
async def fetch_alerts_to_sql(
    owner: str = Field(description="The owner of the repo"),
    repo: str = Field(description="The repository name."),
    state: str = Field(default='open', description="The state of the alert to filter by. Default is 'open'."),
    rule = Field(description='The rule of the alert to fetch', default = ''),
    rename_repo: str = Field(description="An optional alternative repo name for storing the alerts, if not specify, repo is used ", default = '')
    ) -> str:
    """Fetch all code scanning alerts for a specific repository and store them in a SQL database."""
    results = await fetch_alerts_from_gh(owner, repo, state, rule)
    sql_db_path = f"sqlite:///{ALERT_RESULTS_DIR}/alert_results.db" 
    if isinstance(results, str) or not results:
        return results
    engine = create_engine(sql_db_path, echo=False)
    Base.metadata.create_all(engine, tables=[AlertResults.__table__, AlertFlowGraph.__table__])
    with Session(engine) as session:
        for alert in results:
            session.add(AlertResults(
                alert_id=alert.get('alert_id', ''),
                repo = rename_repo.lower() if rename_repo else repo.lower(),
                language=alert.get('language', ''),
                rule=alert.get('rule', ''),
                location=alert.get('location', ''),
                result='',
                created=alert.get('created', ''),
                valid=True
            ))
        session.commit()

    return f"Stored {len(results)} alerts in the SQL database at {sql_db_path}."

async def _fetch_codeql_databases(owner: str, repo: str, language: str):
    """Fetch the CodeQL databases for a given repo and language."""
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/codeql/databases/{language}"
    headers = {"Accept": "application/zip,application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                          "Authorization": f"Bearer {os.getenv('GH_TOKEN')}"}
    try:
        async with httpx.AsyncClient() as client:
            async with client.stream('GET', url, headers =headers, follow_redirects=True) as response:
                response.raise_for_status()
                expected_path = f"{CODEQL_DBS_BASE_PATH}/{owner}/{repo}.zip"
                if os.path.realpath(expected_path) != expected_path:
                    return f"Error: Invalid path for CodeQL database: {expected_path}"
                if not Path(f"{CODEQL_DBS_BASE_PATH}/{owner}").exists():
                    os.makedirs(f"{CODEQL_DBS_BASE_PATH}/{owner}", exist_ok=True)
                async with aiofiles.open(f"{CODEQL_DBS_BASE_PATH}/{owner}/{repo}.zip", 'wb') as f:
                    async for chunk in response.aiter_bytes():
                        await f.write(chunk)
        # Unzip the downloaded file
        zip_path = Path(f"{CODEQL_DBS_BASE_PATH}/{owner}/{repo}.zip")
        if not zip_path.exists():
            return f"Error: CodeQL database for {repo} ({language}) does not exist."

        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(Path(f"{CODEQL_DBS_BASE_PATH}/{owner}/{repo}"))
        # Remove the zip file after extraction
        os.remove(zip_path)

        qldb_subfolder = language
        if Path(f"{CODEQL_DBS_BASE_PATH}/{owner}/{repo}/codeql_db").exists():
            qldb_subfolder = "codeql_db"

        return json.dumps({'message': f"CodeQL database for {repo} ({language}) fetched successfully.", 'relative_database_path': f"{owner}/{repo}/{qldb_subfolder}"})
    except httpx.RequestError as e:
        return f"Error: Request error: {e}"
    except httpx.HTTPStatusError as e:
        return f"Error: HTTP error: {e}"
    except Exception as e:
        return f"Error: An unexpected error occurred: {e}"

@mcp.tool()
async def fetch_database(owner: str = Field(description="The owner of the repo."),
                     repo: str = Field(description="The name of the repo."),
                     language: str = Field(description="The language used for the CodeQL database.")):
    """Fetch the CodeQL database for a given repo and language."""
    return await _fetch_codeql_databases(owner, repo, language)

@mcp.tool()
async def dismiss_alert(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    alert_id: str = Field(description="The ID of the alert to dismiss"),
    reason: str = Field(description="The reason for dismissing the alert. It must be less than 280 characters.")
) -> str:
    """
    Dismiss a code scanning alert.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_id}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": f"Bearer {GH_TOKEN}"
    }

    async with httpx.AsyncClient(headers=headers) as client:
        response = await client.patch(url, json={"state": "dismissed", "dismissed_reason": "false positive", "dismissed_comment": reason})
        response.raise_for_status()
        return response.text

@mcp.tool()
async def check_alert_issue_exists(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    alert_id: str = Field(description="The ID of the alert to check for an associated issue")
) -> str:
    """
    Check if an issue exists for a specific alert in a repository.
    """
    url = f"https://api.github.com/repos/{owner}/{repo}/issues"
    #see https://github.com/octokit/plugin-paginate-rest.js/blob/8ec2713699ee473ee630be5c8a66b9665bcd4173/src/iterator.ts#L40
    link_pattern = re.compile(r'<([^<>]+)>;\s*rel="next"')
    params = {"state": "open", "per_page": 100}
    while True:
        resp = await call_api(url, params=params)
        resp_headers = resp.headers
        link = resp_headers.get('link', '')
        resp = resp.json()
        if isinstance(resp, list):
            for issue in resp:
                if f"Alert {alert_id}" in issue.get("title", ""):
                    return f"Issue found: issue #{issue['number']} - {issue['title']}"
        else:
            return resp + " url: " + url
        m = link_pattern.search(link)
        if not m:
            break
        url = m.group(1)
        params = parse_qs(urlparse(url).query)
    return "No issue found for this alert."

@mcp.tool()
async def fetch_issues_matches(
    repo: str = Field(description="A comma separated list of repositories to search in. Each term is of the form owner/repo. For example: 'owner1/repo1,owner2/repo2'"),
    matches: str = Field(description="The search term to match against issue titles"),
    state: str = Field(default='open', description="The state of the issues to filter by. Default is 'open'."),
    labels: str = Field(default="", description="Labels to filter issues by")) -> str:
    """
    Fetch issues from a repository that match a specific title pattern.
    """
    old_repo = repo.split(",")
    results = []
    if not state:
        state = "open"
    for r in old_repo:
        url = f"https://api.github.com/repos/{r}/issues"
        params = {
            "state": state,
            "per_page": 100,
        }
        if labels:
            params["labels"] = labels
        #see https://github.com/octokit/plugin-paginate-rest.js/blob/8ec2713699ee473ee630be5c8a66b9665bcd4173/src/iterator.ts#L40
        link_pattern = re.compile(r'<([^<>]+)>;\s*rel="next"')
        while True:
            resp = await call_api(url, params=params)
            resp_headers = resp.headers
            link = resp_headers.get('link', '')
            resp = resp.json()
            if isinstance(resp, list):
                for issue in resp:
                    if matches in issue.get("title", "") or matches in issue.get("body", ""):
                        results.append({"title": issue["title"], "number": issue["number"], "repo": r, "body": issue.get("body", ""),
                                        "labels": issue.get("labels", [])})
            else:
                return resp + " url: " + url
            m = link_pattern.search(link)
            if not m:
                break
            url = m.group(1)
            params = parse_qs(urlparse(url).query)
    return json.dumps(results, indent=2)


if __name__ == "__main__":
    mcp.run(show_banner=False)

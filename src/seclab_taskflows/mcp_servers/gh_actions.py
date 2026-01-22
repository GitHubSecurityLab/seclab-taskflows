# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
from pydantic import Field
import httpx
import json
import os
import yaml
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from pathlib import Path
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_gh_actions.log'),
    filemode='a'
)

class Base(DeclarativeBase):
    pass

class WorkflowUses(Base):
    __tablename__ = 'workflow_uses'

    id: Mapped[int] = mapped_column(primary_key=True)
    user: Mapped[str]
    lines: Mapped[str]
    action_name: Mapped[str]
    repo: Mapped[str]

    def __repr__(self):
        return (f"<WorkflowUses(user={self.user}, lines={self.lines}, "
                f"action_name={self.action_name}, repo={self.repo})>")


mcp = FastMCP("GitHubCodeScanning")

high_privileged_triggers = set(["issues", "issue_comment", "pull_request_comment", "pull_request_review", "pull_request_review_comment",
                                "pull_request_target"])

unimportant_triggers = set(['pull_request', 'workflow_dispatch'])

GH_TOKEN = os.getenv('GH_TOKEN', default='')

ACTIONS_DB_DIR = mcp_data_dir('seclab-taskflows', 'gh_actions', 'ACTIONS_DB_DIR')

engine = create_engine(f'sqlite:///{os.path.abspath(ACTIONS_DB_DIR)}/actions.db', echo=False)
Base.metadata.create_all(engine, tables = [WorkflowUses.__table__])


async def call_api(url: str, params: dict, raw = False) -> str:
    """Call the GitHub code scanning API to fetch alert."""
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                          "Authorization": f"Bearer {GH_TOKEN}"}
    if raw:
        headers["Accept"] = "application/vnd.github.raw+json"
    async def _fetch(url, headers, params):
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

    r = await _fetch(url, headers = headers, params=params)
    return r

@mcp.tool()
async def fetch_workflow(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_id: str = Field(description="The ID or name of the workflow")) -> str:
    """
    Fetch the details of a GitHub Actions workflow.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}",
        params={}
    )
    if isinstance(r, str):
        return r
    return r.json()

@mcp.tool()
async def check_workflow_active(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_id: str = Field(description="The ID or name of the workflow")) -> str:
    """
    Check if a GitHub Actions workflow is active.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}",
        params={}
    )
    if isinstance(r, str):
        return r
    return f"Workflow {workflow_id} is {'active' if r.json().get('state') == 'active' else 'inactive'}."

def find_in_yaml(key, node):
    if isinstance(node, dict):
        for k, v in node.items():
            if k == key:
                yield v
            elif isinstance(v, dict) or isinstance(v, list):
                for result in find_in_yaml(key, v):
                    yield result
    elif isinstance(node, list):
        for item in node:
            for result in find_in_yaml(key, item):
                yield result

async def get_workflow_triggers(owner: str, repo: str, workflow_file_path: str) -> str:

    r = await call_api(
                url=f"https://api.github.com/repos/{owner}/{repo}/contents/{workflow_file_path}",
                params={}, raw = True
            )
    if isinstance(r, str):
        return json.dumps([r])
    data = yaml.safe_load(r.text)
    #'on' is parsed as 'True': https://github.com/yaml/pyyaml/issues/470
    triggers = list(find_in_yaml(True, data))
    return triggers

@mcp.tool()
async def find_workflow_run_dependency(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_file_path: str = Field(description="The file path of the workflow that is triggered by `workflow_run`"),
    high_privileged: bool = Field(description="Whether to return high privileged dependencies only.")
)->str:
    """
    Find the workflow that triggers this workflow_run.
    """
    r = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/contents/{workflow_file_path}",
        params={}, raw=True
    )
    if isinstance(r, str):
        return json.dumps([r])
    data = yaml.safe_load(r.text)
    trigger_workflow = list(find_in_yaml('workflow_run', data))[0].get('workflows', [])
    if not trigger_workflow:
        return json.dumps([], indent=2)
    r = await call_api(
    url=f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows",
    params={}, raw=True
    )
    if isinstance(r, str):
        return json.dumps([r])
    if not r.json():
        return json.dumps([], indent=2)
    paths_list = [item['path'] for item in r.json() if item['path'].endswith('.yml') or item['path'].endswith('.yaml')]

    results = []
    for path in paths_list:
        workflow_id = path.split('/')[-1]
        active =  await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}",
        params={}
        )
        if not isinstance(active, str) and active.json().get('state') == "active":
            r = await call_api(
                url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
                params={}, raw=True
            )
            if isinstance(r, str):
                return json.dumps([r])
            data = yaml.safe_load(r.text)
            name = data.get('name', '')
            if name in trigger_workflow or "*" in trigger_workflow:
                triggers = data.get(True, {})
                if not high_privileged or high_privileged_triggers.intersection(set(triggers)):
                    results.append({
                        "path": path,
                        "name": name,
                        "triggers": triggers
                    })
    return json.dumps(results, indent=2)

@mcp.tool()
async def get_workflow_trigger(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_file_path: str = Field(description="The file path of the workflow")) -> str:
    """
    Get the trigger of a GitHub Actions workflow.
    """
    return json.dumps(await get_workflow_triggers(owner, repo, workflow_file_path), indent=2)

@mcp.tool()
async def check_workflow_reusable(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_file_path: str = Field(description="The file path of the workflow")) -> str:
    """
    Check if a GitHub Actions workflow is reusable.
    """
    if workflow_file_path.endswith('/action.yml') or workflow_file_path.endswith('/action.yaml'):
        return "This workflow is reusable as an action."
    triggers = await get_workflow_triggers(owner, repo, workflow_file_path)
    print(f"Triggers found: {triggers}")
    for trigger in triggers:
        if isinstance(trigger, str) and trigger == "workflow_call":
            return "This workflow is reusable as a workflow call."
        elif isinstance(trigger, dict):
            for k, v in trigger.items():
                if 'workflow_call' == k:
                    return "This workflow is reusable."
    return "This workflow is not reusable."

@mcp.tool()
async def get_high_privileged_workflow_triggers(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_file_path: str = Field(description="The file path of the workflow")) -> str:
    """
    Gets the high privileged triggers for a workflow, if none returns, then the workflow is not high privileged.
    """
    triggers = await get_workflow_triggers(owner, repo, workflow_file_path)
    results = []
    for trigger in triggers:
        if isinstance(trigger, str):
            if trigger in high_privileged_triggers:
                results.append(trigger)
            elif trigger == 'workflow_run':
                results.append(trigger)
        elif isinstance(trigger, dict):
            this_results = {}
            for k, v in trigger.items():
                if k in high_privileged_triggers:
                    this_results[k] = v
                elif k == 'workflow_run':
                    if not v or isinstance(v, str):
                        this_results[k] = v
                    elif isinstance(v, dict) and not 'branches' in v:
                        this_results[k] = v
            if this_results:
                results.append(this_results)

    return json.dumps(["Workflow is high privileged" if results else "Workflow is not high privileged", results], indent = 2)

@mcp.tool()
async def get_workflow_user(
    owner: str = Field(description="The owner of the repository"),
    repo: str = Field(description="The name of the repository"),
    workflow_file_path: str = Field(description="The file path of the workflow"),
    save_to_db: bool = Field(description="Save the results to database.", default=False)) -> str:
    """
    Get the user of a reusable workflow in repo.
    """
    paths = workflow_file_path.split('/')
    if workflow_file_path.endswith('/action.yml') or workflow_file_path.endswith('/action.yaml'):
        action_name = paths[-2]
    else:
        action_name = paths[-1].replace('.yml', '').replace('.yaml', '')
    paths = await call_api(
        url=f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows",
        params={}
    )
    if isinstance(paths, str) or not paths.json():
        return json.dumps([], indent=2)

    paths_list = [item['path'] for item in paths.json() if item['path'].endswith('.yml') or item['path'].endswith('.yaml')]
    results = []
    for path in paths_list:
        r = await call_api(
            url=f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
            params={}, raw=True
        )
        if isinstance(r, str):
            continue
        data = yaml.safe_load(r.text)
        uses = list(find_in_yaml('uses', data))
        lines = r.text.splitlines()
        actual_name = {}
        for use in uses:
            if action_name in use:
                actual_name[use] = []
        for i, line in enumerate(lines):
            for use in actual_name.keys():
                if use in line:
                    actual_name[use].append(i + 1)
        for use, line_numbers in actual_name.items():
            if not line_numbers:
                continue
            results.append({
                "user": path,
                "lines": line_numbers,
                "action_name": workflow_file_path,
                "repo": f"{owner}/{repo}"
            })

    if not results:
        return json.dumps([])
    if save_to_db:
        with Session(engine) as session:
            for result in results:
                result['lines'] = json.dumps(result['lines'])  # Convert list of lines to JSON string
                result['repo'] = result['repo'].lower()
                workflow_use = WorkflowUses(**result)
                session.add(workflow_use)
            session.commit()
        return f"Search results saved to database."
    return json.dumps(results)

@mcp.tool()
def fetch_last_workflow_users_results() -> str:
    """
    Fetch the previous workflow users results from the database. Will delete the results after fetching.
    """
    with Session(engine) as session:
        results = session.query(WorkflowUses).all()
        session.query(WorkflowUses).delete()
        session.commit()
    return json.dumps([{"user": result.user, "lines" : json.loads(result.lines), "action": result.action_name, "repo" : result.repo.lower()} for result in results])

if __name__ == "__main__":
    mcp.run(show_banner=False)

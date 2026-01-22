# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
import json
from pathlib import Path
import os
from typing import Any
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from pydantic import Field
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name

from .alert_results_models import AlertResults, AlertFlowGraph, Base

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_report_alert_state.log'),
    filemode='a'
)

def result_to_dict(result):
    return {
        "canonical_id": result.canonical_id,
        "alert_id": result.alert_id,
        "repo": result.repo.lower(),
        "rule": result.rule,
        "language": result.language,
        "location": result.location,
        "result": result.result,
        "created": result.created,
        "valid": result.valid
    }

def flow_to_dict(flow):
    return {
        "id": flow.id,
        "alert_canonical_id": flow.alert_canonical_id,
        "flow_data": flow.flow_data,
        "repo": flow.repo.lower(),
        "prev": flow.prev,
        "next": flow.next
    }

def remove_line_numbers(location: str) -> str:
    """
    Remove line numbers from a location string.
    The location is expected to be in the format 'file:line:col:line:col'.
    """
    if not location:
        return location
    parts = location.split(':')
    if len(parts) < 4:  # Ensure there are enough parts to remove line numbers
        return location
    # Keep the first part (file path) and the last two parts (col:col)
    return ':'.join(parts[:-4])


MEMORY = mcp_data_dir('seclab-taskflows', 'report_alert_state', 'ALERT_RESULTS_DIR')

class ReportAlertStateBackend:
    def __init__(self, memcache_state_dir: str):
        self.memcache_state_dir = memcache_state_dir
        self.location_pattern = r'^([a-zA-Z]+)(:\d+){4}$'
        if not Path(self.memcache_state_dir).exists():
            db_dir = 'sqlite://'
        else:
            db_dir = f'sqlite:///{self.memcache_state_dir}/alert_results.db'
        self.engine = create_engine(db_dir, echo=False)
        Base.metadata.create_all(self.engine, tables=[AlertResults.__table__, AlertFlowGraph.__table__])

    def set_alert_result(self, alert_id: str, repo: str, rule: str, language: str, location: str, result: str, created: str) -> str:
        if not result:
            result = ""
        with Session(self.engine) as session:
            existing = session.query(AlertResults).filter_by(alert_id=alert_id, repo=repo, rule=rule, language=language).first()
            if existing:
                existing.result += result
            else:
                new_alert = AlertResults(
                    alert_id=alert_id,
                    repo=repo,
                    rule=rule,
                    language=language,
                    location=location,
                    result=result,
                    created=created,
                    valid=True,
                    completed=False
                )
                session.add(new_alert)
            session.commit()
        return f"Updated or added alert result for {alert_id} in {repo}"

    def update_alert_result(self, alert_id: str, repo: str, result: str) -> str:
        with Session(self.engine) as session:
            existing = session.query(AlertResults).filter_by(alert_id=alert_id, repo=repo).first()
            if not existing:
                return f"No alert result found for {alert_id} in {repo}"
            existing.result += result
            session.commit()
        return f"Updated alert result for {alert_id} in {repo}"

    def update_alert_result_by_canonical_id(self, canonical_id: int, result: str) -> str:
        with Session(self.engine) as session:
            existing = session.query(AlertResults).filter_by(canonical_id=canonical_id).first()
            if not existing:
                return f"No alert result found for canonical ID {canonical_id}"
            existing.result += result
            session.commit()
        return f"Updated alert result for canonical ID {canonical_id}"

    def set_alert_valid(self, alert_id: str, repo: str, valid: bool) -> str:
        with Session(self.engine) as session:
            existing = session.query(AlertResults).filter_by(alert_id=alert_id, repo=repo).first()
            if not existing:
                return f"No alert result found for {alert_id} in {repo}"
            existing.valid = valid
            session.commit()
        return f"Set alert validity for {alert_id} in {repo} to {valid}"

    def set_alert_completed(self, alert_id: str, repo: str, completed: bool) -> str:
        with Session(self.engine) as session:
            existing = session.query(AlertResults).filter_by(alert_id=alert_id, repo=repo).first()
            if not existing:
                return f"No alert result found for {alert_id} in {repo}"
            existing.completed = completed
            session.commit()
        return f"Set alert completion status for {alert_id} in {repo} to {completed}"

    def get_completed_alerts(self, rule: str, repo: str = None) -> Any:
        """Get all incomplete alerts in a repository."""
        filter_params = {'completed' : True}
        if repo:
            filter_params['repo'] = repo
        if rule:
            filter_params['rule'] = rule
        with Session(self.engine) as session:
            results = [result_to_dict(r) for r in session.query(AlertResults).filter_by(**filter_params).all()]
        return results

    def clear_completed_alerts(self, repo: str = None, rule: str = None) -> str:
        """Clear all completed alerts in a repository."""
        filter_params = {'completed': True}
        if repo:
            filter_params['repo'] = repo
        if rule:
            filter_params['rule'] = rule
        with Session(self.engine) as session:
            session.query(AlertResults).filter_by(**filter_params).delete()
            session.commit()
        return "Cleared completed alerts with repo: {}, rule: {}".format(repo if repo else "all", rule if rule else "all")

    def get_alert_results(self, alert_id: str, repo: str) -> str:
        with Session(self.engine) as session:
            result = session.query(AlertResults).filter_by(alert_id=alert_id, repo = repo).first()
        if not result:
            return "No results found."
        return "Analysis results for alert ID {} in repo {}: {}".format(alert_id, repo, result.result)

    def get_alert_by_canonical_id(self, canonical_id: int) -> Any:
        with Session(self.engine) as session:
            result = session.query(AlertResults).filter_by(canonical_id=canonical_id).first()
        if not result:
            return "No results found for the specified canonical ID."
        return result_to_dict(result)

    def get_alert_results_by_rule(self, rule: str, repo: str = None, valid: bool = None) -> Any:
        filter_params = {'rule': rule}
        if repo:
            filter_params['repo'] = repo
        if valid is not None:
            filter_params['valid'] = valid
        with Session(self.engine) as session:
            results = [result_to_dict(r) for r in session.query(AlertResults).filter_by(**filter_params).all()]
        return results
    def delete_alert_result(self, alert_id: str, repo: str) -> str:
        with Session(self.engine) as session:
            result = session.query(AlertResults).filter_by(alert_id=alert_id, repo=repo).delete()
            session.commit()
            return f"Deleted alert result for {alert_id} in {repo}"

    def clear_alert_results(self, repo : str = None, rule: str = None) -> str:
        filter_params = {}
        if repo:
            filter_params['repo'] = repo
        if rule:
            filter_params['rule'] = rule
        with Session(self.engine) as session:
            if not filter_params:
                session.query(AlertResults).delete()
            else:
                session.query(AlertResults).filter_by(**filter_params).delete()
            session.commit()
        return "Cleared alert results with repo: {}, rule: {}".format(repo if repo else "all", rule if rule else "all")

    def add_flow_to_alert(self, canonical_id: int, flow_data: str, repo: str, prev: str = None, next: str = None) -> str:
        """Add a flow graph for a specific alert result."""
        with Session(self.engine) as session:
            flow_graph = AlertFlowGraph(
                alert_canonical_id=canonical_id,
                flow_data=flow_data,
                repo=repo,
                prev=prev,
                next=next,
                started = False
            )
            session.add(flow_graph)
            session.commit()
        return f"Added flow graph for alert with canonical ID {canonical_id}"

    def batch_add_flow_to_alert(self, alert_canonical_id: int, flows: list[str], repo: str, prev: str, next: str) -> str:
        """Batch add flow graphs for multiple alert results."""
        with Session(self.engine) as session:
            for flow in flows:
                flow_graph = AlertFlowGraph(
                    alert_canonical_id=alert_canonical_id,
                    flow_data=flow.strip('"'),
                    repo=repo,
                    prev=prev,
                    next=next,
                    started = False
                )
                session.add(flow_graph)
            session.commit()
        return f"Added {len(flows)} flow graphs for alerts."

    def get_alert_flow(self, canonical_id: int) -> Any:
        """Get the flow graph for a specific alert result."""
        with Session(self.engine) as session:
            flow_graphs = session.query(AlertFlowGraph).filter_by(alert_canonical_id=canonical_id).all()
        return [flow_to_dict(fg) for fg in flow_graphs]

    def get_alert_flows_by_data(self, repo: str, flow_data: str) -> Any:
        """Get flow graphs for a specific alert result by repo and flow data."""
        with Session(self.engine) as session:
            flow_graphs = session.query(AlertFlowGraph).filter_by(repo=repo, flow_data=flow_data.strip('"')).all()
        return [flow_to_dict(fg) for fg in flow_graphs]

    def get_all_alert_flows(self) -> Any:
        """Get all flow graphs for all alert results."""
        with Session(self.engine) as session:
            flow_graphs = session.query(AlertFlowGraph).all()
        return [flow_to_dict(fg) for fg in flow_graphs]

    def delete_flow_graph_for_alert(self, alert_canonical_id: int) -> str:
        """Delete a flow graph for with an id."""
        with Session(self.engine) as session:
            result = session.query(AlertFlowGraph).filter_by(alert_canonical_id=alert_canonical_id).delete()
            session.commit()
        return f"Deleted flow graph with for alert with canonical iD {id}" if result else "No flow graph found to delete."

    def update_all_alert_results_for_flow_graph(self, next: str, repo: str, result: str) -> str:
        with Session(self.engine) as session:
            flow_graphs = session.query(AlertFlowGraph).filter_by(next=next, repo = repo).all()
            if not flow_graphs:
                return f"No flow graphs found with next value {next}"
            alert_canonical_ids = set([fg.alert_canonical_id for fg in flow_graphs])
            for alert_canonical_id in alert_canonical_ids:
                alert_result = session.query(AlertResults).filter_by(canonical_id=alert_canonical_id).first()
                if alert_result:
                    alert_result.result += result
            session.commit()
        return f"Updated alert results for flow graphs with next value {next} with result: {result}"

    def delete_flow_graph(self, id: int) -> str:
        """Delete a flow graph for with an id."""
        with Session(self.engine) as session:
            result = session.query(AlertFlowGraph).filter_by(id=id).delete()
            session.commit()
        return f"Deleted flow graph with ID {id}" if result else "No flow graph found to delete."

    def clear_flow_graphs(self) -> str:
        """Clear all flow graphs."""
        with Session(self.engine) as session:
            session.query(AlertFlowGraph).delete()
            session.commit()
        return "Cleared all flow graphs."

mcp = FastMCP("ReportAlertState")

backend = ReportAlertStateBackend(MEMORY)

def process_repo(repo):
    return repo.lower() if repo else None

@mcp.tool()
def create_alert(alert_id: str, repo: str, rule: str, language: str, location: str,
                     result: str = Field(description="The result of the alert analysis", default=""),
                     created: str = Field(description = "The creation time of the alert", default="")) -> str:
    """Create an alert using a specific alert ID in a repository."""
    return backend.set_alert_result(alert_id, process_repo(repo), rule, language, location, result, created)

@mcp.tool()
def update_alert_result(alert_id: str, repo: str, result: str) -> str:
    """Update an existing alert result for a specific alert ID in a repository."""
    return backend.update_alert_result(alert_id, process_repo(repo), result)

@mcp.tool()
def update_alert_result_by_canonical_id(canonical_id: int, result: str) -> str:
    """Update an existing alert result by canonical ID."""
    return backend.update_alert_result_by_canonical_id(canonical_id, result)

@mcp.tool()
def set_alert_valid(alert_id: str, repo: str, valid: bool) -> str:
    """Set the validity of an alert result for a specific alert ID in a repository."""
    return backend.set_alert_valid(alert_id, process_repo(repo), valid)

@mcp.tool()
def get_alert_results(alert_id: str, repo: str = Field(description="repo in the format owner/repo")) -> str:
    """Get the analysis results for a specific alert ID in a repository."""
    return backend.get_alert_results(alert_id, process_repo(repo))

@mcp.tool()
def get_alert_by_canonical_id(canonical_id: int) -> str:
    """Get alert results by canonical ID."""
    return json.dumps(backend.get_alert_by_canonical_id(canonical_id))

@mcp.tool()
def get_alert_results_by_rule(rule: str, repo: str = Field(description="Optional repository of the alert in the format of owner/repo", default = None)) -> str:
    """Get all alert results for a specific rule in a repository."""
    return json.dumps(backend.get_alert_results_by_rule(rule, process_repo(repo), None))

@mcp.tool()
def get_valid_alert_results_by_rule(rule: str, repo: str = Field(description="Optional repository of the alert in the format of owner/repo", default = None)) -> str:
    """Get all valid alert results for a specific rule in a repository."""
    return json.dumps(backend.get_alert_results_by_rule(rule, process_repo(repo), True))

@mcp.tool()
def get_invalid_alert_results(rule: str, repo: str = Field(description="Optional repository of the alert in the format of owner/repo", default = None)) -> str:
    """Get all valid alert results for a specific rule in a repository."""
    return json.dumps(backend.get_alert_results_by_rule(rule, process_repo(repo), False))

@mcp.tool()
def set_alert_completed(alert_id: str, repo: str = Field(description="repo in the format owner/repo")) -> str:
    """Set the completion status of an alert result for a specific alert ID in a repository."""
    return backend.set_alert_completed(alert_id, process_repo(repo), True)

@mcp.tool()
def get_completed_alerts(rule: str, repo: str = Field(description="repo in the format owner/repo", default = None)) -> str:
    """Get all complete alerts in a repository."""
    results = backend.get_completed_alerts(rule, process_repo(repo))
    return json.dumps(results)

@mcp.tool()
def clear_completed_alerts(repo: str = Field(description="repo in the format owner/repo", default = None), rule: str = None) -> str:
    """Clear all completed alerts in a repository."""
    return backend.clear_completed_alerts(process_repo(repo), rule)

@mcp.tool()
def clear_repo_results(repo: str = Field(description="repo in the format owner/repo")) -> str:
    """Clear all alert results for a specific repository."""
    return backend.clear_alert_results(process_repo(repo), None)

@mcp.tool()
def clear_rule_results(rule: str, repo: str = Field(description="repo in the format owner/repo", default = None)) -> str:
    """Clear all alert results for a specific rule in a repository."""
    return backend.clear_alert_results(process_repo(repo), rule)

@mcp.tool()
def clear_alert_results() -> str:
    """Clear all alert results."""
    return backend.clear_alert_results(None, None)

@mcp.tool()
def add_flow_to_alert(canonical_id: int, flow_data: str, repo: str = Field(description="repo in the format owner/repo"), prev: str = None, next: str = None) -> str:
    """Add a flow graph for a specific alert result."""
    flow_data = remove_line_numbers(flow_data)
    prev = remove_line_numbers(prev) if prev else None
    next = remove_line_numbers(next) if next else None
    backend.add_flow_to_alert(canonical_id, flow_data, process_repo(repo), prev, next)
    return f"Added flow graph for alert with canonical ID {canonical_id}"

@mcp.tool()
def batch_add_flow_to_alert(alert_canonical_id: int,
                            repo: str = Field(description="The repository name for the alert result in the format owner/repo"),
                            flows: str = Field(description="A JSON string containing a list of flows to add for the alert result."),
                            next: str = None, prev: str = None) -> str:
    """Batch add a list of paths to flow graphs for a specific alert result."""
    flows_list = flows.split(',')
    return backend.batch_add_flow_to_alert(alert_canonical_id, flows_list, process_repo(repo), prev, next)


@mcp.tool()
def get_alert_flow(canonical_id: int) -> str:
    """Get the flow graph for a specific alert result."""
    return json.dumps(backend.get_alert_flow(canonical_id))

@mcp.tool()
def get_all_alert_flows() -> str:
    """Get all flow graphs for all alert results."""
    return json.dumps(backend.get_all_alert_flows())

@mcp.tool()
def get_alert_flows_by_data(flow_data: str, repo: str = Field(description="repo in the format owner/repo")) -> str:
    """Get flow graphs for a specific alert result by repo and flow data."""
    flow_data = remove_line_numbers(flow_data)
    return json.dumps(backend.get_alert_flows_by_data(process_repo(repo), flow_data))

@mcp.tool()
def delete_flow_graph(id: int) -> str:
    """Delete a flow graph with id."""
    return backend.delete_flow_graph(id)

@mcp.tool()
def delete_flow_graph_for_alert(alert_canonical_id: int) -> str:
    """Delete a all flow graphs for an alert with a specific canonical ID."""
    return backend.delete_flow_graph_for_alert(alert_canonical_id)

@mcp.tool()
def update_all_alert_results_for_flow_graph(next: str, result: str, repo: str = Field(description="repo in the format owner/repo")) -> str:
    """Update all alert results for flow graphs with a specific next value."""
    if not '/' in repo:
        return "Invalid repository format. Please provide a repository in the format 'owner/repo'."
    next = remove_line_numbers(next) if next else None
    return backend.update_all_alert_results_for_flow_graph(next, process_repo(repo), result)

@mcp.tool()
def clear_flow_graphs() -> str:
    """Clear all flow graphs."""
    return backend.clear_flow_graphs()

if __name__ == "__main__":
    mcp.run(show_banner=False)

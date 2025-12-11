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

from .repo_context_models import Application, EntryPoint, UserAction, WebEntryPoint, ApplicationIssue, AuditResult, Base
from .utils import process_repo

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file_name('mcp_repo_context.log'),
    filemode='a'
)

MEMORY = mcp_data_dir('seclab-taskflows', 'repo_context', 'REPO_CONTEXT_DIR')

def app_to_dict(result):
    return {
        "app_id": result.id,
        "repo": result.repo.lower(),
        "location": result.location,
        "notes": result.notes,
        "is_app": result.is_app,
        "is_library": result.is_library
    }

def entry_point_to_dict(ep):
    return {
        "id": ep.id,
        "component_id": ep.app_id,
        "file": ep.file,
        "user_input": ep.user_input,
        "repo": ep.repo.lower(),
        "line": ep.line,
        "notes": ep.notes
    }

def user_action_to_dict(ua):
    return {
        "id": ua.id,
        "component_id": ua.app_id,
        "file": ua.file,
        "line": ua.line,
        "repo": ua.repo.lower(),
        "notes": ua.notes
    }

def web_entry_point_to_dict(wep):
    return {
        "id": wep.id,
        "entry_point_id": wep.entry_point_id,
        "method": wep.method,
        "path": wep.path,
        "component": wep.component,
        "auth": wep.auth,
        "middleware": wep.middleware,
        "roles_scopes": wep.roles_scopes,
        "repo": wep.repo.lower(),
        "notes": wep.notes
    }

def audit_result_to_dict(res):
    return {
        "id" : res.id,
        "repo" : res.repo.lower(),
        "component_id" : res.component_id,
        "issue_type" : res.issue_type,
        "issue_id" : res.issue_id,
        "notes" : res.notes,
        "has_vulnerability": res.has_vulnerability,
        "has_non_security_error": res.has_non_security_error
    }

class RepoContextBackend:
    def __init__(self, memcache_state_dir: str):
        self.memcache_state_dir = memcache_state_dir
        self.location_pattern = r'^([a-zA-Z]+)(:\d+){4}$'
        if not Path(self.memcache_state_dir).exists():
            db_dir = 'sqlite://'
        else:
            db_dir = f'sqlite:///{self.memcache_state_dir}/repo_context.db'
        self.engine = create_engine(db_dir, echo=False)
        Base.metadata.create_all(self.engine, tables=[Application.__table__, EntryPoint.__table__, UserAction.__table__,
                                                      WebEntryPoint.__table__, ApplicationIssue.__table__, AuditResult.__table__])

    def store_new_application(self, repo, location, is_app, is_library, notes):
        with Session(self.engine) as session:
            existing = session.query(Application).filter_by(repo = repo, location = location).first()
            if existing:
                if is_app is not None:
                    existing.is_app = is_app
                if is_library is not None:
                    existing.is_library = is_library
                existing.notes += notes
            else:
                new_application = Application(repo = repo, location = location, is_app = is_app, is_library = is_library, notes = notes)
                session.add(new_application)
            session.commit()
        return f"Updated or added application for {location} in {repo}."

    def store_new_component_issue(self, repo, component_id, issue_type, notes):
        with Session(self.engine) as session:
            existing = session.query(ApplicationIssue).filter_by(repo = repo, component_id = component_id, issue_type = issue_type).first()
            if existing:
                existing.notes += notes
            else:
                new_issue = ApplicationIssue(repo = repo, component_id = component_id, issue_type = issue_type, notes = notes)
                session.add(new_issue)
            session.commit()
        return f"Updated or added application issue for {repo} and {component_id}"

    def overwrite_component_issue_notes(self, id, notes):
        with Session(self.engine) as session:
            existing = session.query(ApplicationIssue).filter_by(id = id).first()
            if not existing:
                return f"Component issue with id {id} does not exist!"
            else:
                existing.notes += notes
            session.commit()
        return f"Updated notes for application issue with id {id}"

    def store_new_audit_result(self, repo, component_id, issue_type, issue_id, has_non_security_error, has_vulnerability, notes):
        with Session(self.engine) as session:
            existing = session.query(AuditResult).filter_by(repo = repo, issue_id = issue_id).first()
            if existing:
                existing.notes += notes
                existing.has_non_security_error = has_non_security_error
                existing.has_vulnerability = has_vulnerability
            else:
                new_result = AuditResult(repo = repo, component_id = component_id, issue_type = issue_type, issue_id = issue_id, notes = notes,
                has_non_security_error = has_non_security_error, has_vulnerability = has_vulnerability)
                session.add(new_result)
            session.commit()
        return f"Updated or added audit result for {repo} and {issue_id}"

    def store_new_entry_point(self, repo, app_id, file, user_input, line, notes, update = False):
        with Session(self.engine) as session:
            existing = session.query(EntryPoint).filter_by(repo = repo, file = file, line = line).first()
            if existing:
                existing.notes += notes
            else:
                if update:
                    return f"No entry point exists at repo {repo}, file {file} and line {line}"
                new_entry_point = EntryPoint(repo = repo, app_id = app_id, file = file, user_input = user_input, line = line, notes = notes)
                session.add(new_entry_point)
            session.commit()
        return f"Updated or added entry point for {file} and {line} in {repo}."

    def store_new_web_entry_point(self, repo, entry_point_id, method, path, component, auth, middleware, roles_scopes, notes, update = False):
        with Session(self.engine) as session:
            existing = session.query(WebEntryPoint).filter_by(repo = repo, entry_point_id = entry_point_id).first()
            if existing:
                existing.notes += notes
                if method:
                    existing.method = method
                if path:
                    existing.path = path
                if component is not None:
                    existing.component = component
                if auth:
                    existing.auth = auth
                if middleware:
                    existing.middleware = middleware
                if roles_scopes:
                    existing.roles_scopes = roles_scopes
            else:
                if update:
                    return f"No web entry point exists at repo {repo} with entry_point_id {entry_point_id}."
                new_web_entry_point = WebEntryPoint(
                    repo = repo,
                    entry_point_id = entry_point_id,
                    method = method,
                    path = path,
                    component = component,
                    auth = auth,
                    middleware = middleware,
                    roles_scopes = roles_scopes,
                    notes = notes
                )
                session.add(new_web_entry_point)
            session.commit()
        return f"Updated or added web entry point for entry_point_id {entry_point_id} in {repo}."

    def store_new_user_action(self, repo, app_id, file, line, notes, update = False):
        with Session(self.engine) as session:
            existing = session.query(UserAction).filter_by(repo = repo, file = file, line = line).first()
            if existing:
                existing.notes += notes
            else:
                if update:
                    return f"No user action exists at repo {repo}, file {file} and line {line}."
                new_user_action = UserAction(repo = repo, app_id = app_id, file = file, line = line, notes = notes)
                session.add(new_user_action)
            session.commit()
        return f"Updated or added user action for {file} and {line} in {repo}."

    def get_app(self, repo, location):
        with Session(self.engine) as session:
            existing = session.query(Application).filter_by(repo = repo, location = location).first()
            if not existing:
                return None
        return existing

    def get_apps(self, repo):
        with Session(self.engine) as session:
            existing = session.query(Application).filter_by(repo = repo).all()
        return [app_to_dict(app) for app in existing]

    def get_app_issues(self, repo, component_id):
        with Session(self.engine) as session:
            issues = session.query(Application, ApplicationIssue).filter(
                Application.repo == repo,
                Application.id == ApplicationIssue.component_id
            )
            if component_id is not None:
                issues = issues.filter(Application.id == component_id)
            issues = issues.all()
        return [{
                  'component_id': app.id,
                  'location' : app.location,
                  'repo' : app.repo,
                  'component_notes' : app.notes,
                  'issue_type' : issue.issue_type,
                  'issue_notes': issue.notes,
                  'issue_id' : issue.id
                } for app, issue in issues]

    def get_app_audit_results(self, repo, component_id, has_non_security_error, has_vulnerability):
        with Session(self.engine) as session:
            issues = session.query(Application, AuditResult).filter(Application.repo == repo
                     ).filter(Application.id == AuditResult.component_id)
            if component_id is not None:
                issues =  issues.filter(Application.id == component_id)
            if has_non_security_error is not None:
                issues = issues.filter(AuditResult.has_non_security_error == has_non_security_error)
            if has_vulnerability is not None:
                issues = issues.filter(AuditResult.has_vulnerability == has_vulnerability)
            issues = issues.all()
        return [{
                  'component_id': app.id,
                  'location' : app.location,
                  'repo' : app.repo,
                  'issue_type' : issue.issue_type,
                  'issue_id' : issue.issue_id,
                  'notes': issue.notes,
                  'has_vulnerability' : issue.has_vulnerability,
                  'has_non_security_error' : issue.has_non_security_error
                } for app, issue in issues]

    def get_app_entries(self, repo, location):
        with Session(self.engine) as session:
            results = session.query(Application, EntryPoint
            ).filter(Application.repo == repo, Application.location == location
            ).filter(EntryPoint.app_id == Application.id).all()
            eps = [entry_point_to_dict(ep) for app, ep in results]
        return eps

    def get_app_entries_for_repo(self, repo):
        with Session(self.engine) as session:
            results = session.query(Application, EntryPoint
            ).filter(Application.repo == repo
            ).filter(EntryPoint.app_id == Application.id).all()
            eps = [entry_point_to_dict(ep) for app, ep in results]
        return eps

    def get_web_entries_for_repo(self, repo):
        with Session(self.engine) as session:
            results = session.query(WebEntryPoint).filter_by(repo = repo).all()
        return [{
                    'repo' : r.repo,
                    'entry_point_id' : r.entry_point_id,
                    'method' : r.method,
                    'path' : r.path,
                    'component' : r.component,
                    'auth' : r.auth,
                    'middleware' : r.middleware,
                    'roles_scopes' : r.roles_scopes,
                    'notes' : r.notes
                } for r in results]

    def get_web_entries(self, repo, component_id):
        with Session(self.engine) as session:
            results = session.query(WebEntryPoint).filter_by(repo = repo, component = component_id).all()
        return [{
                    'repo' : r.repo,
                    'entry_point_id' : r.entry_point_id,
                    'method' : r.method,
                    'path' : r.path,
                    'component' : r.component,
                    'auth' : r.auth,
                    'middleware' : r.middleware,
                    'roles_scopes' : r.roles_scopes,
                    'notes' : r.notes
                } for r in results]


    def get_user_actions(self, repo, location):
        with Session(self.engine) as session:
            results = session.query(Application, UserAction
            ).filter(Application.repo == repo, Application.location == location
            ).filter(UserAction.app_id == Application.id).all()
            uas = [user_action_to_dict(ua) for app, ua in results]
        return uas

    def get_user_actions_for_repo(self, repo):
        with Session(self.engine) as session:
            results = session.query(Application, UserAction
            ).filter(Application.repo == repo
            ).filter(UserAction.app_id == Application.id).all()
            uas = [user_action_to_dict(ua) for app, ua in results]
        return uas

    def clear_repo(self, repo):
        with Session(self.engine) as session:
            session.query(Application).filter_by(repo = repo).delete()
            session.query(EntryPoint).filter_by(repo = repo).delete()
            session.query(UserAction).filter_by(repo = repo).delete()
            session.query(ApplicationIssue).filter_by(repo = repo).delete()
            session.query(WebEntryPoint).filter_by(repo = repo).delete()
            session.query(AuditResult).filter_by(repo = repo).delete()
            session.commit()
        return f"Cleared results for repo {repo}"

    def clear_repo_issues(self, repo):
        with Session(self.engine) as session:
            session.query(ApplicationIssue).filter_by(repo = repo).delete()
            session.commit()
        return f"Clear application issues for repo {repo}"


mcp = FastMCP("RepoContext")

backend = RepoContextBackend(MEMORY)

@mcp.tool()
def store_new_component(owner: str = Field(description="The owner of the GitHub repository"),
                        repo: str = Field(description="The name of the GitHub repository"),
                        location: str = Field(description="The directory of the component"),
                        is_app: bool = Field(description="Is this an application", default=None),
                        is_library: bool = Field(description="Is this a library", default=None),
                        notes: str = Field(description="The notes taken for this component", default="")):
    """
    Stores a new component in the database.
    """
    return backend.store_new_application(process_repo(owner, repo), location, is_app, is_library, notes)

@mcp.tool()
def add_component_notes(owner: str = Field(description="The owner of the GitHub repository"),
                        repo: str = Field(description="The name of the GitHub repository"),
                        location: str = Field(description="The directory of the component", default=None),
                        notes: str = Field(description="New notes taken for this component", default="")):
    """
    Add new notes to a component
    """
    repo = process_repo(owner, repo)
    app = backend.get_app(repo, location)
    if not app:
        return f"Error: No component exists in repo: {repo} and location {location}"
    return backend.store_new_application(repo, location, None, None, notes)

@mcp.tool()
def store_new_entry_point(owner: str = Field(description="The owner of the GitHub repository"),
                          repo: str = Field(description="The name of the GitHub repository"),
                          location: str = Field(description="The directory of the component where the entry point belongs to"),
                          file: str = Field(description="The file that contains the entry point"),
                          line: int = Field(description="The file line that contains the entry point"),
                          user_input: str = Field(description="The variables that are considered as user input"),
                          notes: str = Field(description="The notes for this entry point", default = "")):
    """
    Stores a new entry point in a component to the database.
    """
    repo = process_repo(owner, repo)
    app = backend.get_app(repo, location)
    if not app:
        return f"Error: No component exists in repo: {repo} and location {location}"
    return backend.store_new_entry_point(repo, app.id, file, user_input, line, notes)

@mcp.tool()
def store_new_component_issue(owner: str = Field(description="The owner of the GitHub repository"),
                              repo: str = Field(description="The name of the GitHub repository"),
                              component_id: int = Field(description="The ID of the component"),
                              issue_type: str = Field(description="The type of issue"),
                              notes: str = Field(description="Notes about the issue")):
    """
    Stores a type of common issue for a component.
    """
    repo = process_repo(owner, repo)
    return backend.store_new_component_issue(repo, component_id, issue_type, notes)

@mcp.tool()
def store_new_audit_result(owner: str = Field(description="The owner of the GitHub repository"),
                           repo: str = Field(description="The name of the GitHub repository"),
                           component_id: int = Field(description="The ID of the component"),
                           issue_type: str = Field(description="The type of issue"),
                           issue_id: int = Field(description="The ID of the issue"),
                           has_non_security_error: bool = Field(description="Set to true if there are security issues or logic error but may not be exploitable"),
                           has_vulnerability: bool = Field(description="Set to true if a security vulnerability is identified"),
                           notes: str = Field(description="The notes for the audit of this issue")):
    """
    Stores the audit result for issue with issue_id.
    """
    repo = process_repo(owner, repo)
    return backend.store_new_audit_result(repo, component_id, issue_type, issue_id, has_non_security_error, has_vulnerability, notes)

@mcp.tool()
def store_new_web_entry_point(owner: str = Field(description="The owner of the GitHub repository"),
                              repo: str = Field(description="The name of the GitHub repository"),
                              entry_point_id: int = Field(description="The ID of the entry point this web entry point refers to"),
                              location: str = Field(description="The directory of the component where the web entry point belongs to"),
                              method: str = Field(description="HTTP method (GET, POST, etc)", default=""),
                              path: str = Field(description="URL path (e.g., /info)", default=""),
                              component: int = Field(description="Component identifier", default=0),
                              auth: str = Field(description="Authentication information", default=""),
                              middleware: str = Field(description="Middleware information", default=""),
                              roles_scopes: str = Field(description="Roles and scopes information", default=""),
                              notes: str = Field(description="Notes for this web entry point", default="")):
    """
    Stores a new web entry point in a component to the database. A web entry point extends a regular entry point
    with web-specific properties like HTTP method, path, authentication, middleware, and roles/scopes.
    """
    return backend.store_new_web_entry_point(process_repo(owner, repo), entry_point_id, method, path, component, auth, middleware, roles_scopes, notes)

@mcp.tool()
def add_entry_point_notes(owner: str = Field(description="The owner of the GitHub repository"),
                          repo: str = Field(description="The name of the GitHub repository"),
                          location: str = Field(description="The directory of the component where the entry point belongs to"),
                          file: str = Field(description="The file that contains the entry point"),
                          line: int = Field(description="The file line that contains the entry point"),
                          notes: str = Field(description="The notes for this entry point", default = "")):
    """
    add new notes to an entry point.
    """
    repo = process_repo(owner, repo)
    app = backend.get_app(repo, location)
    if not app:
        return f"Error: No component exists in repo: {repo} and location {location}"
    return backend.store_new_entry_point(repo, app.id, file, None, line, notes, True)


@mcp.tool()
def store_new_user_action(owner: str = Field(description="The owner of the GitHub repository"),
                          repo: str = Field(description="The name of the GitHub repository"),
                          location: str = Field(description="The directory of the component where the user action belongs to"),
                          file: str = Field(description="The file that contains the user action"),
                          line: int = Field(description="The file line that contains the user action"),
                          notes: str = Field(description="New notes for this user action", default = "")):
    """
    Stores a new user action in a component to the database.
    """
    repo = process_repo(owner, repo)
    app = backend.get_app(repo, location)
    if not app:
        return f"Error: No component exists in repo: {repo} and location {location}"
    return backend.store_new_user_action(repo, app.id, file, line, notes)

@mcp.tool()
def add_user_action_notes(owner: str = Field(description="The owner of the GitHub repository"),
                          repo: str = Field(description="The name of the GitHub repository"),
                          location: str = Field(description="The directory of the component where the user action belongs to"),
                          file: str = Field(description="The file that contains the user action"),
                          line: str = Field(description="The file line that contains the user action"),
                          notes: str = Field(description="The notes for user action", default = "")):
    repo = process_repo(owner, repo)
    app = backend.get_app(repo, location)
    if not app:
        return f"Error: No component exists in repo: {repo} and location {location}"
    return backend.store_new_user_action(repo, app.id, file, line, notes, True)

@mcp.tool()
def get_component(owner: str = Field(description="The owner of the GitHub repository"),
                  repo: str = Field(description="The name of the GitHub repository"),
                  location: str = Field(description="The directory of the component")):
    """
    Get a component from the database
    """
    repo = process_repo(owner, repo)
    app = backend.get_app(repo, location)
    if not app:
        return f"Error: No component exists in repo: {repo} and location {location}"
    return json.dumps(app_to_dict(app))

@mcp.tool()
def get_components(owner: str = Field(description="The owner of the GitHub repository"),
                   repo: str = Field(description="The name of the GitHub repository")):
    """
    Get components from the repo
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_apps(repo))

@mcp.tool()
def get_entry_points(owner: str = Field(description="The owner of the GitHub repository"),
                     repo: str = Field(description="The name of the GitHub repository"),
                     location: str = Field(description="The directory of the component")):
    """
    Get all the entry points of a component.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_entries(repo, location))

@mcp.tool()
def get_entry_points_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                              repo: str = Field(description="The name of the GitHub repository")):
    """
    Get all entry points of an repo
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_entries_for_repo(repo))

@mcp.tool()
def get_web_entry_points_component(owner: str = Field(description="The owner of the GitHub repository"),
                                   repo: str = Field(description="The name of the GitHub repository"),
                                   component_id: int = Field(description="The ID of the component")):
    """
    Get all web entry points for a component
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_web_entries(repo, component_id))

@mcp.tool()
def get_web_entry_points_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                                  repo: str = Field(description="The name of the GitHub repository")):
    """
    Get all web entry points of an repo
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_web_entries_for_repo(repo))

@mcp.tool()
def get_user_actions(owner: str = Field(description="The owner of the GitHub repository"),
                     repo: str = Field(description="The name of the GitHub repository"),
                     location: str = Field(description="The directory of the component")):
    """
    Get all the user actions in a component.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_user_actions(repo, location))

@mcp.tool()
def get_user_actions_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                              repo: str = Field(description="The name of the GitHub repository")):
    """
    Get all the user actions in a repo.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_user_actions_for_repo(repo))

@mcp.tool()
def get_component_issues(owner: str = Field(description="The owner of the GitHub repository"),
                         repo: str = Field(description="The name of the GitHub repository"),
                         component_id: int = Field(description="The ID of the component")):
    """
    Get issues for the component.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_issues(repo, component_id))

@mcp.tool()
def get_component_issues_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                         repo: str = Field(description="The name of the GitHub repository")):
    """
    Get all component issues for the repository.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_issues(repo, None))


@mcp.tool()
def get_component_results(owner: str = Field(description="The owner of the GitHub repository"),
                          repo: str = Field(description="The name of the GitHub repository"),
                          component_id: int = Field(description="The ID of the component")):
    """
    Get audit results for the component.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_audit_results(repo, component_id, None, None))

@mcp.tool()
def get_component_vulnerable_results(owner: str = Field(description="The owner of the GitHub repository"),
                                     repo: str = Field(description="The name of the GitHub repository"),
                                     component_id: int = Field(description="The ID of the component")):
    """
    Get audit results for the component that are audited as vulnerable.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_audit_results(repo, component_id, has_non_security_error = None, has_vulnerability = True))

@mcp.tool()
def get_component_potential_results(owner: str = Field(description="The owner of the GitHub repository"),
                                    repo: str = Field(description="The name of the GitHub repository"),
                                    component_id: int = Field(description="The ID of the component")):
    """
    Get audit results for the component that are audited as an issue but may not be exploitable.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_audit_results(repo, component_id, has_non_security_error = True, has_vulnerability = None))

@mcp.tool()
def get_audit_results_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                               repo: str = Field(description="The name of the GitHub repository")):
    """
    Get audit results for the repo.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_audit_results(repo, component_id = None, has_non_security_error = None, has_vulnerability = None))

@mcp.tool()
def get_vulnerable_audit_results_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                                          repo: str = Field(description="The name of the GitHub repository")):
    """
    Get audit results for the repo that are audited as vulnerable.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_audit_results(repo, component_id = None, has_non_security_error = None, has_vulnerability = True))

@mcp.tool()
def get_potential_audit_results_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                                         repo: str = Field(description="The name of the GitHub repository")):
    """
    Get audit results for the repo that are potential issues but may not be exploitable.
    """
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_app_audit_results(repo, component_id = None, has_non_security_error = True, has_vulnerability = None))

@mcp.tool()
def clear_repo(owner: str = Field(description="The owner of the GitHub repository"),
               repo: str = Field(description="The name of the GitHub repository")):
    """
    clear all results for repo.
    """
    repo = process_repo(owner, repo)
    return backend.clear_repo(repo)

@mcp.tool()
def clear_component_issues_for_repo(owner: str = Field(description="The owner of the GitHub repository"),
                                    repo: str = Field(description="The name of the GitHub repository")):
    """
    clear all results for repo.
    """
    repo = process_repo(owner, repo)
    return backend.clear_repo_issues(repo)

if __name__ == "__main__":
    mcp.run(show_banner=False)

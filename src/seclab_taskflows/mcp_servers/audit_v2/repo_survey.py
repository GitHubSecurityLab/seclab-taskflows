# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""MCP server exposing the audit v2 repository survey.

This is the v2 counterpart to ``repo_context``. It records what a repository
is made of and where untrusted data enters it, in terms that apply to any kind
of software rather than to web applications specifically.

``repo_context`` is untouched, so v1 taskflows keep working; a v2 audit simply
uses this store instead.
"""

import json
import logging
from pathlib import Path

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name, mcp_data_dir
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from ..utils import process_repo
from .repo_survey_models import (
    COMPONENT_KINDS,
    KIND_OTHER,
    TRUST_BOUNDARIES,
    Base,
    Component,
    EntryPoint,
    component_to_dict,
    entry_point_to_dict,
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_repo_survey.log"),
    filemode="a",
)

MEMORY = mcp_data_dir("seclab-taskflows", "repo_survey", "REPO_SURVEY_DIR")


class InvalidSurveyValueError(ValueError):
    """Raised when a caller supplies a value outside an allowed set."""


def _require(value: str, allowed, name: str, default: str | None = None) -> str:
    """Validate an enum-like argument, raising a message the model can act on."""
    normalized = (value or "").strip().lower()
    if not normalized and default is not None:
        return default
    if normalized not in allowed:
        msg = f"invalid {name} {value!r}; expected one of: {', '.join(allowed)}"
        raise InvalidSurveyValueError(msg)
    return normalized


class RepoSurveyBackend:
    """Durable store for the audit v2 survey.

    Always writes a real database file for the same reason the finding ledger
    does: a survey that silently evaporates would send every later stage
    hunting an empty map.
    """

    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        Path(self.state_dir).mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{self.state_dir}/repo_survey.db", echo=False)
        Base.metadata.create_all(
            self.engine, tables=[Component.__table__, EntryPoint.__table__]
        )

    # -- writes ------------------------------------------------------------

    def store_component(
        self, repo, location, kind, language, runtime, is_app, is_library, notes
    ):
        kind = _require(kind, COMPONENT_KINDS, "kind", default=KIND_OTHER)
        with Session(self.engine) as session:
            # A component is the unit the hunt stage fans out over, so two
            # components at one location would have the hunt read the same code
            # twice and report the same paths twice. It would also leave the
            # entry points in that file split arbitrarily between them. One
            # location is therefore one component, and a second description of
            # the same location enriches the first.
            existing = (
                session.query(Component)
                .filter(Component.repo == repo, Component.location == location)
                .first()
            )
            if existing is not None:
                self._enrich_component(existing, kind, language, runtime, is_app, is_library, notes)
                session.commit()
                return existing.id
            component = Component(
                repo=repo,
                location=location,
                kind=kind,
                language=language or "",
                runtime=runtime or "",
                is_app=bool(is_app),
                is_library=bool(is_library),
                notes=notes or "",
            )
            session.add(component)
            session.commit()
            return component.id

    @staticmethod
    def _enrich_component(existing, kind, language, runtime, is_app, is_library, notes):
        """Fold a second description of a location into the record already held."""
        for field, value in (("language", language), ("runtime", runtime)):
            if value and not getattr(existing, field):
                setattr(existing, field, value)
        if kind != KIND_OTHER and existing.kind == KIND_OTHER:
            existing.kind = kind
        # Reachable as a program in any pass's reading means reachable, and the
        # same for being callable as a library; plenty of components are both.
        existing.is_app = bool(existing.is_app or is_app)
        existing.is_library = bool(existing.is_library or is_library)
        if notes and notes not in (existing.notes or ""):
            existing.notes = f"{existing.notes}\n\n{notes}".strip()

    def store_entry_point(
        self, repo, component_id, file, line, trust_boundary, untrusted_input, variables, notes
    ):
        trust_boundary = _require(trust_boundary, TRUST_BOUNDARIES, "trust_boundary")
        line = int(line or 0)
        with Session(self.engine) as session:
            if session.get(Component, component_id) is None:
                return f"No component with id {component_id}"
            # An entry point is a place in the code, so the same file, line and
            # boundary is the same entry point no matter which pass found it.
            # Several passes do find it: the mapping task and every fan-out
            # branch read the same sources, and a branch will happily record an
            # entry point that belongs to a sibling component. Recording those
            # separately would make the hunt stage work each one repeatedly.
            existing = (
                session.query(EntryPoint)
                .filter(
                    EntryPoint.repo == repo,
                    EntryPoint.file == file,
                    EntryPoint.line == line,
                    EntryPoint.trust_boundary == trust_boundary,
                )
                .first()
            )
            if existing is not None:
                # Fill in what an earlier pass left blank, but let its wording
                # stand, so a later terser pass cannot erase a better note.
                for field, value in (
                    ("untrusted_input", untrusted_input),
                    ("variables", variables),
                    ("notes", notes),
                ):
                    if value and not getattr(existing, field):
                        setattr(existing, field, value)
                session.commit()
                return existing.id
            entry_point = EntryPoint(
                repo=repo,
                component_id=component_id,
                file=file,
                line=line,
                trust_boundary=trust_boundary,
                untrusted_input=untrusted_input or "",
                variables=variables or "",
                notes=notes or "",
            )
            session.add(entry_point)
            session.commit()
            return entry_point.id

    # -- reads -------------------------------------------------------------

    def get_components(self, repo):
        with Session(self.engine) as session:
            rows = session.query(Component).filter(Component.repo == repo).all()
            return [component_to_dict(c) for c in rows]

    def get_component(self, component_id):
        with Session(self.engine) as session:
            component = session.get(Component, component_id)
            if component is None:
                return None
            data = component_to_dict(component)
            rows = (
                session.query(EntryPoint)
                .filter(EntryPoint.component_id == component_id)
                .all()
            )
            data["entry_points"] = [entry_point_to_dict(e) for e in rows]
            return data

    def get_entry_points(self, repo, component_id=None):
        with Session(self.engine) as session:
            query = session.query(EntryPoint).filter(EntryPoint.repo == repo)
            if component_id:
                query = query.filter(EntryPoint.component_id == component_id)
            return [entry_point_to_dict(e) for e in query.all()]

    def get_survey_summary(self, repo):
        with Session(self.engine) as session:
            components = session.query(Component).filter(Component.repo == repo).all()
            entry_points = session.query(EntryPoint).filter(EntryPoint.repo == repo).all()
            by_boundary: dict[str, int] = dict.fromkeys(TRUST_BOUNDARIES, 0)
            for e in entry_points:
                by_boundary[e.trust_boundary] = by_boundary.get(e.trust_boundary, 0) + 1
            return {
                "repo": repo,
                "components": len(components),
                "entry_points": len(entry_points),
                "by_trust_boundary": by_boundary,
            }

    def clear_survey(self, repo):
        with Session(self.engine) as session:
            components = session.query(Component).filter(Component.repo == repo).delete()
            session.query(EntryPoint).filter(EntryPoint.repo == repo).delete()
            session.commit()
            return components


backend = RepoSurveyBackend(str(MEMORY))

mcp = FastMCP("RepoSurvey")


@mcp.tool()
def store_component(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    location: str = Field(description="Directory or module path of the component"),
    kind: str = Field(
        description=f"What kind of component this is, one of: {', '.join(COMPONENT_KINDS)}",
        default=KIND_OTHER,
    ),
    language: str = Field(description="Primary implementation language", default=""),
    runtime: str = Field(description="Runtime or platform it executes on", default=""),
    is_app: bool = Field(description="True if it is reached as a running program", default=False),
    is_library: bool = Field(description="True if it is consumed by callers as an API", default=False),
    notes: str = Field(
        description="What it does, who talks to it across which trust boundary, "
        "and what makes it interesting to attack",
        default="",
    ),
):
    """Store a component of the repository and return its id."""
    repo = process_repo(owner, repo)
    try:
        component_id = backend.store_component(
            repo, location, kind, language, runtime, is_app, is_library, notes
        )
    except InvalidSurveyValueError as exc:
        return str(exc)
    return json.dumps({"component_id": component_id})


@mcp.tool()
def store_entry_point(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    component_id: int = Field(description="The id of the component this entry point belongs to"),
    file: str = Field(description="Path to the file containing the entry point"),
    trust_boundary: str = Field(
        description=f"Which boundary is crossed, one of: {', '.join(TRUST_BOUNDARIES)}"
    ),
    line: int = Field(description="Line number of the entry point", default=0),
    untrusted_input: str = Field(
        description="What untrusted data arrives here and where it came from", default=""
    ),
    variables: str = Field(description="Variables carrying the untrusted data", default=""),
    notes: str = Field(
        description="Why the data on the other side of the boundary is untrusted", default=""
    ),
):
    """Store an entry point where untrusted data crosses into a component."""
    repo = process_repo(owner, repo)
    try:
        result = backend.store_entry_point(
            repo, component_id, file, line, trust_boundary, untrusted_input, variables, notes
        )
    except InvalidSurveyValueError as exc:
        return str(exc)
    if isinstance(result, str):
        return result
    return json.dumps({"entry_point_id": result})


@mcp.tool()
def get_components(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Get every component recorded for a repository."""
    return json.dumps(backend.get_components(process_repo(owner, repo)))


@mcp.tool()
def get_component(
    component_id: int = Field(description="The id of the component"),
):
    """Get one component together with its entry points."""
    component = backend.get_component(component_id)
    if component is None:
        return f"No component with id {component_id}"
    return json.dumps(component)


@mcp.tool()
def get_entry_points(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    component_id: int = Field(
        description="Optionally restrict to one component; 0 means all", default=0
    ),
):
    """Get the entry points for a repository, optionally for one component."""
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_entry_points(repo, component_id or None))


@mcp.tool()
def get_survey_summary(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Get counts of components and entry points, grouped by trust boundary."""
    return json.dumps(backend.get_survey_summary(process_repo(owner, repo)))


@mcp.tool()
def clear_survey_for_repo(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Delete every component and entry point recorded for a repository."""
    repo = process_repo(owner, repo)
    removed = backend.clear_survey(repo)
    return f"Cleared survey for {repo} ({removed} components)"


if __name__ == "__main__":
    mcp.run()

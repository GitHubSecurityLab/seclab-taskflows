# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Schema for the audit v2 repository survey.

The v1 ``repo_context`` store is shaped around web applications: it models
applications, web entry points, security entry points and user actions. That
shape is a good fit for auditing a web app and a poor fit for auditing a
parser, a daemon, a build plugin or a native library, which is what audit v2
is meant to cover.

This is a separate store rather than a change to ``repo_context`` so that
existing v1 taskflows keep working exactly as they do today.

The organising idea here is the trust boundary. A component is a unit of code
worth reasoning about on its own, and an entry point is a place where data
crosses into it from somewhere less trusted. Both are deliberately neutral
about what kind of software is being audited.
"""

from __future__ import annotations

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, func
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# What kind of thing a component is. This is descriptive, not a taxonomy to
# argue about; it exists so a hunter knows how the code is reached.
KIND_APPLICATION = "application"
KIND_SERVICE = "service"
KIND_LIBRARY = "library"
KIND_PARSER = "parser"
KIND_CLI = "cli"
KIND_DAEMON = "daemon"
KIND_PLUGIN = "plugin"
KIND_OTHER = "other"
COMPONENT_KINDS = (
    KIND_APPLICATION,
    KIND_SERVICE,
    KIND_LIBRARY,
    KIND_PARSER,
    KIND_CLI,
    KIND_DAEMON,
    KIND_PLUGIN,
    KIND_OTHER,
)

# Which boundary the untrusted data crosses. This is the field that generalises
# the v1 notion of a "web entry point" to arbitrary software.
BOUNDARY_NETWORK = "network"
BOUNDARY_FILE = "file"
BOUNDARY_IPC = "ipc"
BOUNDARY_PROCESS = "process"
BOUNDARY_STORED_DATA = "stored_data"
BOUNDARY_PACKAGE_CONTENT = "package_content"
BOUNDARY_LIBRARY_API = "library_api"
BOUNDARY_OTHER = "other"
TRUST_BOUNDARIES = (
    BOUNDARY_NETWORK,
    BOUNDARY_FILE,
    BOUNDARY_IPC,
    BOUNDARY_PROCESS,
    BOUNDARY_STORED_DATA,
    BOUNDARY_PACKAGE_CONTENT,
    BOUNDARY_LIBRARY_API,
    BOUNDARY_OTHER,
)


class Component(Base):
    """A unit of functionality that can be reasoned about on its own."""

    __tablename__ = "component_v2"

    id = Column(Integer, primary_key=True)
    repo = Column(String, index=True, nullable=False)
    location = Column(String, nullable=False)
    kind = Column(String, default=KIND_OTHER)
    language = Column(String, default="")
    runtime = Column(String, default="")
    # Kept alongside `kind` because "can a caller pass me attacker data?" and
    # "am I reachable over the network?" are independent questions, and a
    # component is frequently both a library and an application.
    is_app = Column(Boolean, default=False)
    is_library = Column(Boolean, default=False)
    notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class EntryPoint(Base):
    """A place where data crosses into a component from somewhere less trusted."""

    __tablename__ = "entry_point_v2"

    id = Column(Integer, primary_key=True)
    repo = Column(String, index=True, nullable=False)
    component_id = Column(Integer, index=True, nullable=False)
    file = Column(String, nullable=False)
    line = Column(Integer, default=0)
    trust_boundary = Column(String, default=BOUNDARY_OTHER)
    untrusted_input = Column(Text, default="")
    variables = Column(Text, default="")
    notes = Column(Text, default="")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


# These projections are the wire contract the taskflows declare `outputs` against,
# so they live here, importable without starting a server or opening a database.
def component_to_dict(c: Component) -> dict:
    return {
        "component_id": c.id,
        "repo": c.repo,
        "location": c.location,
        "kind": c.kind,
        "language": c.language,
        "runtime": c.runtime,
        "is_app": bool(c.is_app),
        "is_library": bool(c.is_library),
        "notes": c.notes,
    }


def entry_point_to_dict(e: EntryPoint) -> dict:
    return {
        "entry_point_id": e.id,
        "repo": e.repo,
        "component_id": e.component_id,
        "file": e.file,
        "line": e.line,
        "trust_boundary": e.trust_boundary,
        "untrusted_input": e.untrusted_input,
        "variables": e.variables,
        "notes": e.notes,
    }

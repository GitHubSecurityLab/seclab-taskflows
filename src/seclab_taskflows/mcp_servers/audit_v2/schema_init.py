# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Schema creation that survives several servers starting at once.

Every branch of a fanned-out task starts its own copy of an MCP server, so a
stage that hunts three components with three models opens nine of them within
the same second, all pointed at one SQLite file.

``Base.metadata.create_all`` is not safe under that. It checks whether a table
exists and then creates it, which is two statements with a gap in between. Two
servers that both look at an empty database both decide to create, and the
loser gets ``table finding already exists``. That exception propagates out of
the server's module-level setup, the process exits, and the runner reports only
``Error initializing MCP server: Connection closed`` — so the branch runs on
with no ledger and files nothing, which looks like a model that found nothing.

The table the loser wanted exists either way, so the error is not interesting:
retry until every table is present.
"""

import time
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

__all__ = ["create_all_tolerating_races", "open_state_engine"]

_RETRIES = 8
_BACKOFF_SECONDS = 0.05


def create_all_tolerating_races(base, engine, tables) -> None:
    """Create *tables*, treating a concurrent creator as success."""
    for attempt in range(_RETRIES):
        try:
            base.metadata.create_all(engine, tables=tables)
        except OperationalError as exc:
            if "already exists" not in str(exc).lower():
                raise
            # Another server won this table. It may still be creating the
            # rest, so pause and re-check rather than assuming all are ready.
            time.sleep(_BACKOFF_SECONDS * (attempt + 1))
        else:
            return
    # Every attempt collided. Let a real failure surface rather than starting
    # a server whose schema may be incomplete.
    base.metadata.create_all(engine, tables=tables)


def open_state_engine(state_dir, db_filename, base, tables):
    """Open a real on-disk SQLite engine for *db_filename* under *state_dir*.

    Both audit v2 stores must persist. An in-memory fallback would let an audit
    run to completion, promote findings and print a summary, and then leave
    nothing on disk. So the directory is created if missing, a file-backed
    engine is opened, and the schema is initialised race-tolerantly.
    """
    directory = Path(state_dir)
    directory.mkdir(parents=True, exist_ok=True)
    # A fanned-out stage opens one server per branch and the pool can hand a
    # connection to a different thread than the one that opened it, so the
    # default same-thread check would raise. SQLite serialises access itself.
    engine = create_engine(
        f"sqlite:///{directory / db_filename}",
        echo=False,
        connect_args={"check_same_thread": False},
    )
    create_all_tolerating_races(base, engine, tables)
    return engine

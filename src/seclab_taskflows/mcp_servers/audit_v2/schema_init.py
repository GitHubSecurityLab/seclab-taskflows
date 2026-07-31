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

from sqlalchemy.exc import OperationalError

__all__ = ["create_all_tolerating_races"]

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

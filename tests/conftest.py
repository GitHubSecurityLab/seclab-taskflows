# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Shared pytest configuration.

Several MCP server modules open their log file and their state database at
import time, so the destination has to be chosen before any test module is
imported. Left alone they write into the user's real application support and
log directories, which makes the suite depend on -- and mutate -- state outside
the checkout. Point them at a throwaway directory instead, without overriding a
value the caller deliberately set.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="seclab-taskflows-tests-")

for _var, _sub in (
    ("LOG_DIR", "logs"),
    ("FINDING_LEDGER_DIR", "finding_ledger"),
    ("REPO_SURVEY_DIR", "repo_survey"),
    ("REPO_CONTEXT_DIR", "repo_context"),
):
    if not os.environ.get(_var):
        _path = os.path.join(_TMP, _sub)
        os.makedirs(_path, exist_ok=True)
        os.environ[_var] = _path

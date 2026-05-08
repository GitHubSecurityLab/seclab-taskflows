# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""FastMCP server: guarded freeform host shell.

Used by the fuzzing taskflow during the build-system analysis and harness
authoring phases, where the agent legitimately needs to run arbitrary
``./configure`` / ``make`` / ``cmake`` invocations on the host.

The toolbox YAML lists ``shell_exec`` under ``confirm`` so each call is
surfaced to the user. By default commands run inside ``LOCAL_SHELL_CWD`` (or
``$HOME`` if unset) and write nothing outside the workspace.
"""

import logging
import os
import shlex
import subprocess
from pathlib import Path
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_local_shell.log"),
    filemode="a",
)

mcp = FastMCP("LocalShell")

DEFAULT_CWD = os.environ.get("LOCAL_SHELL_CWD") or str(Path.home())
DEFAULT_TIMEOUT = int(os.environ.get("LOCAL_SHELL_TIMEOUT") or "120")
MAX_OUTPUT = int(os.environ.get("LOCAL_SHELL_MAX_OUTPUT") or "8000")


@mcp.tool()
def shell_exec(
    command: Annotated[str, Field(description="Shell command (single string, runs in bash -c)")],
    workdir: Annotated[str, Field(description="Working directory; defaults to LOCAL_SHELL_CWD or $HOME")] = "",
    timeout_seconds: Annotated[int, Field(description="Hard timeout in seconds")] = DEFAULT_TIMEOUT,
) -> str:
    """Execute a shell command on the host and return combined stdout/stderr + exit code.

    This tool is intentionally narrow in *behaviour* (single command, hard timeout,
    bounded output) but not in *capability*: it can run anything bash can. The toolbox
    YAML lists it under ``confirm`` so each invocation is surfaced to the user.
    """
    cwd = workdir or DEFAULT_CWD
    if not Path(cwd).is_dir():
        return f"[error] working directory does not exist: {cwd}"
    logging.debug("shell_exec cwd=%s timeout=%d cmd=%s", cwd, timeout_seconds, command)
    try:
        proc = subprocess.run(
            ["bash", "-c", command], cwd=cwd, capture_output=True, text=True,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or "") if isinstance(e.stdout, str) else ""
        err = (e.stderr or "") if isinstance(e.stderr, str) else ""
        return f"{out[-MAX_OUTPUT // 2:]}{err[-MAX_OUTPUT // 2:]}\n[exit code: timeout after {timeout_seconds}s]"
    body = proc.stdout
    if proc.stderr:
        body += proc.stderr
    body = body[-MAX_OUTPUT:]
    return f"{body}\n[exit code: {proc.returncode}]"


@mcp.tool()
def write_file(
    path: Annotated[str, Field(description="Absolute path to write")],
    content: Annotated[str, Field(description="File content (UTF-8)")],
    create_dirs: Annotated[bool, Field(description="Create parent directories")] = True,
) -> str:
    """Write a UTF-8 text file. Used by the agent to author harness sources and seeds."""
    p = Path(path)
    if create_dirs:
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return f"wrote {len(content)} bytes to {path}"


@mcp.tool()
def write_bytes(
    path: Annotated[str, Field(description="Absolute path to write")],
    hex_content: Annotated[str, Field(description="Hex-encoded bytes (e.g. 'deadbeef')")],
    create_dirs: Annotated[bool, Field(description="Create parent directories")] = True,
) -> str:
    """Write a binary file from a hex string. Used for binary seed corpora."""
    try:
        data = bytes.fromhex(hex_content.strip())
    except ValueError as e:
        return f"[error] invalid hex: {e}"
    p = Path(path)
    if create_dirs:
        p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return f"wrote {len(data)} bytes to {path}"


if __name__ == "__main__":
    mcp.run(show_banner=False)

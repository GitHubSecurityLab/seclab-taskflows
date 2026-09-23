# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""MCP server that runs shell commands inside a managed Docker container.

Configuration is read from the process environment (set per toolbox in the
toolbox YAML's ``server_params.env`` block):

- ``CONTAINER_IMAGE`` — image to run (required).
- ``CONTAINER_WORKSPACE`` — host path bind-mounted at ``/workspace`` (optional).
- ``CONTAINER_WORKSPACE_MOUNT_MODE`` — bind-mount mode for that path, ``rw`` (default)
  or ``ro``. The default preserves the historical writable mount, because the
  shipped source-access and SAST prompts build symbol indexes in-tree
  (``ctags -R .``, ``cscope -R -b``, ``gtags``). Set it to ``ro`` when the
  workspace should be left pristine — for example when the caller collects the
  tree afterwards as an artifact and wants a faithful copy of the input. Only a
  literal ``ro`` selects read-only; any other value mounts read-write.
- ``CONTAINER_TIMEOUT`` — default per-command timeout in seconds (default 30).
- ``CONTAINER_PERSIST`` — reuse a deterministic container across runs when truthy.
- ``CONTAINER_PERSIST_KEY`` — extra key to distinguish persistent containers.
- ``CONTAINER_NETWORK`` — Docker network for the container. Defaults to
  ``none`` so the container is egress-locked. Set it to ``bridge``, ``host``, or
  a user-defined network to enable networking.

Selecting a network mode from a toolbox: the agent passes only the toolbox's
declared ``env`` entries to this server, so a network mode is selectable at run
time only if the toolbox exposes the knob. To let callers opt in, add an
environment variable passthrough line to the toolbox ``env`` block, e.g.::

    CONTAINER_NETWORK: "{{ env('CONTAINER_NETWORK', 'none') }}"

A toolbox that needs networking by default (e.g. recon tooling) can use
``'bridge'`` as the template default instead. An empty or unset value always
falls back to ``none``, so isolation cannot be disabled by a blank variable.

Transport:

- ``CONTAINER_SHELL_TRANSPORT`` — MCP transport. Defaults to ``stdio`` for the
  standard local case where the agent launches this server as a subprocess. Set
  it to ``http``, ``streamable-http``, or ``sse`` to run as a network-accessible
  MCP server that a remote agent can connect to.
- ``CONTAINER_SHELL_HOST`` / ``CONTAINER_SHELL_PORT`` — bind address for the
  network transports (defaults ``127.0.0.1`` / ``8080``); ignored for ``stdio``.

Which Docker daemon this server drives is orthogonal to the transport: the
docker CLI honours ``DOCKER_HOST`` from the environment, so pointing this server
at a specific (e.g. dedicated, isolated) daemon needs no code change here.
"""

import atexit
import hashlib
import json
import logging
import os
import subprocess
import uuid
from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("container_shell.log"),
    filemode="a",
)

mcp = FastMCP("ContainerShell")

_container_name: str | None = None

CONTAINER_IMAGE = os.environ.get("CONTAINER_IMAGE", "")
CONTAINER_WORKSPACE = os.environ.get("CONTAINER_WORKSPACE", "")
# Bind-mount mode for CONTAINER_WORKSPACE. Defaults to "rw", which preserves
# the historical behaviour: the shipped source-access and SAST prompts tell the
# model to build symbol indexes in-tree (`ctags -R .`, `cscope -R -b`, `gtags`),
# which write into the workspace. Setting this to "ro" is worth doing whenever
# the caller collects the workspace afterwards as an artifact, since a writable
# mount makes that artifact agent-influenced rather than a faithful copy of the
# input. Flipping the default would require redirecting those index outputs
# first. Only a literal "ro" selects read-only, so a blank or unrecognized
# value cannot accidentally break a workflow that needs to write.
CONTAINER_WORKSPACE_MOUNT_MODE = (
    "ro" if os.environ.get("CONTAINER_WORKSPACE_MOUNT_MODE", "").strip().lower() == "ro" else "rw"
)
CONTAINER_TIMEOUT = int(os.environ.get("CONTAINER_TIMEOUT", "30"))
CONTAINER_PERSIST = os.environ.get("CONTAINER_PERSIST", "").lower() in ("1", "true", "yes")
CONTAINER_PERSIST_KEY = os.environ.get("CONTAINER_PERSIST_KEY", "")
# Docker network mode for the container. Defaults to "none" so containers are
# egress-locked (no network access) unless a caller explicitly opts in by
# setting CONTAINER_NETWORK to a network name such as "bridge", "host", or a
# user-defined network. An empty or whitespace-only value falls back to "none"
# so the isolation default cannot be silently disabled by an unset variable.
CONTAINER_NETWORK = os.environ.get("CONTAINER_NETWORK", "none").strip() or "none"
# MCP transport selection. Defaults to "stdio" for the standard local case
# where the agent launches this server as a subprocess. Set
# CONTAINER_SHELL_TRANSPORT to "http", "streamable-http", or "sse" to run as a
# network-accessible server (for example, an isolated sidecar reached by a
# remote agent); CONTAINER_SHELL_HOST/PORT control the bind address for those
# transports and are ignored for stdio.
CONTAINER_SHELL_TRANSPORT = os.environ.get("CONTAINER_SHELL_TRANSPORT", "stdio").strip() or "stdio"
CONTAINER_SHELL_HOST = os.environ.get("CONTAINER_SHELL_HOST", "127.0.0.1").strip() or "127.0.0.1"
# Kept as a raw string and parsed to an int lazily in _run_server() so an
# invalid value only fails when a network transport is actually selected, not at
# import time under the default stdio transport (where host/port are ignored).
CONTAINER_SHELL_PORT = os.environ.get("CONTAINER_SHELL_PORT", "8080")
_SUPPORTED_TRANSPORTS = ("stdio", "http", "streamable-http", "sse")

_DEFAULT_WORKDIR = "/workspace"
_DOCKER_TIMEOUT = 30


def _persistent_name() -> str:
    """Derive a deterministic container name from the image for reuse across tasks.

    Incorporates a hash of the full image reference, mounted workspace,
    configured network mode, and optional CONTAINER_PERSIST_KEY to avoid
    collisions between independent runs that use the same image with different
    source trees. Including the network mode ensures a run configured for one
    network (e.g. the default "none") never reuses a persistent container that
    was created with a different, more permissive network (e.g. "bridge"),
    which would otherwise silently re-enable egress.

    The workspace mount mode is included for the same reason, but only when it
    differs from the "rw" default. Appending it unconditionally would change the
    derived name for every persistent container that already exists, orphaning
    each one on upgrade: _start_container() only ever inspects or removes the
    name it computes, and persistent containers are normally left running, so a
    non-forcing ``docker rm`` would not collect them either. Omitting the field
    at the default keeps those names byte-identical, while an explicit "ro" run
    still gets a distinct name and so cannot reuse a writable container.
    """
    key_material = f"{CONTAINER_IMAGE}:{CONTAINER_WORKSPACE}:net={CONTAINER_NETWORK}"
    if CONTAINER_WORKSPACE_MOUNT_MODE != "rw":
        key_material += f":ws={CONTAINER_WORKSPACE_MOUNT_MODE}"
    if CONTAINER_PERSIST_KEY:
        key_material += f":{CONTAINER_PERSIST_KEY}"
    digest = hashlib.sha256(key_material.encode()).hexdigest()[:12]
    return f"seclab-persist-{digest}"


def _is_running(name: str) -> bool:
    """Check if a container with the given name is already running."""
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "json", name],
            capture_output=True,
            text=True,
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            return False
        data = json.loads(result.stdout)
        return bool(data and data[0].get("State", {}).get("Running"))
    except (subprocess.TimeoutExpired, json.JSONDecodeError, IndexError):
        return False


def _remove_container(name: str) -> None:
    """Remove a stopped container by name. Logs failures for diagnostics.

    Uses ``docker rm`` (without -f) so that running containers are NOT
    killed — only genuinely stopped leftovers are cleaned up.
    """
    try:
        result = subprocess.run(
            ["docker", "rm", name],
            capture_output=True,
            text=True,
            timeout=_DOCKER_TIMEOUT,
        )
        if result.returncode != 0:
            logging.debug(
                "docker rm skipped for %s: %s", name, result.stderr.strip()
            )
    except subprocess.TimeoutExpired:
        logging.exception("docker rm timed out for %s after %ds", name, _DOCKER_TIMEOUT)


def _start_container() -> str:
    """Start the Docker container and return its name."""
    if not CONTAINER_IMAGE:
        msg = "CONTAINER_IMAGE is not set — cannot start container"
        raise RuntimeError(msg)
    if CONTAINER_WORKSPACE and ":" in CONTAINER_WORKSPACE:
        msg = f"CONTAINER_WORKSPACE must not contain a colon: {CONTAINER_WORKSPACE!r}"
        raise RuntimeError(msg)

    if CONTAINER_PERSIST:
        name = _persistent_name()
        if _is_running(name):
            logging.debug(f"Reusing persistent container: {name}")
            return name
        # Remove stopped leftover with the same name
        _remove_container(name)
    else:
        name = f"seclab-shell-{uuid.uuid4().hex[:8]}"

    cmd = ["docker", "run", "-d", "--name", name, "--network", CONTAINER_NETWORK]
    if not CONTAINER_PERSIST:
        cmd.append("--rm")
    if CONTAINER_WORKSPACE:
        cmd += ["-v", f"{CONTAINER_WORKSPACE}:/workspace:{CONTAINER_WORKSPACE_MOUNT_MODE}"]
    cmd += [CONTAINER_IMAGE, "tail", "-f", "/dev/null"]
    logging.debug(f"Starting container: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=_DOCKER_TIMEOUT)
    if result.returncode != 0:
        msg = f"docker run failed: {result.stderr.strip()}"
        raise RuntimeError(msg)
    logging.debug(f"Container started: {name} (persist={CONTAINER_PERSIST})")
    return name


def _stop_container() -> None:
    """Stop the running container (skipped for persistent containers)."""
    global _container_name
    if _container_name is None:
        return
    if CONTAINER_PERSIST:
        logging.debug(f"Leaving persistent container running: {_container_name}")
        _container_name = None
        return
    logging.debug(f"Stopping container: {_container_name}")
    result = subprocess.run(
        ["docker", "stop", "--time", "5", _container_name],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logging.warning(
            "docker stop failed for container %s: %s",
            _container_name,
            result.stderr.strip(),
        )
    _container_name = None


atexit.register(_stop_container)


@mcp.tool()
def container_shell_exec(
    command: Annotated[str, Field(description="Shell command to execute inside the container")],
    timeout: Annotated[int, Field(description="Timeout in seconds")] = CONTAINER_TIMEOUT,
    workdir: Annotated[str, Field(description="Working directory inside the container")] = _DEFAULT_WORKDIR,
) -> str:
    """Execute a shell command inside the managed Docker container."""
    global _container_name
    if _container_name is None:
        try:
            _container_name = _start_container()
        except RuntimeError as e:
            return f"Failed to start container: {e}"

    cmd = ["docker", "exec", "-w", workdir, _container_name, "bash", "-c", command]
    logging.debug(f"Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return f"[exit code: timeout after {timeout}s]"

    output = result.stdout
    if result.stderr:
        output += result.stderr
    output += f"[exit code: {result.returncode}]"
    return output


def _run_server() -> None:
    """Run the MCP server using the configured transport.

    Defaults to stdio (local subprocess use). When CONTAINER_SHELL_TRANSPORT
    selects a network transport, the server binds CONTAINER_SHELL_HOST:PORT so a
    remote agent can reach it.
    """
    if CONTAINER_SHELL_TRANSPORT not in _SUPPORTED_TRANSPORTS:
        msg = (
            f"Unsupported CONTAINER_SHELL_TRANSPORT {CONTAINER_SHELL_TRANSPORT!r}; "
            f"expected one of {', '.join(_SUPPORTED_TRANSPORTS)}"
        )
        raise ValueError(msg)
    if CONTAINER_SHELL_TRANSPORT == "stdio":
        mcp.run(show_banner=False)
    else:
        try:
            port = int(CONTAINER_SHELL_PORT)
        except (TypeError, ValueError) as exc:
            msg = (
                f"Invalid CONTAINER_SHELL_PORT {CONTAINER_SHELL_PORT!r}; "
                f"expected an integer for transport {CONTAINER_SHELL_TRANSPORT!r}"
            )
            raise ValueError(msg) from exc
        mcp.run(
            transport=CONTAINER_SHELL_TRANSPORT,
            host=CONTAINER_SHELL_HOST,
            port=port,
            show_banner=False,
        )


if __name__ == "__main__":
    _run_server()

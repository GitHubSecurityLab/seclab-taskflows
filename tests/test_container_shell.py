# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import atexit
import importlib
import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import seclab_taskflows.mcp_servers.container_shell as cs_mod
from seclab_taskflow_agent.available_tools import AvailableTools
from seclab_taskflow_agent.models import ToolboxDocument


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proc(returncode=0, stdout="", stderr=""):
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


def _reset_container():
    """Reset global container state between tests."""
    cs_mod._container_name = None


def _reload_cs():
    """Reload cs_mod without accumulating atexit handlers.

    The module registers ``_stop_container`` with ``atexit`` at import time, so
    reloading would stack a fresh handler each time. Unregister the current one
    first so exactly one handler remains after the reload.
    """
    atexit.unregister(cs_mod._stop_container)
    return importlib.reload(cs_mod)


def _restore_env_and_reload(var, original):
    """Restore an env var to its pre-test value and reload cs_mod.

    Reloading with the real environment (rather than the monkeypatched value)
    keeps the module-level config from leaking into subsequent tests.
    """
    if original is None:
        os.environ.pop(var, None)
    else:
        os.environ[var] = original
    _reload_cs()


# ---------------------------------------------------------------------------
# _start_container tests
# ---------------------------------------------------------------------------

class TestStartContainer:
    def setup_method(self):
        _reset_container()

    def test_start_container_success(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", "/host/workspace"),
            patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run,
        ):
            name = cs_mod._start_container()
            assert name.startswith("seclab-shell-")
            cmd = mock_run.call_args[0][0]
            assert "docker" in cmd
            assert "run" in cmd
            assert "--name" in cmd
            assert "-v" in cmd
            assert "/host/workspace:/workspace:ro" in cmd
            assert "test-image:latest" in cmd
            assert "tail" in cmd

    def test_start_container_no_workspace(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run,
        ):
            name = cs_mod._start_container()
            assert name.startswith("seclab-shell-")
            cmd = mock_run.call_args[0][0]
            assert "-v" not in cmd

    def test_start_container_workspace_read_only_by_default(self):
        """The workspace mount is read-only unless a caller opts in."""
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", "/host/workspace"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE_MODE", "ro"),
            patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run,
        ):
            cs_mod._start_container()
            cmd = mock_run.call_args[0][0]
            assert "/host/workspace:/workspace:ro" in cmd

    def test_start_container_workspace_rw_opt_in(self):
        """CONTAINER_WORKSPACE_MODE=rw restores a writable mount."""
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", "/host/workspace"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE_MODE", "rw"),
            patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run,
        ):
            cs_mod._start_container()
            cmd = mock_run.call_args[0][0]
            assert "/host/workspace:/workspace:rw" in cmd

    def test_start_container_failure(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "missing-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch("subprocess.run", return_value=_make_proc(returncode=1, stderr="image not found")),
        ):
            with pytest.raises(RuntimeError, match="docker run failed"):
                cs_mod._start_container()

    def test_start_container_rejects_colon_in_workspace(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", "/host/path:ro"),
        ):
            with pytest.raises(RuntimeError, match="CONTAINER_WORKSPACE must not contain a colon"):
                cs_mod._start_container()

    def test_start_container_rejects_empty_image(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", ""),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
        ):
            with pytest.raises(RuntimeError, match="CONTAINER_IMAGE is not set"):
                cs_mod._start_container()

    def test_start_container_default_network_none(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch.object(cs_mod, "CONTAINER_NETWORK", "none"),
            patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run,
        ):
            cs_mod._start_container()
            cmd = mock_run.call_args[0][0]
            assert "--network" in cmd
            assert cmd[cmd.index("--network") + 1] == "none"

    def test_start_container_opt_in_network(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch.object(cs_mod, "CONTAINER_NETWORK", "bridge"),
            patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run,
        ):
            cs_mod._start_container()
            cmd = mock_run.call_args[0][0]
            assert "--network" in cmd
            assert cmd[cmd.index("--network") + 1] == "bridge"

    def test_workspace_mode_defaults_to_ro_when_unset(self, monkeypatch):
        original = os.environ.get("CONTAINER_WORKSPACE_MODE")
        monkeypatch.delenv("CONTAINER_WORKSPACE_MODE", raising=False)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_WORKSPACE_MODE == "ro"
        finally:
            _restore_env_and_reload("CONTAINER_WORKSPACE_MODE", original)

    @pytest.mark.parametrize("value", ["", "   ", "\t", "bogus", "readwrite", "ro"])
    def test_workspace_mode_falls_back_to_ro(self, monkeypatch, value):
        """Only an explicit "rw" opts in; anything else is read-only."""
        original = os.environ.get("CONTAINER_WORKSPACE_MODE")
        monkeypatch.setenv("CONTAINER_WORKSPACE_MODE", value)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_WORKSPACE_MODE == "ro"
        finally:
            _restore_env_and_reload("CONTAINER_WORKSPACE_MODE", original)

    @pytest.mark.parametrize("value", ["rw", "RW", " rw "])
    def test_workspace_mode_rw_opt_in(self, monkeypatch, value):
        original = os.environ.get("CONTAINER_WORKSPACE_MODE")
        monkeypatch.setenv("CONTAINER_WORKSPACE_MODE", value)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_WORKSPACE_MODE == "rw"
        finally:
            _restore_env_and_reload("CONTAINER_WORKSPACE_MODE", original)

    def test_network_defaults_to_none_when_unset(self, monkeypatch):
        original = os.environ.get("CONTAINER_NETWORK")
        monkeypatch.delenv("CONTAINER_NETWORK", raising=False)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_NETWORK == "none"
        finally:
            _restore_env_and_reload("CONTAINER_NETWORK", original)

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_network_falls_back_to_none_when_blank(self, monkeypatch, blank):
        original = os.environ.get("CONTAINER_NETWORK")
        monkeypatch.setenv("CONTAINER_NETWORK", blank)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_NETWORK == "none"
        finally:
            _restore_env_and_reload("CONTAINER_NETWORK", original)


# ---------------------------------------------------------------------------
# container_shell_exec tests
# ---------------------------------------------------------------------------

class TestShellExec:
    def setup_method(self):
        _reset_container()

    def test_container_shell_exec_lazy_start(self):
        start_proc = _make_proc(returncode=0)
        exec_proc = _make_proc(returncode=0, stdout="hello\n")
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch("subprocess.run", side_effect=[start_proc, exec_proc]),
        ):
            assert cs_mod._container_name is None
            result = cs_mod.container_shell_exec(command="echo hello")
            assert cs_mod._container_name is not None
            assert "hello" in result

    def test_container_shell_exec_runs_command(self):
        cs_mod._container_name = "seclab-shell-testtest"
        exec_proc = _make_proc(returncode=0, stdout="output\n")
        with patch("subprocess.run", return_value=exec_proc) as mock_run:
            result = cs_mod.container_shell_exec(command="echo output", workdir="/workspace")
            cmd = mock_run.call_args[0][0]
            assert "docker" in cmd
            assert "exec" in cmd
            assert "-w" in cmd
            assert "/workspace" in cmd
            assert "seclab-shell-testtest" in cmd
            assert "echo output" in cmd
            assert "output" in result

    def test_container_shell_exec_includes_exit_code(self):
        cs_mod._container_name = "seclab-shell-testtest"
        exec_proc = _make_proc(returncode=0, stdout="done\n")
        with patch("subprocess.run", return_value=exec_proc):
            result = cs_mod.container_shell_exec(command="true")
            assert "[exit code: 0]" in result

    def test_container_shell_exec_nonzero_exit(self):
        cs_mod._container_name = "seclab-shell-testtest"
        exec_proc = _make_proc(returncode=1, stdout="", stderr="error\n")
        with patch("subprocess.run", return_value=exec_proc):
            result = cs_mod.container_shell_exec(command="false")
            assert "[exit code: 1]" in result
            assert "error" in result

    def test_container_shell_exec_timeout(self):
        cs_mod._container_name = "seclab-shell-testtest"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5)):
            result = cs_mod.container_shell_exec(command="sleep 999", timeout=5)
            assert "timeout" in result

    def test_container_shell_exec_start_failure_returns_error(self):
        _reset_container()
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "bad-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch("subprocess.run", return_value=_make_proc(returncode=1, stderr="image not found")),
        ):
            result = cs_mod.container_shell_exec(command="echo hi")
            assert "Failed to start container" in result
            assert cs_mod._container_name is None


# ---------------------------------------------------------------------------
# _stop_container tests
# ---------------------------------------------------------------------------

class TestStopContainer:
    def setup_method(self):
        _reset_container()

    def test_stop_container_called_on_atexit(self):
        cs_mod._container_name = "seclab-shell-tostop"
        with patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run:
            cs_mod._stop_container()
            cmd = mock_run.call_args[0][0]
            assert "docker" in cmd
            assert "stop" in cmd
            assert "seclab-shell-tostop" in cmd
            assert cs_mod._container_name is None

    def test_stop_container_no_op_when_none(self):
        cs_mod._container_name = None
        with patch("subprocess.run") as mock_run:
            cs_mod._stop_container()
            mock_run.assert_not_called()

    def test_stop_container_clears_name_on_failure(self):
        cs_mod._container_name = "seclab-shell-tostop"
        with patch("subprocess.run", return_value=_make_proc(returncode=1, stderr="not found")):
            cs_mod._stop_container()
            assert cs_mod._container_name is None


# ---------------------------------------------------------------------------
# Persistent container tests
# ---------------------------------------------------------------------------

class TestPersistentContainer:
    def setup_method(self):
        _reset_container()

    def test_persistent_name_uses_hash(self):
        with patch.object(cs_mod, "CONTAINER_IMAGE", "myregistry.io/org/image:v1.2.3"):
            with patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""):
                name = cs_mod._persistent_name()
                assert name.startswith("seclab-persist-")
                assert len(name) == len("seclab-persist-") + 12

    def test_persistent_name_varies_with_key(self):
        with patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"):
            with patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""):
                name_a = cs_mod._persistent_name()
            with patch.object(cs_mod, "CONTAINER_PERSIST_KEY", "run-42"):
                name_b = cs_mod._persistent_name()
            assert name_a != name_b

    def test_persistent_name_differs_for_different_images(self):
        with patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""):
            with patch.object(cs_mod, "CONTAINER_IMAGE", "image-a:latest"):
                name_a = cs_mod._persistent_name()
            with patch.object(cs_mod, "CONTAINER_IMAGE", "image-b:latest"):
                name_b = cs_mod._persistent_name()
            assert name_a != name_b

    def test_persistent_name_differs_for_different_workspaces(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""),
        ):
            with patch.object(cs_mod, "CONTAINER_WORKSPACE", "/source/tree-a"):
                name_a = cs_mod._persistent_name()
            with patch.object(cs_mod, "CONTAINER_WORKSPACE", "/source/tree-b"):
                name_b = cs_mod._persistent_name()
            assert name_a != name_b

    def test_persistent_name_varies_with_workspace_mode(self):
        """A "ro" run must not reuse a container created with a writable mount."""
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", "/source/tree"),
            patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""),
        ):
            with patch.object(cs_mod, "CONTAINER_WORKSPACE_MODE", "ro"):
                name_ro = cs_mod._persistent_name()
            with patch.object(cs_mod, "CONTAINER_WORKSPACE_MODE", "rw"):
                name_rw = cs_mod._persistent_name()
            assert name_ro != name_rw

    def test_persistent_name_varies_with_network(self):
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""),
        ):
            with patch.object(cs_mod, "CONTAINER_NETWORK", "none"):
                name_none = cs_mod._persistent_name()
            with patch.object(cs_mod, "CONTAINER_NETWORK", "bridge"):
                name_bridge = cs_mod._persistent_name()
            assert name_none != name_bridge

    def test_start_reuses_running_persistent_container(self):
        inspect_proc = _make_proc(
            returncode=0,
            stdout='[{"State":{"Running":true}}]',
        )
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch.object(cs_mod, "CONTAINER_PERSIST", True),
            patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""),
            patch("subprocess.run", return_value=inspect_proc) as mock_run,
        ):
            name = cs_mod._start_container()
            assert name.startswith("seclab-persist-")
            # Only docker inspect should be called, NOT docker run
            assert mock_run.call_count == 1
            cmd = mock_run.call_args[0][0]
            assert cmd == ["docker", "inspect", "--format", "json", name]

    def test_start_persistent_no_rm_flag(self):
        inspect_proc = _make_proc(
            returncode=1,
            stdout="",
        )
        rm_proc = _make_proc(returncode=0)
        run_proc = _make_proc(returncode=0)
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch.object(cs_mod, "CONTAINER_PERSIST", True),
            patch.object(cs_mod, "CONTAINER_PERSIST_KEY", ""),
            patch("subprocess.run", side_effect=[inspect_proc, rm_proc, run_proc]) as mock_run,
        ):
            name = cs_mod._start_container()
            assert name.startswith("seclab-persist-")
            # The docker run call is the third one
            run_cmd = mock_run.call_args_list[2][0][0]
            assert "--rm" not in run_cmd

    def test_stop_skips_persistent_container(self):
        cs_mod._container_name = "seclab-persist-abc123"
        with (
            patch.object(cs_mod, "CONTAINER_PERSIST", True),
            patch("subprocess.run") as mock_run,
        ):
            cs_mod._stop_container()
            mock_run.assert_not_called()
            assert cs_mod._container_name is None

    def test_remove_container_logs_failure(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=1, stderr="conflict")):
            with patch.object(cs_mod.logging, "debug") as mock_debug:
                cs_mod._remove_container("test-name")
                mock_debug.assert_called_once()

    def test_remove_container_logs_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30)):
            with patch.object(cs_mod.logging, "exception") as mock_err:
                cs_mod._remove_container("test-name")
                mock_err.assert_called_once()

    def test_is_running_returns_false_on_timeout(self):
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=30)):
            assert cs_mod._is_running("test-name") is False

    def test_is_running_returns_false_on_bad_json(self):
        with patch("subprocess.run", return_value=_make_proc(returncode=0, stdout="not json")):
            assert cs_mod._is_running("test-name") is False


# ---------------------------------------------------------------------------
# Transport selection tests
# ---------------------------------------------------------------------------

class TestRunServer:
    def test_default_transport_is_stdio(self, monkeypatch):
        original = os.environ.get("CONTAINER_SHELL_TRANSPORT")
        monkeypatch.delenv("CONTAINER_SHELL_TRANSPORT", raising=False)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_SHELL_TRANSPORT == "stdio"
        finally:
            _restore_env_and_reload("CONTAINER_SHELL_TRANSPORT", original)

    def test_blank_transport_falls_back_to_stdio(self, monkeypatch):
        original = os.environ.get("CONTAINER_SHELL_TRANSPORT")
        monkeypatch.setenv("CONTAINER_SHELL_TRANSPORT", "   ")
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_SHELL_TRANSPORT == "stdio"
        finally:
            _restore_env_and_reload("CONTAINER_SHELL_TRANSPORT", original)

    @pytest.mark.parametrize("blank", ["", "   ", "\t"])
    def test_host_falls_back_to_default_when_blank(self, monkeypatch, blank):
        original = os.environ.get("CONTAINER_SHELL_HOST")
        monkeypatch.setenv("CONTAINER_SHELL_HOST", blank)
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_SHELL_HOST == "127.0.0.1"
        finally:
            _restore_env_and_reload("CONTAINER_SHELL_HOST", original)

    def test_run_server_stdio_uses_stdio_call(self):
        with (
            patch.object(cs_mod, "CONTAINER_SHELL_TRANSPORT", "stdio"),
            patch.object(cs_mod.mcp, "run") as mock_run,
        ):
            cs_mod._run_server()
            mock_run.assert_called_once_with(show_banner=False)

    @pytest.mark.parametrize("transport", ["http", "streamable-http", "sse"])
    def test_run_server_network_transport_binds_host_port(self, transport):
        with (
            patch.object(cs_mod, "CONTAINER_SHELL_TRANSPORT", transport),
            patch.object(cs_mod, "CONTAINER_SHELL_HOST", "127.0.0.1"),
            patch.object(cs_mod, "CONTAINER_SHELL_PORT", 9123),
            patch.object(cs_mod.mcp, "run") as mock_run,
        ):
            cs_mod._run_server()
            mock_run.assert_called_once_with(
                transport=transport,
                host="127.0.0.1",
                port=9123,
                show_banner=False,
            )

    def test_run_server_rejects_unknown_transport(self):
        with (
            patch.object(cs_mod, "CONTAINER_SHELL_TRANSPORT", "carrier-pigeon"),
            patch.object(cs_mod.mcp, "run") as mock_run,
        ):
            with pytest.raises(ValueError, match="Unsupported CONTAINER_SHELL_TRANSPORT"):
                cs_mod._run_server()
            mock_run.assert_not_called()

    def test_invalid_port_does_not_break_stdio_import(self, monkeypatch):
        original = os.environ.get("CONTAINER_SHELL_PORT")
        monkeypatch.setenv("CONTAINER_SHELL_PORT", "notaport")
        try:
            reloaded = _reload_cs()
            assert reloaded.CONTAINER_SHELL_PORT == "notaport"
            with (
                patch.object(reloaded, "CONTAINER_SHELL_TRANSPORT", "stdio"),
                patch.object(reloaded.mcp, "run") as mock_run,
            ):
                reloaded._run_server()
            mock_run.assert_called_once_with(show_banner=False)
        finally:
            _restore_env_and_reload("CONTAINER_SHELL_PORT", original)

    def test_invalid_port_raises_on_network_transport(self):
        with (
            patch.object(cs_mod, "CONTAINER_SHELL_TRANSPORT", "http"),
            patch.object(cs_mod, "CONTAINER_SHELL_PORT", "notaport"),
            patch.object(cs_mod.mcp, "run") as mock_run,
        ):
            with pytest.raises(ValueError, match="Invalid CONTAINER_SHELL_PORT"):
                cs_mod._run_server()
            mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Toolbox YAML validation
# ---------------------------------------------------------------------------

class TestToolboxYaml:
    def test_toolbox_yaml_valid_base(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_base")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

    def test_toolbox_yaml_valid_remote(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_remote")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

    def test_toolbox_yaml_valid_malware(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_malware_analysis")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

    def test_toolbox_yaml_valid_network(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_network_analysis")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

    def test_toolbox_yaml_valid_sast(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_sast")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

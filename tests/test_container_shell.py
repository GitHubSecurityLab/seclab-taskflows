import importlib
import subprocess
from unittest.mock import MagicMock, patch

import pytest

import seclab_taskflows.mcp_servers.container_shell as cs_mod
from seclab_taskflow_agent.available_tools import AvailableTools


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
    cs_mod._container_id = None


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
            assert "/host/workspace:/workspace" in cmd
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


# ---------------------------------------------------------------------------
# shell_exec tests
# ---------------------------------------------------------------------------

class TestShellExec:
    def setup_method(self):
        _reset_container()

    def test_shell_exec_lazy_start(self):
        start_proc = _make_proc(returncode=0)
        exec_proc = _make_proc(returncode=0, stdout="hello\n")
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "test-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch("subprocess.run", side_effect=[start_proc, exec_proc]),
        ):
            assert cs_mod._container_id is None
            result = cs_mod.shell_exec.fn(command="echo hello")
            assert cs_mod._container_id is not None
            assert "hello" in result

    def test_shell_exec_runs_command(self):
        cs_mod._container_id = "seclab-shell-testtest"
        exec_proc = _make_proc(returncode=0, stdout="output\n")
        with patch("subprocess.run", return_value=exec_proc) as mock_run:
            result = cs_mod.shell_exec.fn(command="echo output", workdir="/workspace")
            cmd = mock_run.call_args[0][0]
            assert "docker" in cmd
            assert "exec" in cmd
            assert "-w" in cmd
            assert "/workspace" in cmd
            assert "seclab-shell-testtest" in cmd
            assert "echo output" in cmd
            assert "output" in result

    def test_shell_exec_includes_exit_code(self):
        cs_mod._container_id = "seclab-shell-testtest"
        exec_proc = _make_proc(returncode=0, stdout="done\n")
        with patch("subprocess.run", return_value=exec_proc):
            result = cs_mod.shell_exec.fn(command="true")
            assert "[exit code: 0]" in result

    def test_shell_exec_nonzero_exit(self):
        cs_mod._container_id = "seclab-shell-testtest"
        exec_proc = _make_proc(returncode=1, stdout="", stderr="error\n")
        with patch("subprocess.run", return_value=exec_proc):
            result = cs_mod.shell_exec.fn(command="false")
            assert "[exit code: 1]" in result
            assert "error" in result

    def test_shell_exec_timeout(self):
        cs_mod._container_id = "seclab-shell-testtest"
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5)):
            result = cs_mod.shell_exec.fn(command="sleep 999", timeout=5)
            assert "timeout" in result

    def test_shell_exec_start_failure_returns_error(self):
        _reset_container()
        with (
            patch.object(cs_mod, "CONTAINER_IMAGE", "bad-image:latest"),
            patch.object(cs_mod, "CONTAINER_WORKSPACE", ""),
            patch("subprocess.run", return_value=_make_proc(returncode=1, stderr="image not found")),
        ):
            result = cs_mod.shell_exec.fn(command="echo hi")
            assert "Failed to start container" in result
            assert cs_mod._container_id is None


# ---------------------------------------------------------------------------
# _stop_container tests
# ---------------------------------------------------------------------------

class TestStopContainer:
    def setup_method(self):
        _reset_container()

    def test_stop_container_called_on_atexit(self):
        cs_mod._container_id = "seclab-shell-tostop"
        with patch("subprocess.run", return_value=_make_proc(returncode=0)) as mock_run:
            cs_mod._stop_container()
            cmd = mock_run.call_args[0][0]
            assert "docker" in cmd
            assert "stop" in cmd
            assert "seclab-shell-tostop" in cmd
            assert cs_mod._container_id is None

    def test_stop_container_no_op_when_none(self):
        cs_mod._container_id = None
        with patch("subprocess.run") as mock_run:
            cs_mod._stop_container()
            mock_run.assert_not_called()


# ---------------------------------------------------------------------------
# Toolbox YAML validation
# ---------------------------------------------------------------------------

class TestToolboxYaml:
    def test_toolbox_yaml_valid_base(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_base")
        assert result is not None
        assert result["seclab-taskflow-agent"]["filetype"] == "toolbox"

    def test_toolbox_yaml_valid_malware(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_malware_analysis")
        assert result is not None
        assert result["seclab-taskflow-agent"]["filetype"] == "toolbox"

    def test_toolbox_yaml_valid_network(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_network_analysis")
        assert result is not None
        assert result["seclab-taskflow-agent"]["filetype"] == "toolbox"

    def test_toolbox_yaml_valid_sast(self):
        tools = AvailableTools()
        result = tools.get_toolbox("seclab_taskflows.toolboxes.container_shell_sast")
        assert result is not None
        assert result["seclab-taskflow-agent"]["filetype"] == "toolbox"

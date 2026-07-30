# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Corpus gate for the taskflows shipped by this package.

Mirrors the agent's own example gate: every bundled grammar document must
validate against its model, and every bundled taskflow must lint clean. On top
of that, the audit_v2 prompts are actually *rendered*, because `--lint` only
checks Jinja syntax and will not notice a `{% include %}` pointing at a prompt
file that does not exist.
"""

from __future__ import annotations

import glob
import tempfile
from pathlib import Path

import pytest
import yaml

from seclab_taskflow_agent.available_tools import AvailableTools
from seclab_taskflow_agent.linting import lint_taskflow
from seclab_taskflow_agent.models import DOCUMENT_MODELS
from seclab_taskflow_agent.template_utils import evaluate_expression, render_template

from seclab_taskflows.mcp_servers.audit_v2.finding_ledger import FindingLedgerBackend
from seclab_taskflows.mcp_servers.audit_v2.repo_survey_models import (
    Component,
    component_to_dict,
)

_ROOT = "src/seclab_taskflows"

# A representative component and finding, shaped like the `outputs` contracts
# the audit_v2 stages declare. Rendering against these proves the prompts only
# reference fields the pipeline actually produces.
#
# The component is built from the survey's own projection rather than written
# out by hand, so a renamed column cannot leave this fixture agreeing with a
# prompt that no longer matches the server.
_COMPONENT = {
    **component_to_dict(
        Component(
            id=1,
            repo="acme/widget",
            location="src/api",
            kind="service",
            language="go",
            runtime="",
            is_app=True,
            is_library=False,
            notes="handles uploads",
        )
    )
}
_FINDING = {
    "finding_id": 1,
    "repo": "acme/widget",
    "component": "src/api",
    "title": "Path traversal in file download",
    "vuln_class": "CWE-22",
    "state": "confirmed",
    "severity": "high",
    "proposed_by": "hunt_gpt",
}
_OUTPUTS = {
    "components": [_COMPONENT],
    "candidates": [_FINDING],
    "raw_candidates": [_FINDING],
    "confirmed": [_FINDING],
    "findings": [_FINDING],
    "draft": "# draft report",
}

# Pre-existing corpus debt, unrelated to audit_v2: these prompts embed literal
# GitHub Actions `${{ ... }}` expressions, which Jinja tries to evaluate. They
# need `{% raw %}` fencing before they can lint or render.
_KNOWN_LINT_ERRORS = {
    "seclab_taskflows.taskflows.alert_triage_examples.triage_taskflows.triage_actions_code_injection",
}


def _dotted(path: str) -> str:
    return path.removeprefix("src/")[: -len(".yaml")].replace("/", ".")


def _grammar_files() -> list[str]:
    kept: list[str] = []
    for f in sorted(glob.glob(f"{_ROOT}/**/*.yaml", recursive=True)):
        data = yaml.safe_load(Path(f).read_text())
        if isinstance(data, dict) and "seclab-taskflow-agent" in data:
            kept.append(f)
    return kept


def _taskflow_dotted_paths() -> list[str]:
    paths: list[str] = []
    for f in sorted(glob.glob(f"{_ROOT}/taskflows/**/*.yaml", recursive=True)):
        data = yaml.safe_load(Path(f).read_text())
        filetype = (data.get("seclab-taskflow-agent") or {}).get("filetype")
        if filetype == "taskflow":
            paths.append(_dotted(f))
    return paths


def _lint_params() -> list[object]:
    params: list[object] = []
    for dotted in _taskflow_dotted_paths():
        if dotted in _KNOWN_LINT_ERRORS:
            params.append(
                pytest.param(
                    dotted,
                    marks=pytest.mark.xfail(
                        strict=True,
                        reason="pre-existing: literal GitHub Actions ${{ }} in prompts",
                    ),
                )
            )
        else:
            params.append(dotted)
    return params


def _audit_v2_dotted_paths() -> list[str]:
    return [p for p in _taskflow_dotted_paths() if ".audit_v2." in p]


@pytest.mark.parametrize("path", _grammar_files())
def test_bundled_document_validates(path: str) -> None:
    """Every shipped grammar document parses and validates against its model."""
    data = yaml.safe_load(Path(path).read_text())
    assert isinstance(data, dict), f"{path}: not a mapping"
    filetype = (data.get("seclab-taskflow-agent") or {}).get("filetype")
    model = DOCUMENT_MODELS.get(filetype)
    assert model is not None, f"{path}: unknown filetype {filetype!r}"
    model.model_validate(data)


@pytest.mark.parametrize("dotted", _lint_params())
def test_bundled_taskflow_lints_without_errors(dotted: str) -> None:
    """Every bundled taskflow lints clean (warnings allowed, no errors)."""
    issues = lint_taskflow(AvailableTools(), dotted)
    errors = [i for i in issues if i.severity == "error"]
    assert not errors, f"{dotted} has lint errors:\n" + "\n".join(
        f"  {i.code}: {i.message} [{i.location}]" for i in errors
    )


@pytest.mark.parametrize("dotted", _audit_v2_dotted_paths())
def test_audit_v2_prompts_render(dotted: str) -> None:
    """Every audit_v2 prompt renders, so `{% include %}` targets really exist."""
    tools = AvailableTools()
    taskflow = tools.get_taskflow(dotted)
    for index, step in enumerate(taskflow.taskflow):
        task = step.task
        if not task.user_prompt:
            continue
        where = f"{dotted}[{index}] {task.name or '(unnamed)'}"
        # `result` is whatever the branch is fanned out over; fall back to a
        # finding for plain (non-repeat) tasks.
        result = _FINDING
        if task.over:
            candidates = list(
                evaluate_expression(
                    task.over, tools, globals_dict={}, inputs_dict={}, outputs_dict=_OUTPUTS
                )
            )
            if candidates:
                result = candidates[0]
        rendered = render_template(
            template_str=task.user_prompt,
            available_tools=tools,
            globals_dict={"repo": "acme/widget"},
            inputs_dict={},
            result_value=result,
            outputs_dict=_OUTPUTS,
        )
        assert "{%" not in rendered, f"{where}: prompt still contains an unrendered Jinja block"
        assert "{{" not in rendered, f"{where}: prompt still contains an unrendered Jinja variable"
        assert rendered.strip(), f"{where}: prompt rendered empty"


@pytest.mark.parametrize("dotted", _audit_v2_dotted_paths())
def test_audit_v2_over_expressions_resolve(dotted: str) -> None:
    """Every `over` expression selects a real list from the declared outputs."""
    tools = AvailableTools()
    taskflow = tools.get_taskflow(dotted)
    for index, step in enumerate(taskflow.taskflow):
        task = step.task
        if not task.over:
            continue
        where = f"{dotted}[{index}] {task.name or '(unnamed)'}"
        value = evaluate_expression(
            task.over, tools, globals_dict={}, inputs_dict={}, outputs_dict=_OUTPUTS
        )
        assert isinstance(list(value), list), f"{where}: `over` did not yield a list"


def test_audit_v2_over_targets_are_produced_by_an_earlier_task() -> None:
    """An `over` referencing `outputs.<id>` must follow the task that sets it."""
    tools = AvailableTools()
    for dotted in _audit_v2_dotted_paths():
        taskflow = tools.get_taskflow(dotted)
        produced: set[str] = set()
        for index, step in enumerate(taskflow.taskflow):
            task = step.task
            if task.over and task.over.startswith("outputs."):
                name = task.over.removeprefix("outputs.").split(".")[0].strip("\"' ")
                assert name in produced, (
                    f"{dotted}[{index}] iterates outputs.{name}, "
                    f"which no earlier task publishes (published so far: {sorted(produced)})"
                )
            if task.id:
                produced.add(task.id)


def _declared_output_properties(tools: AvailableTools, dotted: str, task_id: str) -> set[str]:
    taskflow = tools.get_taskflow(dotted)
    for step in taskflow.taskflow:
        if step.task.id == task_id:
            schema = step.task.outputs or {}
            return set((schema.get("items") or {}).get("properties", {}))
    msg = f"{dotted} has no task with id {task_id!r}"
    raise AssertionError(msg)


def test_component_outputs_match_what_the_survey_returns() -> None:
    """The declared component schema must match `component_to_dict`, not resemble it.

    A field named `id` here instead of `component_id` still lints, still renders,
    and still passes every static check, then fails at run time after the survey
    has already paid for a full mapping pass. That is exactly what happened, so
    the contract is asserted rather than assumed.
    """
    actual = set(_COMPONENT)
    tools = AvailableTools()
    for dotted in (
        "seclab_taskflows.taskflows.audit_v2.survey",
        "seclab_taskflows.taskflows.audit_v2.hunt",
    ):
        declared = _declared_output_properties(tools, dotted, "components")
        assert declared <= actual, (
            f"{dotted} declares component fields that get_components never returns: "
            f"{sorted(declared - actual)}"
        )


def test_finding_outputs_match_what_the_ledger_returns() -> None:
    """Same guard for the finding schemas the contest and reproduce stages read."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        ledger = FindingLedgerBackend(tmp_dir)
        finding_id = ledger.store_finding(
            "acme/widget", "src/api", "t", "CWE-22", "python", "s", "k", "f", [], "h", "m"
        )
        actual = set(ledger.get_finding(finding_id))

    tools = AvailableTools()
    for dotted, task_id in (
        ("seclab_taskflows.taskflows.audit_v2.contest", "candidates"),
        ("seclab_taskflows.taskflows.audit_v2.reproduce", "confirmed"),
        ("seclab_taskflows.taskflows.audit_v2.report", "findings"),
    ):
        declared = _declared_output_properties(tools, dotted, task_id)
        assert declared <= actual, (
            f"{dotted} declares finding fields the ledger never returns: "
            f"{sorted(declared - actual)}"
        )

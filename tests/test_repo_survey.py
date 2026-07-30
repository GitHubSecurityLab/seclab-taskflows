# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Tests for the audit v2 repository survey store.

The survey is the map every later stage hunts over, so the properties worth
pinning down are the ones whose failure would send a stage looking at nothing:
the store must be durable, it must reject vocabulary it cannot use, and it must
refuse to attach an entry point to a component that does not exist.
"""

import pytest

from seclab_taskflow_agent.available_tools import AvailableTools

from seclab_taskflows.mcp_servers.audit_v2.repo_survey import (
    InvalidSurveyValueError,
    RepoSurveyBackend,
)
from seclab_taskflows.mcp_servers.audit_v2.repo_survey_models import (
    COMPONENT_KINDS,
    TRUST_BOUNDARIES,
)

REPO = "acme/widget"
OTHER_REPO = "acme/gadget"


@pytest.fixture
def survey(tmp_path):
    return RepoSurveyBackend(str(tmp_path / "state"))


def _component(survey, repo=REPO, location="src/parser", kind="parser"):
    return survey.store_component(
        repo, location, kind, "c", "native", False, True, "decodes untrusted frames"
    )


class TestComponents:
    def test_stores_and_reads_back_a_component(self, survey):
        component_id = _component(survey)
        components = survey.get_components(REPO)
        assert len(components) == 1
        assert components[0]["component_id"] == component_id
        assert components[0]["kind"] == "parser"
        assert components[0]["is_library"] is True
        assert components[0]["is_app"] is False

    def test_components_are_scoped_to_their_repo(self, survey):
        _component(survey)
        _component(survey, repo=OTHER_REPO)
        assert len(survey.get_components(REPO)) == 1
        assert len(survey.get_components(OTHER_REPO)) == 1

    def test_a_component_may_be_both_app_and_library(self, survey):
        component_id = survey.store_component(REPO, "src/cli", "cli", "go", "", True, True, "")
        component = survey.get_component(component_id)
        assert component["is_app"] is True
        assert component["is_library"] is True

    def test_unknown_kind_is_rejected_with_the_allowed_set(self, survey):
        with pytest.raises(InvalidSurveyValueError) as exc:
            survey.store_component(REPO, "src", "microservice", "", "", True, False, "")
        message = str(exc.value)
        assert "microservice" in message
        assert "application" in message

    def test_kind_is_normalised(self, survey):
        component_id = survey.store_component(REPO, "src", "  Parser  ", "", "", False, True, "")
        assert survey.get_component(component_id)["kind"] == "parser"

    def test_missing_kind_falls_back_rather_than_failing(self, survey):
        component_id = survey.store_component(REPO, "src", "", "", "", False, False, "")
        assert survey.get_component(component_id)["kind"] == "other"

    def test_every_documented_kind_is_accepted(self, survey):
        for kind in COMPONENT_KINDS:
            assert survey.store_component(REPO, f"src/{kind}", kind, "", "", False, False, "")

    def test_get_component_of_unknown_id_is_none(self, survey):
        assert survey.get_component(4242) is None


class TestEntryPoints:
    def test_stores_an_entry_point_against_a_component(self, survey):
        component_id = _component(survey)
        entry_id = survey.store_entry_point(
            REPO, component_id, "src/parser/frame.c", 120, "network", "frame bytes", "buf", ""
        )
        entry_points = survey.get_entry_points(REPO)
        assert len(entry_points) == 1
        assert entry_points[0]["entry_point_id"] == entry_id
        assert entry_points[0]["trust_boundary"] == "network"
        assert entry_points[0]["line"] == 120

    def test_refuses_to_attach_to_a_component_that_does_not_exist(self, survey):
        result = survey.store_entry_point(REPO, 999, "src/parser/frame.c", 1, "network", "", "", "")
        assert isinstance(result, str)
        assert "999" in result
        assert survey.get_entry_points(REPO) == []

    def test_unknown_trust_boundary_is_rejected(self, survey):
        component_id = _component(survey)
        with pytest.raises(InvalidSurveyValueError) as exc:
            survey.store_entry_point(REPO, component_id, "src/f.c", 1, "http_request", "", "", "")
        assert "network" in str(exc.value)

    def test_a_missing_trust_boundary_is_rejected_rather_than_guessed(self, survey):
        """The boundary is the whole point of the record, so it has no default."""
        component_id = _component(survey)
        with pytest.raises(InvalidSurveyValueError):
            survey.store_entry_point(REPO, component_id, "src/f.c", 1, "", "", "", "")

    def test_every_documented_boundary_is_accepted(self, survey):
        component_id = _component(survey)
        for boundary in TRUST_BOUNDARIES:
            assert survey.store_entry_point(REPO, component_id, "src/f.c", 1, boundary, "", "", "")

    def test_entry_points_can_be_filtered_by_component(self, survey):
        first = _component(survey, location="src/a")
        second = _component(survey, location="src/b")
        survey.store_entry_point(REPO, first, "src/a/x.c", 1, "network", "", "", "")
        survey.store_entry_point(REPO, second, "src/b/y.c", 2, "file", "", "", "")
        assert len(survey.get_entry_points(REPO)) == 2
        only_first = survey.get_entry_points(REPO, first)
        assert len(only_first) == 1
        assert only_first[0]["component_id"] == first

    def test_get_component_includes_its_entry_points(self, survey):
        component_id = _component(survey)
        survey.store_entry_point(
            REPO, component_id, "src/parser/frame.c", 7, "file", "archive member", "", ""
        )
        component = survey.get_component(component_id)
        assert [e["file"] for e in component["entry_points"]] == ["src/parser/frame.c"]


class TestSummaryAndClear:
    def test_summary_counts_by_trust_boundary(self, survey):
        component_id = _component(survey)
        survey.store_entry_point(REPO, component_id, "a.c", 1, "network", "", "", "")
        survey.store_entry_point(REPO, component_id, "b.c", 2, "network", "", "", "")
        survey.store_entry_point(REPO, component_id, "c.c", 3, "file", "", "", "")
        summary = survey.get_survey_summary(REPO)
        assert summary["components"] == 1
        assert summary["entry_points"] == 3
        assert summary["by_trust_boundary"]["network"] == 2
        assert summary["by_trust_boundary"]["file"] == 1
        assert summary["by_trust_boundary"]["ipc"] == 0

    def test_clearing_one_repo_leaves_the_other_alone(self, survey):
        kept = _component(survey, repo=OTHER_REPO)
        cleared = _component(survey)
        survey.store_entry_point(REPO, cleared, "a.c", 1, "network", "", "", "")
        survey.store_entry_point(OTHER_REPO, kept, "b.c", 1, "network", "", "", "")

        survey.clear_survey(REPO)

        assert survey.get_components(REPO) == []
        assert survey.get_entry_points(REPO) == []
        assert len(survey.get_components(OTHER_REPO)) == 1
        assert len(survey.get_entry_points(OTHER_REPO)) == 1


class TestDurability:
    """The survey must never silently become an in-memory database.

    An in-memory SQLite URL hands out a fresh empty database per connection, so
    a survey that fell back to one would map the repository and then present an
    empty map to every stage that follows, with no error anywhere.
    """

    def test_writes_a_real_file_even_when_the_directory_is_absent(self, tmp_path):
        state_dir = tmp_path / "never" / "created"
        survey = RepoSurveyBackend(str(state_dir))
        assert (state_dir / "repo_survey.db").is_file()
        assert str(survey.engine.url).startswith("sqlite:///")

    def test_state_survives_a_new_backend_over_the_same_directory(self, tmp_path):
        state_dir = str(tmp_path / "state")
        component_id = _component(RepoSurveyBackend(state_dir))
        reopened = RepoSurveyBackend(state_dir)
        assert reopened.get_component(component_id)["location"] == "src/parser"


def test_the_toolbox_points_at_this_server() -> None:
    """A renamed module would otherwise only surface as a dead server at run time."""
    toolbox = AvailableTools().get_toolbox("seclab_taskflows.toolboxes.audit_v2_repo_survey")
    assert "seclab_taskflows.mcp_servers.audit_v2.repo_survey" in toolbox.server_params.args

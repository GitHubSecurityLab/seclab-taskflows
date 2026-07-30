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


class TestComponentsAreOnePerLocation:
    """The hunt fans out over components, so two at one location cost a rerun.

    Both the mapping task and the fan-out branches describe the same tree, and
    a model asked to "be granular" happily emits several components for one
    file. Left alone that reads the same code repeatedly and splits the file's
    entry points arbitrarily between the copies.
    """

    def test_a_second_component_at_the_same_location_merges(self, survey):
        first = survey.store_component(REPO, "main.go", "service", "go", "", True, False, "router")
        second = survey.store_component(REPO, "main.go", "other", "", "", False, False, "ping")
        assert second == first
        assert len(survey.get_components(REPO)) == 1

    def test_the_same_location_in_another_repo_is_a_different_component(self, survey):
        first = _component(survey, location="main.go")
        second = _component(survey, repo=OTHER_REPO, location="main.go")
        assert second != first

    def test_merging_keeps_the_first_description_and_adds_the_second(self, survey):
        component_id = survey.store_component(REPO, "main.go", "service", "", "", True, False, "a")
        survey.store_component(REPO, "main.go", "other", "", "", False, False, "b")
        notes = survey.get_component(component_id)["notes"]
        assert "a" in notes
        assert "b" in notes

    def test_merging_does_not_repeat_an_identical_note(self, survey):
        component_id = survey.store_component(REPO, "main.go", "cli", "", "", True, False, "same")
        survey.store_component(REPO, "main.go", "cli", "", "", True, False, "same")
        assert survey.get_component(component_id)["notes"] == "same"

    def test_merging_fills_in_fields_the_first_pass_left_blank(self, survey):
        component_id = survey.store_component(REPO, "main.go", "", "", "", False, False, "")
        survey.store_component(REPO, "main.go", "parser", "go", "native", False, False, "")
        component = survey.get_component(component_id)
        assert component["kind"] == "parser"
        assert component["language"] == "go"
        assert component["runtime"] == "native"

    def test_merging_does_not_overwrite_what_the_first_pass_established(self, survey):
        component_id = survey.store_component(REPO, "main.go", "parser", "go", "", False, False, "")
        survey.store_component(REPO, "main.go", "cli", "rust", "", False, False, "")
        component = survey.get_component(component_id)
        assert component["kind"] == "parser"
        assert component["language"] == "go"

    def test_reachability_is_the_union_of_both_readings(self, survey):
        component_id = survey.store_component(REPO, "main.go", "cli", "", "", True, False, "")
        survey.store_component(REPO, "main.go", "cli", "", "", False, True, "")
        component = survey.get_component(component_id)
        assert component["is_app"] is True
        assert component["is_library"] is True


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


class TestEntryPointsAreOnePerSite:
    """An entry point is a place in the code; every pass that finds it means the same one.

    The mapping task and all the fan-out branches read the same sources, and a
    branch will record an entry point belonging to a sibling component. A live
    survey of a 60-line Go file produced fourteen records for four sites.
    """

    def test_the_same_site_recorded_twice_is_one_entry_point(self, survey):
        component_id = _component(survey)
        first = survey.store_entry_point(REPO, component_id, "main.go", 25, "network", "q", "q", "")
        second = survey.store_entry_point(
            REPO, component_id, "main.go", 25, "network", "q", "q", ""
        )
        assert second == first
        assert len(survey.get_entry_points(REPO)) == 1

    def test_a_sibling_component_claiming_the_same_site_does_not_duplicate_it(self, survey):
        owner = _component(survey, location="src/a")
        sibling = _component(survey, location="src/b")
        first = survey.store_entry_point(REPO, owner, "main.go", 41, "network", "", "", "")
        second = survey.store_entry_point(REPO, sibling, "main.go", 41, "network", "", "", "")
        assert second == first
        entry_points = survey.get_entry_points(REPO)
        assert len(entry_points) == 1
        assert entry_points[0]["component_id"] == owner

    def test_a_different_boundary_at_the_same_line_is_a_different_entry_point(self, survey):
        component_id = _component(survey)
        first = survey.store_entry_point(REPO, component_id, "main.go", 54, "network", "", "", "")
        second = survey.store_entry_point(REPO, component_id, "main.go", 54, "file", "", "", "")
        assert second != first
        assert len(survey.get_entry_points(REPO)) == 2

    def test_the_same_line_in_another_repo_is_a_different_entry_point(self, survey):
        here = _component(survey)
        there = _component(survey, repo=OTHER_REPO)
        first = survey.store_entry_point(REPO, here, "main.go", 25, "network", "", "", "")
        second = survey.store_entry_point(OTHER_REPO, there, "main.go", 25, "network", "", "", "")
        assert second != first

    def test_a_repeat_fills_in_blanks_without_overwriting(self, survey):
        component_id = _component(survey)
        entry_id = survey.store_entry_point(
            REPO, component_id, "main.go", 25, "network", "q parameter", "", ""
        )
        survey.store_entry_point(
            REPO, component_id, "main.go", 25, "network", "something else", "q", "reaches Query"
        )
        entry = survey.get_entry_points(REPO)[0]
        assert entry["entry_point_id"] == entry_id
        assert entry["untrusted_input"] == "q parameter"
        assert entry["variables"] == "q"
        assert entry["notes"] == "reaches Query"

    def test_the_summary_counts_deduplicated_sites(self, survey):
        component_id = _component(survey)
        for _ in range(3):
            survey.store_entry_point(REPO, component_id, "main.go", 25, "network", "", "", "")
        assert survey.get_survey_summary(REPO)["entry_points"] == 1


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

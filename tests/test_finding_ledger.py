# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Tests for the audit v2 finding ledger.

These focus on the promotion rules, because the ledger -- not the prompt -- is
what guarantees a finding cannot claim more than its recorded evidence.
"""

import tempfile
from concurrent.futures import ThreadPoolExecutor

import pytest

from seclab_taskflow_agent.available_tools import AvailableTools
from seclab_taskflow_agent.models import ToolboxDocument

from seclab_taskflows.mcp_servers.audit_v2.finding_ledger import (
    FindingLedgerBackend,
    InvalidLedgerValueError,
    mcp,
)
from seclab_taskflows.mcp_servers.audit_v2.finding_ledger_models import (
    STATE_CANDIDATE,
    STATE_CONFIRMED,
    STATE_DUPLICATE,
    STATE_REJECTED,
    STATE_REPRODUCED,
)

REPO = "acme/widget"


@pytest.fixture
def ledger():
    with tempfile.TemporaryDirectory() as tmp_dir:
        backend = FindingLedgerBackend(tmp_dir)
        try:
            yield backend
        finally:
            backend.dispose()


def _add_finding(
    ledger, component="src/api", vuln_class="CWE-22", proposed_by="hunt_primary", repo=REPO
):
    return ledger.store_finding(
        repo=repo,
        component=component,
        title="Path traversal in file download",
        vuln_class=vuln_class,
        language="python",
        source="HTTP query parameter 'name'",
        sink="open()",
        flow="name flows unsanitised into open()",
        locations=["src/api/files.py:42"],
        hypothesis="Attacker reads arbitrary files",
        proposed_by=proposed_by,
    )


def _contest(ledger, finding_id, prosecution="exploitable", defense="not_exploitable"):
    """File both advocates' verdicts, which adjudication now requires."""
    ledger.store_contest_verdict(
        REPO, finding_id, "prosecution", "prosecution_model", prosecution, "reachable"
    )
    ledger.store_contest_verdict(
        REPO, finding_id, "defense", "defense_model", defense, "input is validated"
    )
    return finding_id


def _contested_finding(ledger, **kwargs):
    """A finding that has been through the contest and is ready to adjudicate."""
    return _contest(ledger, _add_finding(ledger, **kwargs))


class TestFindingCreation:
    def test_new_finding_starts_as_candidate(self, ledger):
        finding_id = _add_finding(ledger)
        finding = ledger.get_finding(finding_id)
        assert finding["state"] == STATE_CANDIDATE
        assert finding["locations"] == ["src/api/files.py:42"]
        assert finding["proposed_by"] == "hunt_primary"

    def test_findings_filtered_by_state(self, ledger):
        first = _contested_finding(ledger)
        _add_finding(ledger, component="src/web")
        ledger.adjudicate_finding(REPO, first, "exploitable", "high", "clear taint path")

        confirmed = ledger.get_findings(REPO, state=STATE_CONFIRMED)
        candidates = ledger.get_findings(REPO, state=STATE_CANDIDATE)

        assert [f["finding_id"] for f in confirmed] == [first]
        assert len(candidates) == 1

    def test_similar_findings_match_component_and_class(self, ledger):
        _add_finding(ledger, component="src/api", vuln_class="CWE-22")
        _add_finding(ledger, component="src/api", vuln_class="CWE-79")

        similar = ledger.find_similar_findings(REPO, "src/api", "CWE-22")

        assert len(similar) == 1
        assert similar[0]["vuln_class"] == "CWE-22"


class TestAdjudication:
    def test_exploitable_confirms_finding(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "prosecution prevailed")
        assert ledger.get_finding(finding_id)["state"] == STATE_CONFIRMED

    def test_not_exploitable_rejects_finding(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "not_exploitable", "none", "input is validated")
        finding = ledger.get_finding(finding_id)
        assert finding["state"] == STATE_REJECTED
        assert finding["disposition_reason"] == "input is validated"

    def test_uncertain_leaves_finding_as_candidate(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "uncertain", "low", "needs runtime evidence")
        assert ledger.get_finding(finding_id)["state"] == STATE_CANDIDATE

    def test_adjudication_is_recorded_as_a_verdict(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "exploitable", "medium", "reachable")
        roles = [v["role"] for v in ledger.get_finding(finding_id)["verdicts"]]
        assert roles == ["prosecution", "defense", "adjudication"]

    def test_adjudication_requires_both_advocates(self, ledger):
        finding_id = _add_finding(ledger)

        result = ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "reachable")

        assert "cannot be adjudicated yet" in result
        assert ledger.get_finding(finding_id)["state"] == STATE_CANDIDATE

    def test_adjudication_requires_the_defense(self, ledger):
        finding_id = _add_finding(ledger)
        ledger.store_contest_verdict(
            REPO, finding_id, "prosecution", "m", "exploitable", "reachable"
        )

        result = ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "reachable")

        assert "no defense verdict" in result
        assert ledger.get_finding(finding_id)["state"] == STATE_CANDIDATE

    def test_adjudication_requires_the_prosecution(self, ledger):
        finding_id = _add_finding(ledger)
        ledger.store_contest_verdict(REPO, finding_id, "defense", "m", "not_exploitable", "safe")

        result = ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "reachable")

        assert "no prosecution verdict" in result
        assert ledger.get_finding(finding_id)["state"] == STATE_CANDIDATE

    def test_invalid_position_is_rejected(self, ledger):
        finding_id = _contested_finding(ledger)
        with pytest.raises(InvalidLedgerValueError):
            ledger.adjudicate_finding(REPO, finding_id, "probably", "high", "")

    def test_invalid_severity_is_rejected(self, ledger):
        finding_id = _contested_finding(ledger)
        with pytest.raises(InvalidLedgerValueError):
            ledger.adjudicate_finding(REPO, finding_id, "exploitable", "catastrophic", "")


class TestContestVerdicts:
    def test_prosecution_and_defense_do_not_change_state(self, ledger):
        finding_id = _add_finding(ledger)
        ledger.store_contest_verdict(
            REPO, finding_id, "prosecution", "prosecutor", "exploitable", "reachable from route"
        )
        ledger.store_contest_verdict(
            REPO, finding_id, "defense", "defender", "not_exploitable", "normalised first"
        )
        finding = ledger.get_finding(finding_id)
        assert finding["state"] == STATE_CANDIDATE
        assert len(finding["verdicts"]) == 2

    def test_invalid_role_is_rejected(self, ledger):
        finding_id = _add_finding(ledger)
        with pytest.raises(InvalidLedgerValueError):
            ledger.store_contest_verdict(REPO, finding_id, "jury", "m", "exploitable", "")

    def test_verdict_refuses_to_cross_repositories(self, ledger):
        foreign = _add_finding(ledger, repo="acme/other")
        result = ledger.store_contest_verdict(
            REPO, foreign, "prosecution", "m", "exploitable", "reachable"
        )
        assert "refusing to record a verdict across repositories" in result
        assert ledger.get_finding(foreign)["verdicts"] == []


class TestReproductionGate:
    def test_reproduction_promotes_only_from_confirmed(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "reachable")
        ledger.store_reproduction_attempt(
            REPO, finding_id, "reproducer", "curl ...", "reproduced", "read /etc/passwd"
        )
        assert ledger.get_finding(finding_id)["state"] == STATE_REPRODUCED

    def test_candidate_cannot_be_promoted_by_reproduction(self, ledger):
        finding_id = _add_finding(ledger)
        message = ledger.store_reproduction_attempt(
            REPO, finding_id, "reproducer", "curl ...", "reproduced", "read /etc/passwd"
        )
        assert ledger.get_finding(finding_id)["state"] == STATE_CANDIDATE
        assert "must be" in message

    def test_failed_reproduction_leaves_state_confirmed(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "reachable")
        ledger.store_reproduction_attempt(
            REPO, finding_id, "reproducer", "curl ...", "not_reproduced", "404 returned"
        )
        assert ledger.get_finding(finding_id)["state"] == STATE_CONFIRMED

    def test_reproduced_finding_is_not_downgraded_by_adjudication(self, ledger):
        finding_id = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, finding_id, "exploitable", "high", "reachable")
        ledger.store_reproduction_attempt(
            REPO, finding_id, "reproducer", "curl ...", "reproduced", "read /etc/passwd"
        )
        ledger.adjudicate_finding(REPO, finding_id, "not_exploitable", "none", "second thoughts")
        assert ledger.get_finding(finding_id)["state"] == STATE_REPRODUCED

    def test_attempts_are_recorded_on_the_finding(self, ledger):
        finding_id = _add_finding(ledger)
        ledger.store_reproduction_attempt(
            REPO, finding_id, "reproducer", "python poc.py", "inconclusive", "server would not boot"
        )
        attempts = ledger.get_finding(finding_id)["reproduction_attempts"]
        assert len(attempts) == 1
        assert attempts[0]["outcome"] == "inconclusive"

    def test_invalid_outcome_is_rejected(self, ledger):
        finding_id = _add_finding(ledger)
        with pytest.raises(InvalidLedgerValueError):
            ledger.store_reproduction_attempt(REPO, finding_id, "m", "", "maybe", "")

    def test_reproduction_refuses_to_cross_repositories(self, ledger):
        foreign = _add_finding(ledger, repo="acme/other")
        result = ledger.store_reproduction_attempt(
            REPO, foreign, "reproducer", "curl ...", "reproduced", "marker reached"
        )
        assert "refusing to record a reproduction attempt across repositories" in result
        assert ledger.get_finding(foreign)["reproduction_attempts"] == []

    def test_adjudication_refuses_to_cross_repositories(self, ledger):
        foreign = _add_finding(ledger, repo="acme/other")
        result = ledger.adjudicate_finding(REPO, foreign, "exploitable", "high", "reachable")
        assert "refusing to adjudicate across repositories" in result
        assert ledger.get_finding(foreign)["state"] == STATE_CANDIDATE


class TestAttribution:
    def test_attribution_records_the_proposing_model(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        ledger.attribute_finding(REPO, finding_id, "claude-sonnet-5")

        assert ledger.get_finding(finding_id)["proposed_by"] == "claude-sonnet-5"

    def test_attribution_unions_rather_than_overwrites(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        ledger.attribute_finding(REPO, finding_id, "claude-sonnet-5")
        ledger.attribute_finding(REPO, finding_id, "gemini-3.6-flash")

        assert ledger.get_finding(finding_id)["proposed_by"] == (
            "claude-sonnet-5, gemini-3.6-flash"
        )

    def test_attribution_is_idempotent(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        ledger.attribute_finding(REPO, finding_id, "claude-sonnet-5")
        ledger.attribute_finding(REPO, finding_id, "claude-sonnet-5")

        assert ledger.get_finding(finding_id)["proposed_by"] == "claude-sonnet-5"

    def test_attribution_rejects_an_empty_label(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        result = ledger.attribute_finding(REPO, finding_id, "  ")

        assert "non-empty model label" in result
        assert ledger.get_finding(finding_id)["proposed_by"] == ""

    def test_attribution_refuses_to_cross_repositories(self, ledger):
        foreign = _add_finding(ledger, repo="acme/other", proposed_by="")

        result = ledger.attribute_finding(REPO, foreign, "claude-sonnet-5")

        assert "refusing to attribute across repositories" in result
        assert ledger.get_finding(foreign)["proposed_by"] == ""

    def test_attribution_reports_an_unknown_finding(self, ledger):
        assert "No finding with id 999" in ledger.attribute_finding(REPO, 999, "m")


class TestBatchAttribution:
    def test_a_whole_run_is_recorded_in_one_call(self, ledger):
        a = _add_finding(ledger, proposed_by="")
        b = _add_finding(ledger, proposed_by="")
        c = _add_finding(ledger, proposed_by="")

        result = ledger.attribute_findings(
            REPO,
            [
                {"proposed_by": "hunt_gpt", "finding_ids": [a, b]},
                {"proposed_by": "hunt_claude", "finding_ids": [b, c]},
            ],
        )

        assert "Recorded 4 attribution pair(s)" in result
        assert ledger.get_finding(a)["proposed_by"] == "hunt_gpt"
        assert ledger.get_finding(b)["proposed_by"] == "hunt_gpt, hunt_claude"
        assert ledger.get_finding(c)["proposed_by"] == "hunt_claude"

    def test_a_branch_that_filed_nothing_is_harmless(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        result = ledger.attribute_findings(
            REPO,
            [
                {"proposed_by": "hunt_gpt", "finding_ids": [finding_id]},
                {"proposed_by": "hunt_gemini", "finding_ids": []},
            ],
        )

        assert "Recorded 1 attribution pair(s)" in result
        assert "Problems" not in result

    def test_one_bad_id_does_not_discard_the_rest(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        result = ledger.attribute_findings(
            REPO,
            [{"proposed_by": "hunt_gpt", "finding_ids": [finding_id, 999]}],
        )

        assert "Recorded 1 attribution pair(s)" in result
        assert "No finding with id 999" in result
        assert ledger.get_finding(finding_id)["proposed_by"] == "hunt_gpt"

    def test_an_entry_without_a_label_is_reported(self, ledger):
        finding_id = _add_finding(ledger, proposed_by="")

        result = ledger.attribute_findings(
            REPO, [{"proposed_by": "  ", "finding_ids": [finding_id]}]
        )

        assert "Recorded 0 attribution pair(s)" in result
        assert "missing proposed_by" in result
        assert ledger.get_finding(finding_id)["proposed_by"] == ""

    def test_a_non_list_payload_is_rejected(self, ledger):
        assert "must be a list" in ledger.attribute_findings(REPO, {"a": 1})


class TestDeduplication:
    def test_merge_folds_duplicate_and_keeps_canonical(self, ledger):
        canonical = _add_finding(ledger, proposed_by="hunt_gpt")
        duplicate = _add_finding(ledger, proposed_by="hunt_claude")

        ledger.merge_duplicate_finding(REPO, duplicate, canonical)

        folded = ledger.get_finding(duplicate)
        kept = ledger.get_finding(canonical)
        assert folded["state"] == STATE_DUPLICATE
        assert folded["duplicate_of"] == canonical
        assert kept["state"] == STATE_CANDIDATE

    def test_merge_accumulates_model_provenance(self, ledger):
        canonical = _add_finding(ledger, proposed_by="hunt_gpt")
        second = _add_finding(ledger, proposed_by="hunt_claude")
        third = _add_finding(ledger, proposed_by="hunt_gemini")

        ledger.merge_duplicate_finding(REPO, second, canonical)
        ledger.merge_duplicate_finding(REPO, third, canonical)

        assert ledger.get_finding(canonical)["proposed_by"] == (
            "hunt_gpt, hunt_claude, hunt_gemini"
        )

    def test_merge_does_not_repeat_a_label(self, ledger):
        canonical = _add_finding(ledger, proposed_by="hunt_gpt")
        duplicate = _add_finding(ledger, proposed_by="hunt_gpt")

        ledger.merge_duplicate_finding(REPO, duplicate, canonical)

        assert ledger.get_finding(canonical)["proposed_by"] == "hunt_gpt"

    def test_merge_refuses_to_cross_repositories(self, ledger):
        canonical = _add_finding(ledger)
        foreign = _add_finding(ledger, repo="acme/other")

        result = ledger.merge_duplicate_finding(REPO, foreign, canonical)

        assert "refusing to merge across repositories" in result
        assert ledger.get_finding(foreign)["state"] == STATE_CANDIDATE

    def test_duplicates_are_excluded_from_candidate_queries(self, ledger):
        canonical = _add_finding(ledger)
        duplicate = _add_finding(ledger)
        ledger.merge_duplicate_finding(REPO, duplicate, canonical)

        candidates = ledger.get_findings(REPO, state=STATE_CANDIDATE)

        assert [f["finding_id"] for f in candidates] == [canonical]

    def test_a_finding_cannot_be_its_own_duplicate(self, ledger):
        finding_id = _add_finding(ledger)
        message = ledger.merge_duplicate_finding(REPO, finding_id, finding_id)
        assert "itself" in message
        assert ledger.get_finding(finding_id)["state"] == STATE_CANDIDATE

    def test_adjudicated_findings_cannot_be_merged_away(self, ledger):
        canonical = _add_finding(ledger)
        confirmed = _contested_finding(ledger)
        ledger.adjudicate_finding(REPO, confirmed, "exploitable", "high", "reachable")

        message = ledger.merge_duplicate_finding(REPO, confirmed, canonical)

        assert "only candidates" in message
        assert ledger.get_finding(confirmed)["state"] == STATE_CONFIRMED

    def test_cannot_merge_into_a_duplicate(self, ledger):
        canonical = _add_finding(ledger)
        duplicate = _add_finding(ledger)
        third = _add_finding(ledger)
        ledger.merge_duplicate_finding(REPO, duplicate, canonical)

        message = ledger.merge_duplicate_finding(REPO, third, duplicate)

        assert "merge into that one instead" in message
        assert ledger.get_finding(third)["state"] == STATE_CANDIDATE

    def test_merge_reports_unknown_findings(self, ledger):
        finding_id = _add_finding(ledger)
        assert "No finding" in ledger.merge_duplicate_finding(REPO, 9999, finding_id)
        assert "No finding" in ledger.merge_duplicate_finding(REPO, finding_id, 9999)


class TestLedgerMaintenance:
    def test_summary_counts_by_state(self, ledger):
        confirmed = _contested_finding(ledger)
        _add_finding(ledger, component="src/web")
        ledger.adjudicate_finding(REPO, confirmed, "exploitable", "high", "reachable")

        summary = ledger.get_ledger_summary(REPO)

        assert summary["total"] == 2
        assert summary["by_state"][STATE_CONFIRMED] == 1
        assert summary["by_state"][STATE_CANDIDATE] == 1

    def test_clear_removes_findings_and_evidence(self, ledger):
        finding_id = _add_finding(ledger)
        ledger.store_contest_verdict(REPO, finding_id, "prosecution", "m", "exploitable", "")
        ledger.clear_findings_for_repo(REPO)

        assert ledger.get_findings(REPO) == []
        assert ledger.get_finding(finding_id) is None

    def test_unknown_finding_reads_return_none(self, ledger):
        assert ledger.get_finding(9999) is None

    def test_writes_against_unknown_finding_are_reported(self, ledger):
        assert "No finding" in ledger.adjudicate_finding(REPO, 9999, "exploitable", "high", "")
        assert "No finding" in ledger.store_reproduction_attempt(
            REPO, 9999, "m", "", "reproduced", ""
        )


class TestDurability:
    def test_missing_state_dir_is_created_not_silently_in_memory(self, tmp_path):
        """A missing directory must not degrade the ledger to an in-memory DB.

        That fallback would let a whole audit run, promote findings, and then
        lose every one of them at exit.
        """
        state_dir = tmp_path / "does" / "not" / "exist"
        ledger = FindingLedgerBackend(str(state_dir))

        _add_finding(ledger)

        assert (state_dir / "finding_ledger.db").is_file()

    def test_findings_survive_a_new_backend_over_the_same_dir(self, tmp_path):
        state_dir = tmp_path / "ledger"
        finding_id = _add_finding(FindingLedgerBackend(str(state_dir)))

        reopened = FindingLedgerBackend(str(state_dir))

        assert reopened.get_finding(finding_id)["title"] == "Path traversal in file download"

    def test_concurrent_backends_over_one_dir_all_start(self, tmp_path):
        """Every branch of a fanned-out task opens the ledger at the same time.

        `create_all` checks for a table and then creates it, so two backends
        racing on an empty database both decide to create and the loser used to
        die with "table finding already exists". That killed its MCP server, so
        the branch ran on with no ledger and filed nothing.
        """
        state_dir = str(tmp_path / "ledger")

        with ThreadPoolExecutor(max_workers=8) as pool:
            backends = list(pool.map(lambda _: FindingLedgerBackend(state_dir), range(8)))

        finding_id = _add_finding(backends[0])
        assert all(b.get_finding(finding_id) is not None for b in backends)


class TestServerWiring:
    def test_toolbox_yaml_valid(self):
        result = AvailableTools().get_toolbox("seclab_taskflows.toolboxes.audit_v2_finding_ledger")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

    @pytest.mark.asyncio
    async def test_all_ledger_tools_are_exposed(self):
        names = {tool.name for tool in await mcp.list_tools()}
        assert names == {
            "store_finding",
            "attribute_findings",
            "get_findings",
            "get_finding",
            "find_similar_findings",
            "store_contest_verdict",
            "adjudicate_finding",
            "merge_duplicate_finding",
            "store_reproduction_attempt",
            "get_ledger_summary",
            "clear_findings_for_repo",
        }


class TestRepoNormalization:
    def test_repo_is_normalized_across_writes_and_reads(self, ledger):
        finding_id = _add_finding(ledger, repo="Acme/Widget")
        assert len(ledger.get_findings("acme/widget")) == 1
        assert len(ledger.get_findings("  ACME/WIDGET ")) == 1
        assert ledger.get_finding(finding_id)["repo"] == "acme/widget"

    def test_guard_matches_the_same_repo_in_a_different_casing(self, ledger):
        finding_id = _contested_finding(ledger, repo="acme/widget")
        result = ledger.adjudicate_finding("ACME/Widget", finding_id, "exploitable", "high", "x")
        assert "adjudicated" in result
        assert ledger.get_finding(finding_id)["state"] == STATE_CONFIRMED

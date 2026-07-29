# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Tests for the audit v2 finding ledger.

These focus on the promotion rules, because the ledger -- not the prompt -- is
what guarantees a finding cannot claim more than its recorded evidence.
"""

import tempfile

import pytest

from seclab_taskflow_agent.available_tools import AvailableTools
from seclab_taskflow_agent.models import ToolboxDocument

from seclab_taskflows.mcp_servers.finding_ledger import (
    FindingLedgerBackend,
    InvalidLedgerValueError,
    mcp,
)
from seclab_taskflows.mcp_servers.finding_ledger_models import (
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
        yield FindingLedgerBackend(tmp_dir)


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


class TestServerWiring:
    def test_toolbox_yaml_valid(self):
        result = AvailableTools().get_toolbox("seclab_taskflows.toolboxes.finding_ledger")
        assert result is not None
        assert isinstance(result, ToolboxDocument)

    @pytest.mark.asyncio
    async def test_all_ledger_tools_are_exposed(self):
        names = {tool.name for tool in await mcp.list_tools()}
        assert names == {
            "store_finding",
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

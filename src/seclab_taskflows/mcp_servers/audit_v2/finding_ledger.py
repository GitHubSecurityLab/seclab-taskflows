# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""MCP server exposing the audit v2 finding ledger.

The ledger is the source of truth for the v2 audit pipeline. Each stage reads
the findings it is responsible for and writes its evidence back, rather than
threading large payloads between tasks. That keeps stages independently
resumable and makes the promotion rules auditable.

Promotion is enforced here, not in prompts: a finding only becomes
``confirmed`` through adjudication, and only becomes ``reproduced`` when a
reproduction attempt actually triggered it from a ``confirmed`` state.
"""

import json
import logging

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name, mcp_data_dir
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pathlib import Path

from .finding_ledger_models import (
    CONTEST_POSITIONS,
    CONTEST_ROLES,
    FINDING_STATES,
    OUTCOME_REPRODUCED,
    POSITION_EXPLOITABLE,
    POSITION_NOT_EXPLOITABLE,
    REPRODUCTION_OUTCOMES,
    ROLE_ADJUDICATION,
    ROLE_DEFENSE,
    ROLE_PROSECUTION,
    SEVERITIES,
    STATE_CANDIDATE,
    STATE_CONFIRMED,
    STATE_DUPLICATE,
    STATE_REJECTED,
    STATE_REPRODUCED,
    Base,
    ContestVerdict,
    Finding,
    ReproductionAttempt,
)
from ..utils import process_repo

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_finding_ledger.log"),
    filemode="a",
)

MEMORY = mcp_data_dir("seclab-taskflows", "finding_ledger", "FINDING_LEDGER_DIR")


def _merge_labels(*label_groups) -> str:
    """Union comma-separated model labels, preserving first-seen order."""
    seen = []
    for group in label_groups:
        for raw in (group or "").split(","):
            label = raw.strip()
            if label and label not in seen:
                seen.append(label)
    return ", ".join(seen)


def finding_to_dict(f):
    try:
        locations = json.loads(f.locations or "[]")
    except (json.JSONDecodeError, ValueError):
        locations = []
    return {
        "finding_id": f.id,
        "repo": f.repo.lower(),
        "component": f.component,
        "title": f.title,
        "vuln_class": f.vuln_class,
        "language": f.language,
        "source": f.source,
        "sink": f.sink,
        "flow": f.flow,
        "locations": locations,
        "hypothesis": f.hypothesis,
        "proposed_by": f.proposed_by,
        "state": f.state,
        "severity": f.severity,
        "disposition_reason": f.disposition_reason,
        "duplicate_of": f.duplicate_of,
    }


def verdict_to_dict(v):
    return {
        "verdict_id": v.id,
        "finding_id": v.finding_id,
        "role": v.role,
        "model": v.model,
        "position": v.position,
        "rationale": v.rationale,
    }


def attempt_to_dict(a):
    return {
        "attempt_id": a.id,
        "finding_id": a.finding_id,
        "model": a.model,
        "harness": a.harness,
        "outcome": a.outcome,
        "observed": a.observed,
    }


class InvalidLedgerValueError(ValueError):
    """Raised when a caller supplies a value outside an allowed set."""


def _require(value: str, allowed, name: str) -> str:
    """Validate an enum-like argument, raising a message the model can act on."""
    normalized = (value or "").strip().lower()
    if normalized not in allowed:
        msg = f"invalid {name} {value!r}; expected one of: {', '.join(allowed)}"
        raise InvalidLedgerValueError(msg)
    return normalized


class FindingLedgerBackend:
    """Durable store for the audit v2 finding lifecycle.

    The ledger is the only channel between pipeline stages, so it always
    materialises a real database file. Other MCP servers in this package fall
    back to an in-memory database when their state directory is missing, but
    that would be silent data loss here: an audit would appear to run, promote
    findings, and then have nothing to show at the end.
    """

    def __init__(self, state_dir: str):
        self.state_dir = state_dir
        Path(self.state_dir).mkdir(parents=True, exist_ok=True)
        self.engine = create_engine(f"sqlite:///{self.state_dir}/finding_ledger.db", echo=False)
        Base.metadata.create_all(
            self.engine,
            tables=[
                Finding.__table__,
                ContestVerdict.__table__,
                ReproductionAttempt.__table__,
            ],
        )

    # -- writes ------------------------------------------------------------

    def store_finding(
        self,
        repo,
        component,
        title,
        vuln_class,
        language,
        source,
        sink,
        flow,
        locations,
        hypothesis,
        proposed_by,
    ):
        with Session(self.engine) as session:
            finding = Finding(
                repo=repo,
                component=component,
                title=title,
                vuln_class=vuln_class,
                language=language or "",
                source=source or "",
                sink=sink or "",
                flow=flow or "",
                locations=json.dumps(list(locations or [])),
                hypothesis=hypothesis or "",
                proposed_by=proposed_by or "",
                state=STATE_CANDIDATE,
            )
            session.add(finding)
            session.commit()
            return finding.id

    def store_contest_verdict(self, repo, finding_id, role, model, position, rationale):
        role = _require(role, CONTEST_ROLES, "role")
        position = _require(position, CONTEST_POSITIONS, "position")
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return f"No finding with id {finding_id}"
            session.add(
                ContestVerdict(
                    finding_id=finding_id,
                    repo=repo,
                    role=role,
                    model=model or "",
                    position=position,
                    rationale=rationale or "",
                )
            )
            session.commit()
        return f"Recorded {role} verdict ({position}) for finding {finding_id}"

    def adjudicate_finding(self, repo, finding_id, position, severity, rationale):
        """Resolve a contested finding. This is the only path to ``confirmed``.

        Adjudication requires that both advocates have actually filed. A
        contest with only one side is not a contest, and letting a finding
        reach ``confirmed`` on an unopposed argument would quietly undo the
        thing this stage exists to do.
        """
        position = _require(position, CONTEST_POSITIONS, "position")
        severity = _require(severity, SEVERITIES, "severity")
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return f"No finding with id {finding_id}"
            if finding.state == STATE_REPRODUCED:
                return f"Finding {finding_id} is already reproduced; adjudication ignored"
            filed = {
                role
                for (role,) in session.query(ContestVerdict.role).filter(
                    ContestVerdict.finding_id == finding_id
                )
            }
            missing = [r for r in (ROLE_PROSECUTION, ROLE_DEFENSE) if r not in filed]
            if missing:
                return (
                    f"Finding {finding_id} cannot be adjudicated yet; no "
                    f"{' or '.join(missing)} verdict has been filed. Call "
                    f"`store_contest_verdict` for each side first."
                )
            if position == POSITION_EXPLOITABLE:
                finding.state = STATE_CONFIRMED
            elif position == POSITION_NOT_EXPLOITABLE:
                finding.state = STATE_REJECTED
            else:
                finding.state = STATE_CANDIDATE
            finding.severity = severity
            finding.disposition_reason = rationale or ""
            session.add(
                ContestVerdict(
                    finding_id=finding_id,
                    repo=repo,
                    role=ROLE_ADJUDICATION,
                    model="",
                    position=position,
                    rationale=rationale or "",
                )
            )
            session.commit()
            return f"Finding {finding_id} adjudicated {position}; state is now {finding.state}"

    def merge_duplicate_finding(self, repo, duplicate_id, canonical_id):
        """Fold one candidate into another, carrying its provenance across.

        Independent hunters converging on the same path is the useful signal
        here, so the canonical finding accumulates every model label that
        proposed it rather than discarding the duplicates' provenance.
        """
        if duplicate_id == canonical_id:
            return f"Finding {duplicate_id} cannot be a duplicate of itself"
        with Session(self.engine) as session:
            duplicate = session.get(Finding, duplicate_id)
            if duplicate is None:
                return f"No finding with id {duplicate_id}"
            canonical = session.get(Finding, canonical_id)
            if canonical is None:
                return f"No finding with id {canonical_id}"
            for label, finding in (("duplicate", duplicate), ("canonical", canonical)):
                if finding.repo != repo:
                    return (
                        f"Finding {finding.id} belongs to {finding.repo!r}, not {repo!r}; "
                        f"refusing to merge across repositories ({label})"
                    )
            if canonical.state == STATE_DUPLICATE:
                return (
                    f"Finding {canonical_id} is itself a duplicate of "
                    f"{canonical.duplicate_of}; merge into that one instead"
                )
            if duplicate.state != STATE_CANDIDATE:
                return (
                    f"Finding {duplicate_id} is {duplicate.state!r}; only candidates "
                    f"can be merged as duplicates"
                )
            labels = _merge_labels(canonical.proposed_by, duplicate.proposed_by)
            canonical.proposed_by = labels
            duplicate.state = STATE_DUPLICATE
            duplicate.duplicate_of = canonical_id
            session.commit()
        return (
            f"Finding {duplicate_id} merged into {canonical_id}; "
            f"{canonical_id} was proposed by: {labels}"
        )

    def store_reproduction_attempt(self, repo, finding_id, model, harness, outcome, observed):
        """Record a dynamic trigger attempt; only a real trigger promotes state."""
        outcome = _require(outcome, REPRODUCTION_OUTCOMES, "outcome")
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return f"No finding with id {finding_id}"
            session.add(
                ReproductionAttempt(
                    finding_id=finding_id,
                    repo=repo,
                    model=model or "",
                    harness=harness or "",
                    outcome=outcome,
                    observed=observed or "",
                )
            )
            promoted = False
            if outcome == OUTCOME_REPRODUCED and finding.state == STATE_CONFIRMED:
                finding.state = STATE_REPRODUCED
                promoted = True
            session.commit()
            if promoted:
                return f"Finding {finding_id} reproduced; state is now {STATE_REPRODUCED}"
            if outcome == OUTCOME_REPRODUCED:
                return (
                    f"Recorded reproduction for finding {finding_id}, but its state is "
                    f"{finding.state!r} (must be {STATE_CONFIRMED!r} to be promoted)"
                )
            return f"Recorded {outcome} reproduction attempt for finding {finding_id}"

    def clear_findings_for_repo(self, repo):
        with Session(self.engine) as session:
            ids = [f.id for f in session.query(Finding).filter_by(repo=repo).all()]
            if ids:
                session.query(ContestVerdict).filter(ContestVerdict.finding_id.in_(ids)).delete(
                    synchronize_session=False
                )
                session.query(ReproductionAttempt).filter(
                    ReproductionAttempt.finding_id.in_(ids)
                ).delete(synchronize_session=False)
            session.query(Finding).filter_by(repo=repo).delete()
            session.commit()
        return f"Cleared {len(ids)} findings for {repo}"

    # -- reads -------------------------------------------------------------

    def get_findings(self, repo, state=None):
        with Session(self.engine) as session:
            query = session.query(Finding).filter_by(repo=repo)
            if state:
                query = query.filter_by(state=state)
            return [finding_to_dict(f) for f in query.all()]

    def get_finding(self, finding_id):
        with Session(self.engine) as session:
            finding = session.get(Finding, finding_id)
            if finding is None:
                return None
            data = finding_to_dict(finding)
            data["verdicts"] = [
                verdict_to_dict(v)
                for v in session.query(ContestVerdict).filter_by(finding_id=finding_id).all()
            ]
            data["reproduction_attempts"] = [
                attempt_to_dict(a)
                for a in session.query(ReproductionAttempt).filter_by(finding_id=finding_id).all()
            ]
            return data

    def find_similar_findings(self, repo, component, vuln_class):
        with Session(self.engine) as session:
            query = session.query(Finding).filter_by(repo=repo)
            if component:
                query = query.filter_by(component=component)
            if vuln_class:
                query = query.filter_by(vuln_class=vuln_class)
            return [finding_to_dict(f) for f in query.all()]

    def get_ledger_summary(self, repo):
        with Session(self.engine) as session:
            findings = session.query(Finding).filter_by(repo=repo).all()
        counts = dict.fromkeys(FINDING_STATES, 0)
        for f in findings:
            counts[f.state] = counts.get(f.state, 0) + 1
        return {"repo": repo.lower(), "total": len(findings), "by_state": counts}


backend = FindingLedgerBackend(MEMORY)

mcp = FastMCP("FindingLedger")


@mcp.tool()
def store_finding(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    component: str = Field(description="Directory or module the finding belongs to"),
    title: str = Field(description="Short one-line description of the finding"),
    vuln_class: str = Field(description="Vulnerability class, e.g. CWE-22 or 'path traversal'"),
    language: str = Field(description="Primary language of the affected code", default=""),
    source: str = Field(description="Where the untrusted input originates", default=""),
    sink: str = Field(description="The dangerous operation reached by the input", default=""),
    flow: str = Field(description="How the source reaches the sink", default=""),
    locations: list[str] = Field(
        description="Evidence locations as 'path:line' strings", default_factory=list
    ),
    hypothesis: str = Field(description="Why this may be exploitable", default=""),
    proposed_by: str = Field(description="Label of the model proposing the finding", default=""),
):
    """Store a new candidate finding and return its id."""
    repo = process_repo(owner, repo)
    finding_id = backend.store_finding(
        repo,
        component,
        title,
        vuln_class,
        language,
        source,
        sink,
        flow,
        locations,
        hypothesis,
        proposed_by,
    )
    return json.dumps({"finding_id": finding_id, "state": STATE_CANDIDATE})


@mcp.tool()
def get_findings(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    state: str = Field(
        description=f"Optional state filter, one of: {', '.join(FINDING_STATES)}", default=""
    ),
):
    """Get all findings for a repository, optionally filtered by lifecycle state."""
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_findings(repo, state or None))


@mcp.tool()
def get_finding(
    finding_id: int = Field(description="The ID of the finding"),
):
    """Get one finding with all its contest verdicts and reproduction attempts."""
    result = backend.get_finding(finding_id)
    if result is None:
        return f"No finding with id {finding_id}"
    return json.dumps(result)


@mcp.tool()
def find_similar_findings(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    component: str = Field(description="Component to match", default=""),
    vuln_class: str = Field(description="Vulnerability class to match", default=""),
):
    """Find existing findings in the same component and class, to avoid duplicates."""
    repo = process_repo(owner, repo)
    return json.dumps(backend.find_similar_findings(repo, component, vuln_class))


@mcp.tool()
def store_contest_verdict(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    finding_id: int = Field(description="The ID of the finding being contested"),
    role: str = Field(description=f"One of: {', '.join(CONTEST_ROLES)}"),
    position: str = Field(description=f"One of: {', '.join(CONTEST_POSITIONS)}"),
    rationale: str = Field(description="Evidence-backed argument for this position", default=""),
    model: str = Field(description="Label of the model taking this position", default=""),
):
    """Record a prosecution or defense position on a finding. Does not change state."""
    repo = process_repo(owner, repo)
    try:
        return backend.store_contest_verdict(repo, finding_id, role, model, position, rationale)
    except InvalidLedgerValueError as exc:
        return f"Error: {exc}"


@mcp.tool()
def adjudicate_finding(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    finding_id: int = Field(description="The ID of the finding to adjudicate"),
    position: str = Field(description=f"One of: {', '.join(CONTEST_POSITIONS)}"),
    severity: str = Field(description=f"One of: {', '.join(SEVERITIES)}"),
    rationale: str = Field(description="Why the prosecution or defense prevailed", default=""),
):
    """Resolve a contested finding. This is the only way a finding becomes confirmed."""
    repo = process_repo(owner, repo)
    try:
        return backend.adjudicate_finding(repo, finding_id, position, severity, rationale)
    except InvalidLedgerValueError as exc:
        return f"Error: {exc}"


@mcp.tool()
def merge_duplicate_finding(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    duplicate_id: int = Field(description="The ID of the finding to fold away"),
    canonical_id: int = Field(description="The ID of the finding to keep"),
):
    """Mark one candidate as a duplicate of another, merging its model provenance.

    Only candidates can be merged. The canonical finding keeps a combined
    `proposed_by` list, so convergence between independent hunters is preserved.
    """
    repo = process_repo(owner, repo)
    return backend.merge_duplicate_finding(repo, duplicate_id, canonical_id)


@mcp.tool()
def store_reproduction_attempt(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
    finding_id: int = Field(description="The ID of the finding being reproduced"),
    outcome: str = Field(description=f"One of: {', '.join(REPRODUCTION_OUTCOMES)}"),
    harness: str = Field(description="The exact commands or PoC used", default=""),
    observed: str = Field(description="What actually happened when the PoC ran", default=""),
    model: str = Field(description="Label of the model that ran the attempt", default=""),
):
    """Record a dynamic reproduction attempt run inside the sandboxed container."""
    repo = process_repo(owner, repo)
    try:
        return backend.store_reproduction_attempt(
            repo, finding_id, model, harness, outcome, observed
        )
    except InvalidLedgerValueError as exc:
        return f"Error: {exc}"


@mcp.tool()
def get_ledger_summary(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Get counts of findings by lifecycle state for a repository."""
    repo = process_repo(owner, repo)
    return json.dumps(backend.get_ledger_summary(repo))


@mcp.tool()
def clear_findings_for_repo(
    owner: str = Field(description="The owner of the GitHub repository"),
    repo: str = Field(description="The name of the GitHub repository"),
):
    """Delete all findings and their evidence for a repository."""
    repo = process_repo(owner, repo)
    return backend.clear_findings_for_repo(repo)


if __name__ == "__main__":
    mcp.run(show_banner=False)

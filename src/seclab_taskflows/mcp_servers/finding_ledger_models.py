# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""SQLAlchemy models for the audit v2 finding ledger.

The ledger tracks a finding through an explicit lifecycle:

``candidate`` -> (adversarial contest) -> ``confirmed`` | ``rejected``
``confirmed`` -> (dynamic reproduction) -> ``reproduced``
``candidate`` -> (deduplication) -> ``duplicate``

State is never set directly by a model. It is derived by the backend from
adjudication and reproduction records, so a finding cannot reach a stronger
state than its recorded evidence supports.
"""

from datetime import datetime, timezone

from sqlalchemy import Column, DateTime, ForeignKey, Integer, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


# Lifecycle states, ordered weakest to strongest.
STATE_CANDIDATE = "candidate"
STATE_DUPLICATE = "duplicate"
STATE_REJECTED = "rejected"
STATE_CONFIRMED = "confirmed"
STATE_REPRODUCED = "reproduced"

FINDING_STATES = (
    STATE_CANDIDATE,
    STATE_DUPLICATE,
    STATE_REJECTED,
    STATE_CONFIRMED,
    STATE_REPRODUCED,
)

# Contest roles and the positions a role may take.
ROLE_PROSECUTION = "prosecution"
ROLE_DEFENSE = "defense"
ROLE_ADJUDICATION = "adjudication"
CONTEST_ROLES = (ROLE_PROSECUTION, ROLE_DEFENSE, ROLE_ADJUDICATION)

POSITION_EXPLOITABLE = "exploitable"
POSITION_NOT_EXPLOITABLE = "not_exploitable"
POSITION_UNCERTAIN = "uncertain"
CONTEST_POSITIONS = (POSITION_EXPLOITABLE, POSITION_NOT_EXPLOITABLE, POSITION_UNCERTAIN)

# Reproduction outcomes.
OUTCOME_REPRODUCED = "reproduced"
OUTCOME_NOT_REPRODUCED = "not_reproduced"
OUTCOME_INCONCLUSIVE = "inconclusive"
REPRODUCTION_OUTCOMES = (OUTCOME_REPRODUCED, OUTCOME_NOT_REPRODUCED, OUTCOME_INCONCLUSIVE)

SEVERITIES = ("critical", "high", "medium", "low", "none")


class Finding(Base):
    """A single candidate or confirmed vulnerability in a repository."""

    __tablename__ = "finding"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    component: Mapped[str]
    title: Mapped[str]
    vuln_class: Mapped[str]
    language: Mapped[str] = mapped_column(default="")
    # Taint-style triple describing the claimed issue.
    source: Mapped[str] = mapped_column(Text, default="")
    sink: Mapped[str] = mapped_column(Text, default="")
    flow: Mapped[str] = mapped_column(Text, default="")
    # JSON-encoded list of "path:line" strings.
    locations: Mapped[str] = mapped_column(Text, default="[]")
    hypothesis: Mapped[str] = mapped_column(Text, default="")
    # Comma-separated model labels. More than one means independent hunters
    # converged on the same path, which is a meaningful prior.
    proposed_by: Mapped[str] = mapped_column(default="")
    state: Mapped[str] = mapped_column(default=STATE_CANDIDATE)
    severity: Mapped[str] = mapped_column(default="")
    disposition_reason: Mapped[str] = mapped_column(Text, default="")
    # Set when this finding was folded into another as a duplicate.
    duplicate_of: Mapped[int | None] = mapped_column(Integer, default=None, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self):
        return (
            f"<Finding(id={self.id}, repo={self.repo}, component={self.component}, "
            f"vuln_class={self.vuln_class}, state={self.state}, severity={self.severity}, "
            f"title={self.title})>"
        )


class ContestVerdict(Base):
    """One role's position on a finding during adversarial validation."""

    __tablename__ = "contest_verdict"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id = Column(Integer, ForeignKey("finding.id", ondelete="CASCADE"))
    repo: Mapped[str]
    role: Mapped[str]
    model: Mapped[str] = mapped_column(default="")
    position: Mapped[str]
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self):
        return (
            f"<ContestVerdict(id={self.id}, finding_id={self.finding_id}, role={self.role}, "
            f"position={self.position}, model={self.model})>"
        )


class ReproductionAttempt(Base):
    """A dynamic attempt to trigger a finding inside a sandboxed container."""

    __tablename__ = "reproduction_attempt"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id = Column(Integer, ForeignKey("finding.id", ondelete="CASCADE"))
    repo: Mapped[str]
    model: Mapped[str] = mapped_column(default="")
    harness: Mapped[str] = mapped_column(Text, default="")
    outcome: Mapped[str]
    observed: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=_utcnow)

    def __repr__(self):
        return (
            f"<ReproductionAttempt(id={self.id}, finding_id={self.finding_id}, "
            f"outcome={self.outcome}, model={self.model})>"
        )

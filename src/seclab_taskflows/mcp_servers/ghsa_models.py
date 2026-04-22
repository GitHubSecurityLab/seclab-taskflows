# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

from sqlalchemy import Text
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from typing import Optional


class Base(DeclarativeBase):
    pass

class GHSA(Base):
    __tablename__ = "ghsa"

    id: Mapped[int] = mapped_column(primary_key=True)
    ghsa_id: Mapped[str]
    repo: Mapped[str]
    severity: Mapped[str]
    cve_id: Mapped[str | None] = mapped_column(nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    published_at: Mapped[str | None] = mapped_column(nullable=True)
    state: Mapped[str | None] = mapped_column(nullable=True)

    def __repr__(self):
        return (
            f"<GHSA(id={self.id}, ghsa_id={self.ghsa_id}, repo={self.repo}, "
            f"severity={self.severity}, cve_id={self.cve_id}, description={self.description}, summary={self.summary}, "
            f"published_at={self.published_at}, state={self.state})>"
        )

class GHSASummary(Base):
    __tablename__ = "ghsa_summary"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    total_advisories: Mapped[int]
    high_severity_count: Mapped[int]
    medium_severity_count: Mapped[int]
    low_severity_count: Mapped[int]
    summary_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    def __repr__(self):
        return (
            f"<GHSASummary(id={self.id}, repo={self.repo}, total_advisories={self.total_advisories}, "
            f"high_severity_count={self.high_severity_count}, medium_severity_count={self.medium_severity_count}, "
            f"low_severity_count={self.low_severity_count}, summary_notes={self.summary_notes})>"
        )

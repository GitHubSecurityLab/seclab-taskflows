# SPDX-FileCopyrightText: 2025 GitHub
# SPDX-License-Identifier: MIT

from sqlalchemy import String, Text, Integer, ForeignKey, Column
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from typing import Optional

class Base(DeclarativeBase):
    pass

class AlertResults(Base):
    __tablename__ = 'alert_results'

    canonical_id: Mapped[int] = mapped_column(primary_key=True)
    alert_id: Mapped[str]
    repo: Mapped[str]
    rule: Mapped[str]
    language: Mapped[str]
    location: Mapped[str]
    result: Mapped[str] = mapped_column(Text)
    created: Mapped[Optional[str]]
    valid: Mapped[bool] = mapped_column(nullable=False, default=True)
    completed: Mapped[bool] = mapped_column(nullable=False, default=False)

    relationship('AlertFlowGraph', cascade='all, delete')

    def __repr__(self):
        return (f"<AlertResults(alert_id={self.alert_id}, repo={self.repo}, "
                f"rule={self.rule}, language={self.language}, location={self.location}, "
                f"result={self.result}, created_at={self.created}, valid={self.valid}, completed={self.completed})>")

class AlertFlowGraph(Base):
    __tablename__ = 'alert_flow_graph'

    id: Mapped[int] = mapped_column(primary_key=True)
    alert_canonical_id = Column(Integer, ForeignKey('alert_results.canonical_id', ondelete='CASCADE'))
    flow_data: Mapped[str] = mapped_column(Text)
    repo: Mapped[str]
    prev: Mapped[Optional[str]]
    next: Mapped[Optional[str]]
    started: Mapped[bool] = mapped_column(nullable=False, default=False)

    def __repr__(self):
        return (f"<AlertFlowGraph(alert_canonical_id={self.alert_canonical_id}, "
                f"flow_data={self.flow_data}, repo={self.repo}, prev={self.prev}, next={self.next}, started={self.started})>")


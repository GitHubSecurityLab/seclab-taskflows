# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Reporter Reputation MCP Server
#
# Tracks PVR reporter history and computes reputation scores based on
# past triage outcomes. Uses a local SQLite database.

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from fastmcp import FastMCP
from pydantic import Field
from seclab_taskflow_agent.path_utils import log_file_name, mcp_data_dir
from sqlalchemy import Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

REPORTER_DB_DIR = mcp_data_dir("seclab-taskflows", "reporter_reputation", "REPORTER_DB_DIR")

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_reporter_reputation.log"),
    filemode="a",
)


class Base(DeclarativeBase):
    pass


class ReporterRecord(Base):
    __tablename__ = "reporter_records"

    id: Mapped[int] = mapped_column(primary_key=True)
    login: Mapped[str]
    ghsa_id: Mapped[str]
    repo: Mapped[str]
    verdict: Mapped[str]   # CONFIRMED / UNCONFIRMED / INCONCLUSIVE
    quality: Mapped[str]   # High / Medium / Low
    timestamp: Mapped[str] = mapped_column(Text)  # ISO8601

    def __repr__(self) -> str:
        return (
            f"<ReporterRecord(login={self.login!r}, ghsa_id={self.ghsa_id!r}, "
            f"repo={self.repo!r}, verdict={self.verdict!r}, quality={self.quality!r})>"
        )


class ReporterReputationBackend:
    def __init__(self, db_dir: Path | str) -> None:
        if str(db_dir) == "sqlite://":
            # Explicit in-memory sentinel (used in tests)
            connection_string = "sqlite://"
        else:
            db_path = Path(db_dir)
            db_path.mkdir(parents=True, exist_ok=True)
            connection_string = f"sqlite:///{db_path}/reporter_reputation.db"
        self.engine = create_engine(connection_string, echo=False)
        Base.metadata.create_all(self.engine)

    def record_triage_result(
        self, login: str, ghsa_id: str, repo: str, verdict: str, quality: str
    ) -> str:
        """Insert or update a triage result record for a reporter."""
        timestamp = datetime.now(timezone.utc).isoformat()
        with Session(self.engine) as session:
            existing = (
                session.query(ReporterRecord)
                .filter_by(login=login, ghsa_id=ghsa_id)
                .first()
            )
            if existing:
                existing.repo = repo
                existing.verdict = verdict
                existing.quality = quality
                existing.timestamp = timestamp
            else:
                session.add(
                    ReporterRecord(
                        login=login,
                        ghsa_id=ghsa_id,
                        repo=repo,
                        verdict=verdict,
                        quality=quality,
                        timestamp=timestamp,
                    )
                )
            session.commit()
        return "recorded"

    def get_reporter_history(self, login: str) -> list[dict]:
        """Return all triage records for a reporter, newest first."""
        with Session(self.engine) as session:
            rows = (
                session.query(ReporterRecord)
                .filter_by(login=login)
                .order_by(ReporterRecord.timestamp.desc())
                .all()
            )
            return [
                {
                    "login": r.login,
                    "ghsa_id": r.ghsa_id,
                    "repo": r.repo,
                    "verdict": r.verdict,
                    "quality": r.quality,
                    "timestamp": r.timestamp,
                }
                for r in rows
            ]

    def get_reporter_score(self, login: str) -> dict:
        """Compute and return a reputation summary for a reporter."""
        history = self.get_reporter_history(login)
        total = len(history)
        if total == 0:
            return {
                "login": login,
                "total_reports": 0,
                "confirmed_pct": 0.0,
                "quality_breakdown": {"High": 0, "Medium": 0, "Low": 0},
                "recommendation": "no history",
            }

        confirmed = sum(1 for r in history if r["verdict"] == "CONFIRMED")
        confirmed_pct = confirmed / total

        quality_breakdown: dict[str, int] = {"High": 0, "Medium": 0, "Low": 0}
        for r in history:
            q = r["quality"]
            if q in quality_breakdown:
                quality_breakdown[q] += 1

        low_share = quality_breakdown["Low"] / total

        # Derive recommendation
        if confirmed_pct >= 0.6 and low_share <= 0.2:
            recommendation = "high trust"
        elif confirmed_pct <= 0.2 or low_share >= 0.5:
            recommendation = "treat with skepticism"
        else:
            recommendation = "normal"

        return {
            "login": login,
            "total_reports": total,
            "confirmed_pct": round(confirmed_pct, 4),
            "quality_breakdown": quality_breakdown,
            "recommendation": recommendation,
        }


mcp = FastMCP("ReporterReputation")

backend = ReporterReputationBackend(REPORTER_DB_DIR)


@mcp.tool()
def record_triage_result(
    login: str = Field(description="GitHub login of the reporter"),
    ghsa_id: str = Field(description="GHSA ID of the advisory, e.g. GHSA-xxxx-xxxx-xxxx"),
    repo: str = Field(description="Repository in owner/repo format"),
    verdict: str = Field(description="Triage verdict: CONFIRMED, UNCONFIRMED, or INCONCLUSIVE"),
    quality: str = Field(description="Report quality rating: High, Medium, or Low"),
) -> str:
    """
    Record or update a triage result for a PVR reporter.

    Upserts a row keyed by (login, ghsa_id). Re-running triage on the same
    GHSA advisory updates the existing record rather than creating a duplicate.
    Returns 'recorded' on success.
    """
    return backend.record_triage_result(login, ghsa_id, repo, verdict, quality)


@mcp.tool()
def get_reporter_history(
    login: str = Field(description="GitHub login of the reporter"),
) -> str:
    """
    Retrieve the full triage history for a reporter.

    Returns a JSON list of all records for this login, newest first.
    Returns an empty JSON list if no history is found.
    """
    history = backend.get_reporter_history(login)
    return json.dumps(history, indent=2)


@mcp.tool()
def get_reporter_score(
    login: str = Field(description="GitHub login of the reporter"),
) -> str:
    """
    Compute and return a reputation score for a PVR reporter.

    Returns a JSON summary including total_reports, confirmed_pct,
    quality_breakdown, and a plain-language recommendation:
    'high trust', 'normal', or 'treat with skepticism'.
    """
    score = backend.get_reporter_score(login)
    return json.dumps(score, indent=2)


if __name__ == "__main__":
    mcp.run(show_banner=False)

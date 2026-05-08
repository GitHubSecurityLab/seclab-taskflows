# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""SQLAlchemy models for the fuzzing taskflow's persistent state."""

from sqlalchemy import Column, ForeignKey, Integer, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class FuzzTarget(Base):
    """A function or library API surface that we want to fuzz."""

    __tablename__ = "fuzz_target"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    component_id: Mapped[int] = mapped_column(nullable=True)
    file: Mapped[str]
    function: Mapped[str]
    signature: Mapped[str] = mapped_column(Text, nullable=True)
    input_kind: Mapped[str] = mapped_column(Text, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)


class Harness(Base):
    """A fuzz harness source file plus the build commands used to compile it."""

    __tablename__ = "harness"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id = Column(Integer, ForeignKey("fuzz_target.id", ondelete="CASCADE"))
    repo: Mapped[str]
    harness_path: Mapped[str]
    afl_binary_path: Mapped[str] = mapped_column(nullable=True)
    cov_binary_path: Mapped[str] = mapped_column(nullable=True)
    build_cmd_afl: Mapped[str] = mapped_column(Text, nullable=True)
    build_cmd_cov: Mapped[str] = mapped_column(Text, nullable=True)
    sanitizers: Mapped[str] = mapped_column(Text, nullable=True)
    version: Mapped[int] = mapped_column(default=1)
    build_status: Mapped[str] = mapped_column(Text, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)


class SeedCorpus(Base):
    """An individual seed input for a target."""

    __tablename__ = "seed_corpus"

    id: Mapped[int] = mapped_column(primary_key=True)
    target_id = Column(Integer, ForeignKey("fuzz_target.id", ondelete="CASCADE"))
    source: Mapped[str]
    path: Mapped[str]
    bytes_count: Mapped[int] = mapped_column(default=0)
    added_in_iteration: Mapped[int] = mapped_column(default=0)


class FuzzRun(Base):
    """A single AFL++ campaign for one harness, one iteration."""

    __tablename__ = "fuzz_run"

    id: Mapped[int] = mapped_column(primary_key=True)
    harness_id = Column(Integer, ForeignKey("harness.id", ondelete="CASCADE"))
    iteration_number: Mapped[int]
    time_budget_seconds: Mapped[int]
    started_at: Mapped[str] = mapped_column(nullable=True)
    ended_at: Mapped[str] = mapped_column(nullable=True)
    exec_per_sec: Mapped[float] = mapped_column(nullable=True)
    paths_total: Mapped[int] = mapped_column(default=0)
    crashes_count: Mapped[int] = mapped_column(default=0)
    hangs_count: Mapped[int] = mapped_column(default=0)
    output_dir: Mapped[str] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=True)


class CoverageReport(Base):
    """Aggregate llvm-cov / gcov metrics for one fuzz_run."""

    __tablename__ = "coverage_report"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id = Column(Integer, ForeignKey("fuzz_run.id", ondelete="CASCADE"))
    lines_total: Mapped[int] = mapped_column(default=0)
    lines_hit: Mapped[int] = mapped_column(default=0)
    line_pct: Mapped[float] = mapped_column(default=0.0)
    fns_total: Mapped[int] = mapped_column(default=0)
    fns_hit: Mapped[int] = mapped_column(default=0)
    fn_pct: Mapped[float] = mapped_column(default=0.0)
    branches_total: Mapped[int] = mapped_column(default=0)
    branches_hit: Mapped[int] = mapped_column(default=0)
    branch_pct: Mapped[float] = mapped_column(default=0.0)
    lcov_path: Mapped[str] = mapped_column(nullable=True)
    html_path: Mapped[str] = mapped_column(Text, nullable=True)


class CoverageGap(Base):
    """An uncovered line / function / branch — the agent reads these to improve harness/seeds."""

    __tablename__ = "coverage_gap"

    id: Mapped[int] = mapped_column(primary_key=True)
    report_id = Column(Integer, ForeignKey("coverage_report.id", ondelete="CASCADE"))
    file: Mapped[str]
    function: Mapped[str] = mapped_column(nullable=True)
    line: Mapped[int] = mapped_column(default=0)
    kind: Mapped[str]
    reason_hint: Mapped[str] = mapped_column(Text, nullable=True)


class CallGraph(Base):
    """A static call graph + reachability snapshot for a repo (E3, Fuzz-Introspector lite)."""

    __tablename__ = "call_graph"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    target_id: Mapped[int] = mapped_column(nullable=True)  # Optional: per-target rather than per-repo
    dot_path: Mapped[str] = mapped_column(Text, nullable=True)
    svg_path: Mapped[str] = mapped_column(Text, nullable=True)
    functions_total: Mapped[int] = mapped_column(default=0)
    functions_in_graph: Mapped[int] = mapped_column(default=0)
    functions_reached: Mapped[int] = mapped_column(default=0)
    functions_unreached: Mapped[int] = mapped_column(default=0)
    untouched_surface_json: Mapped[str] = mapped_column(Text, nullable=True)
    generated_at: Mapped[str] = mapped_column(nullable=True)


class HarnessSuggestion(Base):
    """G1-lite: a new-harness candidate proposed by the agent at end-of-campaign,
    based on untouched API surface + uncovered call graph nodes."""

    __tablename__ = "harness_suggestion"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    function_name: Mapped[str]
    file: Mapped[str] = mapped_column(nullable=True)
    rationale: Mapped[str] = mapped_column(Text, nullable=True)
    input_kind: Mapped[str] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(default=5)
    suggested_at: Mapped[str] = mapped_column(nullable=True)


class IterationNote(Base):
    """v8: a one-line note the agent writes after each fuzz iteration so the
    dashboard can render a campaign timeline."""

    __tablename__ = "iteration_note"

    id: Mapped[int] = mapped_column(primary_key=True)
    repo: Mapped[str]
    harness_id: Mapped[int] = mapped_column(nullable=True)
    iteration_number: Mapped[int]
    note: Mapped[str] = mapped_column(Text)
    created_at: Mapped[str] = mapped_column(nullable=True)


class Crash(Base):
    """A crash discovered by AFL++. Deduped via stack_top_hash."""

    __tablename__ = "crash"

    id: Mapped[int] = mapped_column(primary_key=True)
    run_id = Column(Integer, ForeignKey("fuzz_run.id", ondelete="CASCADE"))
    input_blob_path: Mapped[str]
    minimized_path: Mapped[str] = mapped_column(nullable=True)
    stack_top_hash: Mapped[str] = mapped_column(nullable=True)
    sanitizer_output: Mapped[str] = mapped_column(Text, nullable=True)
    classification: Mapped[str] = mapped_column(Text, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)
    # OSS-Fuzz-style triage verdict (see write_vuln_reports taskflow).
    verdict: Mapped[str] = mapped_column(Text, nullable=True)
    bug_class: Mapped[str] = mapped_column(Text, nullable=True)
    cwe: Mapped[str] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(Text, nullable=True)
    vuln_report_path: Mapped[str] = mapped_column(Text, nullable=True)
    reproducer_path: Mapped[str] = mapped_column(Text, nullable=True)

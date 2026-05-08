# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""FastMCP server: persistent state for the fuzzing taskflow + LCOV parser.

Storage is SQLite under DATA_DIR (or platformdirs default). Parses LCOV/llvm-cov
reports and materialises ``coverage_gap`` rows so downstream agent tasks can
reason about what is uncovered without having to re-parse coverage data.
"""

import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Optional

from fastmcp import FastMCP
from pydantic import Field
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from seclab_taskflow_agent.path_utils import log_file_name, mcp_data_dir

from .fuzz_context_models import (
    Base,
    CallGraph,
    CoverageGap,
    CoverageReport,
    Crash,
    FuzzRun,
    FuzzTarget,
    Harness,
    HarnessSuggestion,
    IterationNote,
    SeedCorpus,
)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_fuzz_context.log"),
    filemode="a",
)

MEMORY = mcp_data_dir("seclab-taskflows", "fuzz_context", "FUZZ_CONTEXT_DIR")

mcp = FastMCP("FuzzContext")


def _engine():
    url = "sqlite://" if not Path(MEMORY).exists() else f"sqlite:///{MEMORY}/fuzz_context.db"
    eng = create_engine(url, echo=False)
    Base.metadata.create_all(eng)
    _migrate(eng)
    return eng


def _migrate(eng) -> None:
    """Add columns added in later schema versions to an existing DB.

    SQLite supports ``ALTER TABLE ... ADD COLUMN`` but not ``DROP COLUMN``, so
    we only ever add. New columns are nullable, matching the model defaults.
    """
    expected = {
        "crash": [
            ("verdict", "TEXT"),
            ("bug_class", "TEXT"),
            ("cwe", "TEXT"),
            ("severity", "TEXT"),
            ("vuln_report_path", "TEXT"),
            ("reproducer_path", "TEXT"),
        ],
        "coverage_report": [
            ("html_path", "TEXT"),
        ],
    }
    with eng.connect() as conn:
        for table, cols in expected.items():
            try:
                existing = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()}
            except Exception as e:
                logging.debug("migrate: skipping %s (%s)", table, e)
                continue
            for name, sqltype in cols:
                if name not in existing:
                    conn.exec_driver_sql(f'ALTER TABLE {table} ADD COLUMN {name} {sqltype}')
        conn.commit()


_ENGINE = _engine()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

@mcp.tool()
def store_fuzz_target(
    repo: Annotated[str, Field(description="owner/repo")],
    file: Annotated[str, Field(description="Source file containing the function")],
    function: Annotated[str, Field(description="Function name to fuzz")],
    signature: Annotated[str, Field(description="Function signature")] = "",
    input_kind: Annotated[str, Field(description="Kind of input the function consumes (e.g. 'bytes', 'utf8 string', 'png file')")] = "",
    notes: Annotated[str, Field(description="Why this function is interesting to fuzz")] = "",
    component_id: Annotated[int | None, Field(description="Optional repo_context.application id")] = None,
) -> str:
    """Register a new fuzz target. Returns the target id."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        existing = session.query(FuzzTarget).filter_by(repo=repo, file=file, function=function).first()
        if existing:
            existing.signature = signature or existing.signature
            existing.input_kind = input_kind or existing.input_kind
            existing.notes = (existing.notes or "") + "\n" + notes if notes else existing.notes
            session.commit()
            return f"updated fuzz_target id={existing.id}"
        t = FuzzTarget(
            repo=repo, file=file, function=function, signature=signature,
            input_kind=input_kind, notes=notes, component_id=component_id,
        )
        session.add(t)
        session.commit()
        return f"created fuzz_target id={t.id}"


@mcp.tool()
def get_fuzz_targets(repo: Annotated[str, Field(description="owner/repo")]) -> list[dict]:
    """List all fuzz targets for the repo."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        rows = session.query(FuzzTarget).filter_by(repo=repo).all()
        return [{
            "id": r.id, "repo": r.repo, "file": r.file, "function": r.function,
            "signature": r.signature, "input_kind": r.input_kind, "notes": r.notes,
            "component_id": r.component_id,
        } for r in rows]


# ---------------------------------------------------------------------------
# Harnesses
# ---------------------------------------------------------------------------

@mcp.tool()
def store_harness(
    target_id: Annotated[int, Field(description="fuzz_target id")],
    repo: Annotated[str, Field(description="owner/repo")],
    harness_path: Annotated[str, Field(description="Absolute path to the harness source file (e.g. .c)")],
    sanitizers: Annotated[str, Field(description="Sanitizers requested, e.g. 'address,undefined'")] = "address,undefined",
    notes: Annotated[str, Field(description="Free-form notes")] = "",
) -> str:
    """Register a harness source file (or bump its version if it already exists)."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        existing = session.query(Harness).filter_by(target_id=target_id, harness_path=harness_path).first()
        if existing:
            existing.version = (existing.version or 1) + 1
            existing.sanitizers = sanitizers
            existing.notes = (existing.notes or "") + "\n" + notes if notes else existing.notes
            session.commit()
            return f"bumped harness id={existing.id} to version {existing.version}"
        h = Harness(target_id=target_id, repo=repo, harness_path=harness_path, sanitizers=sanitizers, notes=notes)
        session.add(h)
        session.commit()
        return f"created harness id={h.id}"


@mcp.tool()
def update_harness_build(
    harness_id: Annotated[int, Field(description="harness id")],
    afl_binary_path: Annotated[str, Field(description="Path to AFL-instrumented binary, '' on failure")] = "",
    cov_binary_path: Annotated[str, Field(description="Path to llvm-cov-instrumented binary, '' on failure")] = "",
    build_cmd_afl: Annotated[str, Field(description="Command used for AFL build")] = "",
    build_cmd_cov: Annotated[str, Field(description="Command used for coverage build")] = "",
    build_status: Annotated[str, Field(description="'ok' or short error explanation")] = "ok",
) -> str:
    """Persist build artefacts/status for a harness."""
    with Session(_ENGINE) as session:
        h = session.get(Harness, harness_id)
        if not h:
            return f"harness {harness_id} not found"
        h.afl_binary_path = afl_binary_path or h.afl_binary_path
        h.cov_binary_path = cov_binary_path or h.cov_binary_path
        h.build_cmd_afl = build_cmd_afl or h.build_cmd_afl
        h.build_cmd_cov = build_cmd_cov or h.build_cmd_cov
        h.build_status = build_status
        session.commit()
        return f"updated harness {harness_id} build_status={build_status}"


@mcp.tool()
def get_harnesses(repo: Annotated[str, Field(description="owner/repo")]) -> list[dict]:
    repo = repo.lower()
    with Session(_ENGINE) as session:
        rows = session.query(Harness).filter_by(repo=repo).all()
        return [{
            "id": h.id, "target_id": h.target_id, "harness_path": h.harness_path,
            "afl_binary_path": h.afl_binary_path, "cov_binary_path": h.cov_binary_path,
            "version": h.version, "build_status": h.build_status,
            "sanitizers": h.sanitizers, "notes": h.notes,
        } for h in rows]


# ---------------------------------------------------------------------------
# Seeds
# ---------------------------------------------------------------------------

@mcp.tool()
def store_seed(
    target_id: Annotated[int, Field(description="fuzz_target id")],
    path: Annotated[str, Field(description="Absolute path to the seed file")],
    source: Annotated[str, Field(description="One of: fixture, synthesized, coverage_feedback")] = "synthesized",
    iteration: Annotated[int, Field(description="Iteration number when this seed was added (0 for initial)")] = 0,
) -> str:
    """Register a seed input."""
    try:
        size = Path(path).stat().st_size
    except OSError:
        size = 0
    with Session(_ENGINE) as session:
        existing = session.query(SeedCorpus).filter_by(target_id=target_id, path=path).first()
        if existing:
            return f"seed already known id={existing.id}"
        s = SeedCorpus(target_id=target_id, path=path, source=source, bytes_count=size, added_in_iteration=iteration)
        session.add(s)
        session.commit()
        return f"created seed id={s.id}"


# ---------------------------------------------------------------------------
# Fuzz runs
# ---------------------------------------------------------------------------

@mcp.tool()
def start_fuzz_run(
    harness_id: Annotated[int, Field(description="harness id")],
    iteration_number: Annotated[int, Field(description="1-indexed iteration count")],
    time_budget_seconds: Annotated[int, Field(description="Wall-clock budget for this run")],
    output_dir: Annotated[str, Field(description="afl-fuzz output directory (-o)")] = "",
) -> int:
    """Create a new fuzz_run row in 'running' state. Returns the run id."""
    with Session(_ENGINE) as session:
        r = FuzzRun(
            harness_id=harness_id, iteration_number=iteration_number,
            time_budget_seconds=time_budget_seconds, output_dir=output_dir,
            started_at=_now(), status="running",
        )
        session.add(r)
        session.commit()
        return r.id


@mcp.tool()
def finish_fuzz_run(
    run_id: Annotated[int, Field(description="fuzz_run id returned from start_fuzz_run")],
    exec_per_sec: Annotated[float, Field(description="Average exec/sec reported by AFL")] = 0.0,
    paths_total: Annotated[int, Field(description="Total queue paths discovered by AFL")] = 0,
    crashes_count: Annotated[int, Field(description="Unique crashes discovered")] = 0,
    hangs_count: Annotated[int, Field(description="Unique hangs discovered")] = 0,
    status: Annotated[str, Field(description="'completed', 'failed', or short error")] = "completed",
) -> str:
    with Session(_ENGINE) as session:
        r = session.get(FuzzRun, run_id)
        if not r:
            return f"run {run_id} not found"
        r.ended_at = _now()
        r.exec_per_sec = exec_per_sec
        r.paths_total = paths_total
        r.crashes_count = crashes_count
        r.hangs_count = hangs_count
        r.status = status
        session.commit()
        return f"finished run {run_id} status={status}"


@mcp.tool()
def get_fuzz_runs(harness_id: Annotated[int, Field(description="harness id")]) -> list[dict]:
    with Session(_ENGINE) as session:
        rows = session.query(FuzzRun).filter_by(harness_id=harness_id).order_by(FuzzRun.iteration_number).all()
        return [{
            "id": r.id, "iteration_number": r.iteration_number,
            "time_budget_seconds": r.time_budget_seconds,
            "started_at": r.started_at, "ended_at": r.ended_at,
            "exec_per_sec": r.exec_per_sec, "paths_total": r.paths_total,
            "crashes_count": r.crashes_count, "hangs_count": r.hangs_count,
            "status": r.status, "output_dir": r.output_dir,
        } for r in rows]


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def _parse_lcov(lcov_text: str) -> dict:
    """Parse an LCOV tracefile into per-file aggregates and uncovered locations.

    Handles records emitted by both ``lcov``/``geninfo`` and ``llvm-cov export
    -format=lcov``. We only look at the keys we care about; any unknown line is
    safely ignored.
    """
    files: dict[str, dict] = {}
    current: str | None = None
    for raw in lcov_text.splitlines():
        line = raw.strip()
        if line.startswith("SF:"):
            current = line[3:]
            files[current] = {
                "lines": {},      # line_no -> hit_count
                "functions": {},  # name -> {line, hits}
                "branches": [],   # list of (line, taken_bool)
            }
        elif current is None:
            continue
        elif line.startswith("FN:"):
            try:
                line_no_str, name = line[3:].split(",", 1)
                files[current]["functions"].setdefault(name, {})["line"] = int(line_no_str)
            except ValueError:
                pass
        elif line.startswith("FNDA:"):
            try:
                hits_str, name = line[5:].split(",", 1)
                files[current]["functions"].setdefault(name, {})["hits"] = int(hits_str)
            except ValueError:
                pass
        elif line.startswith("DA:"):
            try:
                line_no_str, hits_str = line[3:].split(",", 1)
                # llvm-cov sometimes appends ',<checksum>'; drop anything after the second comma
                hits_str = hits_str.split(",", 1)[0]
                files[current]["lines"][int(line_no_str)] = int(hits_str)
            except ValueError:
                pass
        elif line.startswith("BRDA:"):
            parts = line[5:].split(",")
            if len(parts) >= 4:
                try:
                    line_no = int(parts[0])
                    taken = parts[3]
                    files[current]["branches"].append((line_no, taken not in ("-", "0")))
                except ValueError:
                    pass
        elif line == "end_of_record":
            current = None

    totals = {
        "lines_total": 0, "lines_hit": 0,
        "fns_total": 0, "fns_hit": 0,
        "branches_total": 0, "branches_hit": 0,
    }
    gaps: list[dict] = []

    for path, info in files.items():
        for ln, hits in info["lines"].items():
            totals["lines_total"] += 1
            if hits > 0:
                totals["lines_hit"] += 1
            else:
                gaps.append({"file": path, "function": None, "line": ln, "kind": "line"})
        for name, fn in info["functions"].items():
            totals["fns_total"] += 1
            if fn.get("hits", 0) > 0:
                totals["fns_hit"] += 1
            else:
                gaps.append({"file": path, "function": name, "line": fn.get("line", 0), "kind": "fn"})
        for ln, taken in info["branches"]:
            totals["branches_total"] += 1
            if taken:
                totals["branches_hit"] += 1
            else:
                gaps.append({"file": path, "function": None, "line": ln, "kind": "branch"})

    def pct(hit: int, total: int) -> float:
        return (100.0 * hit / total) if total else 0.0

    return {
        "totals": {
            **totals,
            "line_pct": pct(totals["lines_hit"], totals["lines_total"]),
            "fn_pct": pct(totals["fns_hit"], totals["fns_total"]),
            "branch_pct": pct(totals["branches_hit"], totals["branches_total"]),
        },
        "gaps": gaps,
    }


@mcp.tool()
def store_coverage_from_lcov(
    run_id: Annotated[int, Field(description="fuzz_run id")],
    lcov_path: Annotated[str, Field(description="Absolute path to the LCOV tracefile")],
    max_gaps: Annotated[int, Field(description="Cap on number of coverage_gap rows to materialise")] = 500,
    html_path: Annotated[str, Field(description="Optional absolute path to an HTML coverage report (llvm-cov show -format=html)")] = "",
) -> dict:
    """Parse an LCOV file, persist a coverage_report row + (capped) coverage_gap rows.

    Returns a summary dict the agent can read directly.
    """
    p = Path(lcov_path)
    if not p.is_file():
        return {"error": f"lcov file not found: {lcov_path}"}
    parsed = _parse_lcov(p.read_text(errors="replace"))
    t = parsed["totals"]
    with Session(_ENGINE) as session:
        rep = CoverageReport(
            run_id=run_id, lcov_path=str(p), html_path=(html_path or None),
            lines_total=t["lines_total"], lines_hit=t["lines_hit"], line_pct=t["line_pct"],
            fns_total=t["fns_total"], fns_hit=t["fns_hit"], fn_pct=t["fn_pct"],
            branches_total=t["branches_total"], branches_hit=t["branches_hit"], branch_pct=t["branch_pct"],
        )
        session.add(rep)
        session.commit()
        report_id = rep.id

        # Prioritise function gaps (most actionable), then branches, then lines.
        priority = {"fn": 0, "branch": 1, "line": 2}
        sorted_gaps = sorted(parsed["gaps"], key=lambda g: (priority.get(g["kind"], 9), g["file"], g["line"]))
        for g in sorted_gaps[:max_gaps]:
            session.add(CoverageGap(
                report_id=report_id, file=g["file"], function=g["function"],
                line=g["line"], kind=g["kind"], reason_hint=None,
            ))
        session.commit()

    return {
        "report_id": report_id,
        "totals": t,
        "gaps_total": len(parsed["gaps"]),
        "gaps_persisted": min(len(parsed["gaps"]), max_gaps),
        "html_path": html_path or "",
    }


@mcp.tool()
def get_coverage_summary(harness_id: Annotated[int, Field(description="harness id")]) -> list[dict]:
    """Per-iteration coverage summary for a harness, sorted by iteration."""
    return _coverage_summary(harness_id)


def _coverage_summary(harness_id: int) -> list[dict]:
    with Session(_ENGINE) as session:
        runs = session.query(FuzzRun).filter_by(harness_id=harness_id).order_by(FuzzRun.iteration_number).all()
        out = []
        for r in runs:
            rep = session.query(CoverageReport).filter_by(run_id=r.id).first()
            if rep:
                out.append({
                    "iteration": r.iteration_number,
                    "time_budget_seconds": r.time_budget_seconds,
                    "lines_hit": rep.lines_hit, "lines_total": rep.lines_total, "line_pct": rep.line_pct,
                    "fns_hit": rep.fns_hit, "fns_total": rep.fns_total, "fn_pct": rep.fn_pct,
                    "branches_hit": rep.branches_hit, "branches_total": rep.branches_total, "branch_pct": rep.branch_pct,
                    "exec_per_sec": r.exec_per_sec,
                })
        return out


@mcp.tool()
def get_coverage_gaps(
    harness_id: Annotated[int, Field(description="harness id")],
    kind: Annotated[str, Field(description="Filter by 'fn', 'branch', 'line', or '' for all")] = "fn",
    limit: Annotated[int, Field(description="Max rows to return")] = 50,
) -> list[dict]:
    """Most recent coverage gaps for the latest run of a harness."""
    with Session(_ENGINE) as session:
        last_run = (
            session.query(FuzzRun).filter_by(harness_id=harness_id)
            .order_by(FuzzRun.iteration_number.desc()).first()
        )
        if not last_run:
            return []
        rep = session.query(CoverageReport).filter_by(run_id=last_run.id).first()
        if not rep:
            return []
        q = session.query(CoverageGap).filter_by(report_id=rep.id)
        if kind:
            q = q.filter_by(kind=kind)
        rows = q.limit(limit).all()
        return [{"file": g.file, "function": g.function, "line": g.line, "kind": g.kind} for g in rows]


@mcp.tool()
def coverage_plateau_reached(
    harness_id: Annotated[int, Field(description="harness id")],
    threshold_pct: Annotated[float, Field(description="Min line-coverage gain (in absolute pp) considered progress")] = 1.0,
) -> dict:
    """Returns whether the last two iterations both gained < threshold_pct line coverage."""
    summary = _coverage_summary(harness_id)
    if len(summary) < 3:
        return {"plateau": False, "reason": "need at least 3 iterations"}
    deltas = [summary[i]["line_pct"] - summary[i - 1]["line_pct"] for i in range(1, len(summary))]
    last_two = deltas[-2:]
    plateau = all(d < threshold_pct for d in last_two)
    return {"plateau": plateau, "last_two_deltas": last_two, "threshold_pct": threshold_pct}


# ---------------------------------------------------------------------------
# Crashes
# ---------------------------------------------------------------------------

@mcp.tool()
def store_crash(
    run_id: Annotated[int, Field(description="fuzz_run id where the crash was found")],
    input_blob_path: Annotated[str, Field(description="Path to the AFL crash input")],
    minimized_path: Annotated[str, Field(description="Path to the afl-tmin minimised input, if any")] = "",
    stack_top_hash: Annotated[str, Field(description="Hash of the top N frames of the ASan stack trace (for dedupe)")] = "",
    sanitizer_output: Annotated[str, Field(description="Raw sanitizer output for the minimised input")] = "",
    classification: Annotated[str, Field(description="Short classification e.g. 'heap-buffer-overflow READ 4'")] = "",
    notes: Annotated[str, Field(description="Free-form analyst notes")] = "",
) -> str:
    with Session(_ENGINE) as session:
        if stack_top_hash:
            existing = session.query(Crash).filter_by(stack_top_hash=stack_top_hash).first()
            if existing:
                return f"duplicate of crash id={existing.id} (same stack_top_hash)"
        c = Crash(
            run_id=run_id, input_blob_path=input_blob_path, minimized_path=minimized_path or None,
            stack_top_hash=stack_top_hash or None, sanitizer_output=sanitizer_output or None,
            classification=classification or None, notes=notes or None,
        )
        session.add(c)
        session.commit()
        return f"stored crash id={c.id}"


_SEVERITY_BY_BUG_CLASS = {
    # Memory-safety writes — RCE candidates
    "heap-buffer-overflow-write": "high",
    "stack-buffer-overflow": "high",
    "global-buffer-overflow": "high",
    "heap-use-after-free": "high",
    # Reads — primarily info-leak / DoS
    "heap-buffer-overflow-read": "medium",
    "uninitialised-read": "medium",
    # Undefined behaviour — usually low unless reachable
    "integer-overflow": "low",
    "signed-integer-overflow": "low",
    "undefined-behavior": "low",
    "divide-by-zero": "low",
    # DoS-class
    "null-deref": "low",
    "stack-overflow": "medium",
    "assertion-failure": "low",
    "timeout": "low",
    "oom": "low",
    "other": "low",
}


@mcp.tool()
def suggest_severity(
    bug_class: Annotated[str, Field(description="One of the bug-class strings used by store_crash / update_crash_verdict")],
) -> dict:
    """Return a deterministic default severity for a given bug class.

    Lookup table mirroring OSS-Fuzz / ClusterFuzz conventions:
    - heap/stack/global writes and use-after-frees -> high
    - OOB reads and uninitialised reads -> medium
    - signed/unsigned integer overflow, NULL deref, divide-by-zero,
      timeout, OOM, assertion-failure -> low

    Agents should use this as a starting point and override only with a
    written justification in the vuln-report notes.
    """
    severity = _SEVERITY_BY_BUG_CLASS.get(bug_class.strip().lower(), "low")
    return {
        "bug_class": bug_class,
        "suggested_severity": severity,
        "rationale": (
            f"Default for bug_class={bug_class!r}; override with a written "
            f"justification (e.g. attacker-controllable size/value, or "
            f"inverse: mitigated by ASLR/CFI in target's deployment)."
        ),
    }


@mcp.tool()
def get_crashes_grouped(
    repo: Annotated[str, Field(description="owner/repo")],
    by: Annotated[str, Field(description="One of: 'verdict', 'bug_class', 'severity', 'cwe', 'verdict_bug_class'")] = "verdict_bug_class",
) -> list[dict]:
    """Group crashes for a repo by the chosen dimension(s) for at-a-glance triage.

    Useful for the dashboard's grouped view and the final REPORT.md ordering.
    """
    repo = repo.lower()
    by = by.strip().lower()
    valid = {"verdict", "bug_class", "severity", "cwe", "verdict_bug_class"}
    if by not in valid:
        return [{"error": f"by must be one of {sorted(valid)}"}]
    with Session(_ENGINE) as session:
        rows = []
        for c in session.query(Crash).all():
            run = session.get(FuzzRun, c.run_id) if c.run_id else None
            h = session.get(Harness, run.harness_id) if run else None
            if not h or h.repo != repo:
                continue
            rows.append({
                "verdict": c.verdict or "(unclassified)",
                "bug_class": c.bug_class or "(unknown)",
                "severity": c.severity or "(unset)",
                "cwe": c.cwe or "(unset)",
                "id": c.id, "stack_top_hash": c.stack_top_hash,
                "minimized_path": c.minimized_path, "vuln_report_path": c.vuln_report_path,
                "reproducer_path": c.reproducer_path,
            })
    if not rows:
        return []
    if by == "verdict_bug_class":
        def keyf(r):
            return (r["verdict"], r["bug_class"])
    else:
        def keyf(r):
            return r[by]
    buckets: dict = {}
    for r in rows:
        k = keyf(r)
        buckets.setdefault(k, []).append(r)
    out = []
    for k, members in sorted(buckets.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        label = " / ".join(str(x) for x in k) if isinstance(k, tuple) else str(k)
        out.append({
            "group": label, "count": len(members),
            "crash_ids": [m["id"] for m in members],
            "stack_hashes": sorted({m["stack_top_hash"] for m in members if m["stack_top_hash"]}),
        })
    return out


@mcp.tool()
def update_crash_verdict(
    crash_id: Annotated[int, Field(description="crash id (from store_crash)")],
    verdict: Annotated[str, Field(description="One of: vulnerability, library_hardening, harness_bug, non_reproducible, oom, timeout, assertion_failure, duplicate, needs_investigation")],
    bug_class: Annotated[str, Field(description="One of: heap-buffer-overflow-read, heap-buffer-overflow-write, heap-use-after-free, stack-buffer-overflow, stack-overflow, global-buffer-overflow, null-deref, integer-overflow, signed-integer-overflow, divide-by-zero, uninitialised-read, undefined-behavior, assertion-failure, timeout, oom, other")] = "other",
    cwe: Annotated[str, Field(description="CWE identifier hint, e.g. 'CWE-125'. Empty string if not applicable.")] = "",
    severity: Annotated[str, Field(description="One of: low, medium, high, critical")] = "low",
    vuln_report_path: Annotated[str, Field(description="Absolute path to the markdown vuln report")] = "",
    reproducer_path: Annotated[str, Field(description="Absolute path to the .tgz reproducer artefact (from package_reproducer)")] = "",
    notes: Annotated[str, Field(description="Triage notes appended to the existing crash notes")] = "",
) -> str:
    """Persist the triage verdict for a crash."""
    with Session(_ENGINE) as session:
        c = session.get(Crash, crash_id)
        if not c:
            return f"crash {crash_id} not found"
        c.verdict = verdict
        c.bug_class = bug_class
        c.cwe = cwe or None
        c.severity = severity
        c.vuln_report_path = vuln_report_path or None
        c.reproducer_path = reproducer_path or None
        if notes:
            c.notes = (c.notes or "") + "\n\n--- triage ---\n" + notes
        session.commit()
        return f"updated crash {crash_id} verdict={verdict} severity={severity}"


@mcp.tool()
def get_crashes(repo: Annotated[str, Field(description="owner/repo")]) -> list[dict]:
    """All deduped crashes for a repo, joined back to their harness/target."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        out = []
        crashes = session.query(Crash).all()
        for c in crashes:
            run = session.get(FuzzRun, c.run_id) if c.run_id else None
            h = session.get(Harness, run.harness_id) if run else None
            if not h or h.repo != repo:
                continue
            out.append({
                "id": c.id, "harness_id": h.id, "target_id": h.target_id,
                "input_blob_path": c.input_blob_path, "minimized_path": c.minimized_path,
                "stack_top_hash": c.stack_top_hash, "classification": c.classification,
                "notes": c.notes,
                "verdict": c.verdict, "bug_class": c.bug_class,
                "cwe": c.cwe, "severity": c.severity,
                "vuln_report_path": c.vuln_report_path,
                "reproducer_path": c.reproducer_path,
                "sanitizer_output": c.sanitizer_output,
            })
        return out


@mcp.tool()
def clear_repo(repo: Annotated[str, Field(description="owner/repo")]) -> str:
    """Wipe all fuzzing state for a repo (targets, harnesses, runs, coverage, crashes, call graphs)."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        session.query(FuzzTarget).filter_by(repo=repo).delete()
        session.query(Harness).filter_by(repo=repo).delete()
        session.query(CallGraph).filter_by(repo=repo).delete()
        session.commit()
    return f"cleared fuzzing state for {repo}"


# ---------------------------------------------------------------------------
# E3: call-graph snapshots and untouched API surface
# ---------------------------------------------------------------------------

@mcp.tool()
def store_call_graph(
    repo: Annotated[str, Field(description="owner/repo")],
    dot_path: Annotated[str, Field(description="Path to the Graphviz .dot file")] = "",
    svg_path: Annotated[str, Field(description="Path to the rendered SVG (if available)")] = "",
    functions_total: Annotated[int, Field(description="Total functions defined in the repo (per ctags)")] = 0,
    functions_in_graph: Annotated[int, Field(description="Functions actually plotted (capped at max_nodes)")] = 0,
    functions_reached: Annotated[int, Field(description="Functions reached by at least one fuzzing run")] = 0,
    functions_unreached: Annotated[int, Field(description="Functions in the graph but never reached")] = 0,
    untouched_surface_json: Annotated[str, Field(description="JSON list of public-API function names never reached")] = "",
    target_id: Annotated[int | None, Field(description="Optional fuzz_target id if the graph is per-target")] = None,
) -> str:
    """Persist a call-graph snapshot for a repo. Replaces any prior snapshot for
    the same (repo, target_id) tuple — call graphs are always "latest"."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        existing = (
            session.query(CallGraph)
            .filter_by(repo=repo, target_id=target_id).first()
        )
        if existing:
            existing.dot_path = dot_path or existing.dot_path
            existing.svg_path = svg_path or existing.svg_path
            existing.functions_total = functions_total
            existing.functions_in_graph = functions_in_graph
            existing.functions_reached = functions_reached
            existing.functions_unreached = functions_unreached
            existing.untouched_surface_json = untouched_surface_json or existing.untouched_surface_json
            existing.generated_at = _now()
            session.commit()
            return f"updated call_graph id={existing.id}"
        cg = CallGraph(
            repo=repo, target_id=target_id, dot_path=dot_path or None, svg_path=svg_path or None,
            functions_total=functions_total, functions_in_graph=functions_in_graph,
            functions_reached=functions_reached, functions_unreached=functions_unreached,
            untouched_surface_json=untouched_surface_json or None, generated_at=_now(),
        )
        session.add(cg)
        session.commit()
        return f"created call_graph id={cg.id}"


@mcp.tool()
def get_call_graphs(repo: Annotated[str, Field(description="owner/repo")]) -> list[dict]:
    """Return all call-graph snapshots for a repo (most recent first)."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        rows = (
            session.query(CallGraph)
            .filter_by(repo=repo)
            .order_by(CallGraph.generated_at.desc())
            .all()
        )
        return [{
            "id": r.id, "repo": r.repo, "target_id": r.target_id,
            "dot_path": r.dot_path, "svg_path": r.svg_path,
            "functions_total": r.functions_total, "functions_in_graph": r.functions_in_graph,
            "functions_reached": r.functions_reached, "functions_unreached": r.functions_unreached,
            "untouched_surface_json": r.untouched_surface_json, "generated_at": r.generated_at,
        } for r in rows]


@mcp.tool()
def get_repo_reached_functions(
    repo: Annotated[str, Field(description="owner/repo")],
) -> list[str]:
    """Union of all function names hit (FNDA: > 0) by any coverage_report for this repo.

    The dashboard / call-graph builder uses this to compute the never-reached
    set across the entire campaign, not just the latest run.
    """
    repo = repo.lower()
    reached: set[str] = set()
    with Session(_ENGINE) as session:
        for h in session.query(Harness).filter_by(repo=repo).all():
            for fr in session.query(FuzzRun).filter_by(harness_id=h.id).all():
                rep = session.query(CoverageReport).filter_by(run_id=fr.id).first()
                if not rep or not rep.lcov_path:
                    continue
                p = Path(rep.lcov_path)
                if not p.is_file():
                    continue
                # Stream-parse FNDA: lines for speed.
                for raw in p.read_text(errors="replace").splitlines():
                    if raw.startswith("FNDA:"):
                        try:
                            hits_str, name = raw[5:].split(",", 1)
                            if int(hits_str) > 0:
                                reached.add(name)
                        except ValueError:
                            pass
    return sorted(reached)


# ---------------------------------------------------------------------------
# v8 — Harness suggestions (G1-lite)
# ---------------------------------------------------------------------------

@mcp.tool()
def store_harness_suggestion(
    repo: Annotated[str, Field(description="owner/repo")],
    function_name: Annotated[str, Field(description="Name of the public-API function to write a new harness for")],
    file: Annotated[str, Field(description="Source file where the function is defined (best effort)")] = "",
    rationale: Annotated[str, Field(description="Why this function is worth a new harness — be brief")] = "",
    input_kind: Annotated[str, Field(description="Best-guess input kind (e.g. 'utf8 string', 'png file', 'json text')")] = "",
    priority: Annotated[int, Field(description="1 (highest) to 10 (lowest); used to sort the suggestions list")] = 5,
) -> str:
    """Persist a new-harness suggestion produced by the analyze_call_graph or
    triage stage. The next campaign can read these via get_harness_suggestions
    and decide whether to write a harness for them.

    Idempotent on (repo, function_name): re-suggesting the same function
    updates rationale/priority rather than creating duplicates.
    """
    repo = repo.lower()
    with Session(_ENGINE) as session:
        existing = session.query(HarnessSuggestion).filter_by(
            repo=repo, function_name=function_name,
        ).first()
        if existing:
            existing.file = file or existing.file
            existing.rationale = rationale or existing.rationale
            existing.input_kind = input_kind or existing.input_kind
            existing.priority = min(existing.priority, priority)
            existing.suggested_at = _now()
            session.commit()
            return f"updated suggestion id={existing.id} for {function_name}"
        s = HarnessSuggestion(
            repo=repo, function_name=function_name, file=file or None,
            rationale=rationale or None, input_kind=input_kind or None,
            priority=priority, suggested_at=_now(),
        )
        session.add(s)
        session.commit()
        return f"created suggestion id={s.id} for {function_name}"


@mcp.tool()
def get_harness_suggestions(
    repo: Annotated[str, Field(description="owner/repo")],
    limit: Annotated[int, Field(description="Max suggestions to return (sorted by priority asc)")] = 25,
) -> list[dict]:
    """Return the agent-suggested new harnesses for a repo, sorted by priority."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        rows = (
            session.query(HarnessSuggestion)
            .filter_by(repo=repo)
            .order_by(HarnessSuggestion.priority, HarnessSuggestion.id)
            .limit(limit)
            .all()
        )
        return [{
            "id": r.id, "repo": r.repo, "function_name": r.function_name,
            "file": r.file, "rationale": r.rationale, "input_kind": r.input_kind,
            "priority": r.priority, "suggested_at": r.suggested_at,
        } for r in rows]


# ---------------------------------------------------------------------------
# v8 — Iteration notes (timeline for dashboard)
# ---------------------------------------------------------------------------

@mcp.tool()
def store_iteration_note(
    repo: Annotated[str, Field(description="owner/repo")],
    iteration_number: Annotated[int, Field(description="Iteration the note applies to (1-indexed; use 0 for the qualifier round)")],
    note: Annotated[str, Field(description="One-line note: what changed, what was tried, what was learned")],
    harness_id: Annotated[int | None, Field(description="Optional harness id this note refers to")] = None,
) -> str:
    """Persist a one-line note for an iteration, for the dashboard's timeline."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        n = IterationNote(
            repo=repo, harness_id=harness_id, iteration_number=iteration_number,
            note=note[:500], created_at=_now(),
        )
        session.add(n)
        session.commit()
        return f"stored iteration_note id={n.id}"


@mcp.tool()
def get_iteration_notes(
    repo: Annotated[str, Field(description="owner/repo")],
    limit: Annotated[int, Field(description="Max notes to return, newest first")] = 200,
) -> list[dict]:
    """Return iteration notes for a repo, newest first."""
    repo = repo.lower()
    with Session(_ENGINE) as session:
        rows = (
            session.query(IterationNote)
            .filter_by(repo=repo)
            .order_by(IterationNote.created_at.desc(), IterationNote.id.desc())
            .limit(limit)
            .all()
        )
        return [{
            "id": n.id, "iteration_number": n.iteration_number,
            "harness_id": n.harness_id, "note": n.note,
            "created_at": n.created_at,
        } for n in rows]


if __name__ == "__main__":
    mcp.run(show_banner=False)

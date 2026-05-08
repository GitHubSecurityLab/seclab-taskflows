# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import importlib
import sqlite3 as _sqlite3

import pytest
from sqlalchemy.orm import Session

from seclab_taskflows.mcp_servers import fuzz_context as _fc_module
from seclab_taskflows.mcp_servers.fuzz_context_models import CoverageReport


# Force an in-memory DB by setting FUZZ_CONTEXT_DIR to a non-existent path.
# fuzz_context picks the SQLite "sqlite://" sentinel when the dir doesn't exist,
# matching the codebase convention used by repo_context, codeql_python, etc.
@pytest.fixture(autouse=True)
def isolated_fc(monkeypatch, tmp_path):
    nonexistent = tmp_path / "does_not_exist"
    monkeypatch.setenv("FUZZ_CONTEXT_DIR", str(nonexistent))
    # Reload module so MEMORY/_ENGINE pick up the new env var.
    importlib.reload(_fc_module)
    return _fc_module


# ---------------------------------------------------------------------------
# LCOV parser
# ---------------------------------------------------------------------------

class TestLcovParser:
    def test_minimal_lcov(self, isolated_fc):
        fc = isolated_fc
        sample = (
            "SF:/tmp/foo.c\n"
            "FN:10,foo\n"
            "FNDA:0,foo\n"
            "FN:20,bar\n"
            "FNDA:5,bar\n"
            "DA:10,0\n"
            "DA:11,3\n"
            "DA:20,5\n"
            "BRDA:11,0,0,5\n"
            "BRDA:11,0,1,-\n"
            "end_of_record\n"
        )
        parsed = fc._parse_lcov(sample)
        t = parsed["totals"]
        assert t["lines_total"] == 3
        assert t["lines_hit"] == 2
        assert t["fns_total"] == 2
        assert t["fns_hit"] == 1
        assert t["branches_total"] == 2
        assert t["branches_hit"] == 1
        # gap rows include the uncovered function and the uncovered line and the not-taken branch
        kinds = sorted([g["kind"] for g in parsed["gaps"]])
        assert kinds == ["branch", "fn", "line"]

    def test_llvm_cov_extra_checksum(self, isolated_fc):
        # llvm-cov sometimes emits "DA:<line>,<hits>,<checksum>"
        fc = isolated_fc
        sample = "SF:/tmp/x.c\nDA:1,7,abc123\nend_of_record\n"
        parsed = fc._parse_lcov(sample)
        assert parsed["totals"]["lines_total"] == 1
        assert parsed["totals"]["lines_hit"] == 1

    def test_unknown_lines_are_ignored(self, isolated_fc):
        fc = isolated_fc
        sample = (
            "TN:my_test\n"
            "SF:/tmp/y.c\n"
            "VER:1\n"
            "DA:1,0\n"
            "end_of_record\n"
            "garbage\n"
        )
        parsed = fc._parse_lcov(sample)
        assert parsed["totals"]["lines_total"] == 1
        assert parsed["totals"]["lines_hit"] == 0


# ---------------------------------------------------------------------------
# fuzz_target / harness CRUD
# ---------------------------------------------------------------------------

class TestFuzzTargetCrud:
    def test_store_and_get(self, isolated_fc):
        fc = isolated_fc
        msg = fc.store_fuzz_target.fn(
            repo="example/foo", file="src/parser.c", function="parse_blob",
            signature="int parse_blob(const uint8_t*, size_t)",
            input_kind="bytes", notes="parses the on-disk blob format",
        )
        assert "fuzz_target" in msg
        rows = fc.get_fuzz_targets.fn(repo="example/foo")
        assert len(rows) == 1
        assert rows[0]["function"] == "parse_blob"
        # repo is normalised to lower-case
        assert rows[0]["repo"] == "example/foo"

    def test_store_is_upsert(self, isolated_fc):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="example/foo", file="a.c", function="f", notes="first")
        fc.store_fuzz_target.fn(repo="example/foo", file="a.c", function="f", notes="second")
        rows = fc.get_fuzz_targets.fn(repo="example/foo")
        assert len(rows) == 1
        assert "first" in rows[0]["notes"]
        assert "second" in rows[0]["notes"]


class TestHarnessCrud:
    def test_version_bump(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="example/bar", file="x.c", function="g")
        target_id = fc.get_fuzz_targets.fn(repo="example/bar")[0]["id"]
        h_path = str(tmp_path / "h.c")
        fc.store_harness.fn(target_id=target_id, repo="example/bar", harness_path=h_path)
        msg = fc.store_harness.fn(target_id=target_id, repo="example/bar", harness_path=h_path)
        assert "version 2" in msg

    def test_update_build_status(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="example/bar", file="x.c", function="g")
        target_id = fc.get_fuzz_targets.fn(repo="example/bar")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="example/bar", harness_path=str(tmp_path / "h.c"))
        h = fc.get_harnesses.fn(repo="example/bar")[0]
        fc.update_harness_build.fn(
            harness_id=h["id"], afl_binary_path=str(tmp_path / "h.afl"), cov_binary_path=str(tmp_path / "h.cov"),
            build_cmd_afl="afl-clang-lto ...", build_cmd_cov="clang ...", build_status="ok",
        )
        h2 = fc.get_harnesses.fn(repo="example/bar")[0]
        assert h2["build_status"] == "ok"
        assert h2["afl_binary_path"] == str(tmp_path / "h.afl")


# ---------------------------------------------------------------------------
# Coverage persistence + plateau detection
# ---------------------------------------------------------------------------

def _seed_runs(fc, harness_id, line_pcts, base_dir):
    """Insert one fuzz_run + coverage_report per entry in line_pcts."""
    for i, pct in enumerate(line_pcts, start=1):
        run_id = fc.start_fuzz_run.fn(
            harness_id=harness_id, iteration_number=i,
            time_budget_seconds=30 * (2 ** (i - 1)), output_dir=str(base_dir / f"it{i}"),
        )
        fc.finish_fuzz_run.fn(run_id=run_id, status="completed")
        with Session(fc._ENGINE) as session:
            session.add(CoverageReport(
                run_id=run_id, lines_total=100, lines_hit=int(pct),
                line_pct=float(pct), fns_total=10, fns_hit=int(pct/10),
                fn_pct=float(pct), branches_total=20, branches_hit=int(pct/5),
                branch_pct=float(pct),
            ))
            session.commit()


class TestCoverageSummary:
    def test_summary_orders_by_iteration(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/p", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/p")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/p", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/p")[0]["id"]
        _seed_runs(fc, h_id, [10.0, 25.0, 30.0], tmp_path)
        summary = fc._coverage_summary(h_id)
        assert [s["iteration"] for s in summary] == [1, 2, 3]
        assert [s["line_pct"] for s in summary] == [10.0, 25.0, 30.0]

    def test_plateau_needs_three_iterations(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/q", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/q")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/q", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/q")[0]["id"]
        _seed_runs(fc, h_id, [5.0, 50.0], tmp_path)  # only 2 iterations
        result = fc.coverage_plateau_reached.fn(harness_id=h_id, threshold_pct=1.0)
        assert result["plateau"] is False
        assert "need at least 3" in result["reason"]

    def test_plateau_when_growth_below_threshold(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/r", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/r")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/r", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/r")[0]["id"]
        # Iterations gaining 30, 0.5, 0.4 — last two are < 1.0 → plateau
        _seed_runs(fc, h_id, [30.0, 30.5, 30.9], tmp_path)
        result = fc.coverage_plateau_reached.fn(harness_id=h_id, threshold_pct=1.0)
        assert result["plateau"] is True

    def test_no_plateau_when_still_growing(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/s", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/s")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/s", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/s")[0]["id"]
        _seed_runs(fc, h_id, [30.0, 50.0, 60.0], tmp_path)
        result = fc.coverage_plateau_reached.fn(harness_id=h_id, threshold_pct=1.0)
        assert result["plateau"] is False


class TestStoreCoverageFromLcov:
    def test_persists_report_and_capped_gaps(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/cov", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/cov")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/cov", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/cov")[0]["id"]
        run_id = fc.start_fuzz_run.fn(harness_id=h_id, iteration_number=1, time_budget_seconds=30)
        fc.finish_fuzz_run.fn(run_id=run_id)

        # Build a tiny LCOV file with 4 uncovered lines and 2 uncovered fns
        lcov = tmp_path / "out.lcov"
        lcov.write_text(
            "SF:/src/a.c\n"
            "FN:1,a\nFNDA:0,a\nFN:5,b\nFNDA:0,b\n"
            "DA:1,0\nDA:2,0\nDA:5,0\nDA:6,0\n"
            "end_of_record\n"
        )
        result = fc.store_coverage_from_lcov.fn(run_id=run_id, lcov_path=str(lcov), max_gaps=3)
        assert result["totals"]["lines_total"] == 4
        assert result["totals"]["fns_total"] == 2
        assert result["gaps_total"] == 6  # 2 fn + 4 line
        assert result["gaps_persisted"] == 3
        # Function gaps have higher priority than line gaps
        gaps = fc.get_coverage_gaps.fn(harness_id=h_id, kind="fn", limit=10)
        assert {g["function"] for g in gaps} == {"a", "b"}


# ---------------------------------------------------------------------------
# Crash dedup
# ---------------------------------------------------------------------------

class TestCrashDedup:
    def test_same_hash_is_dedup(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/c", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/c")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/c", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/c")[0]["id"]
        run_id = fc.start_fuzz_run.fn(harness_id=h_id, iteration_number=1, time_budget_seconds=30)
        msg1 = fc.store_crash.fn(run_id=run_id, input_blob_path=str(tmp_path / "c1"), stack_top_hash="abc123")
        msg2 = fc.store_crash.fn(run_id=run_id, input_blob_path=str(tmp_path / "c2"), stack_top_hash="abc123")
        assert "stored crash" in msg1
        assert "duplicate" in msg2
        assert len(fc.get_crashes.fn(repo="ex/c")) == 1


class TestUpdateCrashVerdict:
    def test_persists_all_fields(self, isolated_fc, tmp_path):
        fc = isolated_fc
        fc.store_fuzz_target.fn(repo="ex/v", file="x.c", function="f")
        target_id = fc.get_fuzz_targets.fn(repo="ex/v")[0]["id"]
        fc.store_harness.fn(target_id=target_id, repo="ex/v", harness_path=str(tmp_path / "h.c"))
        h_id = fc.get_harnesses.fn(repo="ex/v")[0]["id"]
        run_id = fc.start_fuzz_run.fn(harness_id=h_id, iteration_number=1, time_budget_seconds=30)
        fc.store_crash.fn(run_id=run_id, input_blob_path=str(tmp_path / "c1"), stack_top_hash="hash1")
        crash_id = fc.get_crashes.fn(repo="ex/v")[0]["id"]
        msg = fc.update_crash_verdict.fn(
            crash_id=crash_id,
            verdict="vulnerability",
            bug_class="heap-buffer-overflow-read",
            cwe="CWE-125",
            severity="high",
            vuln_report_path=str(tmp_path / "vuln_1.md"),
            notes="reachable through public lzma_stream_buffer_decode",
        )
        assert "verdict=vulnerability" in msg
        c = fc.get_crashes.fn(repo="ex/v")[0]
        assert c["verdict"] == "vulnerability"
        assert c["bug_class"] == "heap-buffer-overflow-read"
        assert c["cwe"] == "CWE-125"
        assert c["severity"] == "high"
        assert c["vuln_report_path"].endswith("vuln_1.md")
        assert "reachable through public" in c["notes"]

    def test_unknown_crash_returns_message(self, isolated_fc):
        fc = isolated_fc
        msg = fc.update_crash_verdict.fn(crash_id=999999, verdict="harness_bug")
        assert "not found" in msg


class TestMigration:
    def test_alter_table_adds_missing_columns(self, monkeypatch, tmp_path):
        # Build a "v2-shape" DB by hand (without the v3 columns), then verify
        # that initialising a v3 fuzz_context engine ALTERs it.
        db = tmp_path / "fuzz_context.db"
        conn = _sqlite3.connect(db)
        conn.executescript("""
        CREATE TABLE crash (
            id INTEGER PRIMARY KEY,
            run_id INTEGER,
            input_blob_path TEXT,
            minimized_path TEXT,
            stack_top_hash TEXT,
            sanitizer_output TEXT,
            classification TEXT,
            notes TEXT
        );
        """)
        conn.commit()
        conn.close()

        monkeypatch.setenv("FUZZ_CONTEXT_DIR", str(tmp_path))
        importlib.reload(_fc_module)
        cols = _sqlite3.connect(db).execute("PRAGMA table_info(crash)").fetchall()
        names = {row[1] for row in cols}
        for new_col in ("verdict", "bug_class", "cwe", "severity", "vuln_report_path"):
            assert new_col in names, f"missing column {new_col}"


class TestHarnessSuggestions:
    def test_store_and_get(self, isolated_fc):
        fc = isolated_fc
        r1 = fc.store_harness_suggestion.fn(
            repo="ex/v8", function_name="parse_xml",
            file="src/xml.c",
            rationale="public parser entry point",
            input_kind="bytes", priority=1,
        )
        r2 = fc.store_harness_suggestion.fn(
            repo="ex/v8", function_name="json_decode",
            rationale="format decoder", priority=5,
        )
        assert "id=" in r1
        assert "id=" in r2

        rows = fc.get_harness_suggestions.fn(repo="ex/v8")
        assert [r["function_name"] for r in rows] == ["parse_xml", "json_decode"]
        assert rows[0]["priority"] == 1
        assert rows[0]["input_kind"] == "bytes"

    def test_repo_isolation(self, isolated_fc):
        fc = isolated_fc
        fc.store_harness_suggestion.fn(repo="ex/a", function_name="f")
        fc.store_harness_suggestion.fn(repo="ex/b", function_name="g")
        rows_a = fc.get_harness_suggestions.fn(repo="ex/a")
        assert len(rows_a) == 1
        assert rows_a[0]["function_name"] == "f"

    def test_idempotent_on_repo_function(self, isolated_fc):
        fc = isolated_fc
        fc.store_harness_suggestion.fn(repo="ex/i", function_name="f", priority=5)
        fc.store_harness_suggestion.fn(
            repo="ex/i", function_name="f", priority=2, rationale="updated",
        )
        rows = fc.get_harness_suggestions.fn(repo="ex/i")
        assert len(rows) == 1
        assert rows[0]["priority"] == 2
        assert rows[0]["rationale"] == "updated"


class TestIterationNotes:
    def test_store_and_get_in_reverse_chrono(self, isolated_fc):
        fc = isolated_fc
        fc.store_iteration_note.fn(repo="ex/v8", iteration_number=1, note="first")
        fc.store_iteration_note.fn(repo="ex/v8", iteration_number=2, note="second")
        notes = fc.get_iteration_notes.fn(repo="ex/v8")
        assert [n["note"] for n in notes] == ["second", "first"]
        assert notes[0]["iteration_number"] == 2

    def test_truncates_long_notes(self, isolated_fc):
        fc = isolated_fc
        long_note = "x" * 1000
        fc.store_iteration_note.fn(repo="ex/v8", iteration_number=1, note=long_note)
        rows = fc.get_iteration_notes.fn(repo="ex/v8")
        assert len(rows[0]["note"]) <= 500


# ---------------------------------------------------------------------------
# Recovered v3-v7 tests (re-derived after accidental git-checkout in v8)
# ---------------------------------------------------------------------------

class TestSuggestSeverity:
    """Severity defaults follow OSS-Fuzz / ClusterFuzz conventions."""

    def test_high_for_writes(self, isolated_fc):
        fc = isolated_fc
        for bc in (
            "heap-buffer-overflow-write", "stack-buffer-overflow",
            "global-buffer-overflow", "heap-use-after-free",
        ):
            assert fc.suggest_severity.fn(bug_class=bc)["suggested_severity"] == "high"

    def test_medium_for_reads(self, isolated_fc):
        fc = isolated_fc
        for bc in ("heap-buffer-overflow-read", "uninitialised-read", "stack-overflow"):
            assert fc.suggest_severity.fn(bug_class=bc)["suggested_severity"] == "medium"

    def test_low_for_dos(self, isolated_fc):
        fc = isolated_fc
        for bc in (
            "null-deref", "integer-overflow", "signed-integer-overflow",
            "divide-by-zero", "assertion-failure", "timeout", "oom",
        ):
            assert fc.suggest_severity.fn(bug_class=bc)["suggested_severity"] == "low"

    def test_unknown_falls_back_to_low(self, isolated_fc):
        fc = isolated_fc
        out = fc.suggest_severity.fn(bug_class="brand-new-bug-class")
        assert out["suggested_severity"] == "low"
        assert "Default for bug_class" in out["rationale"]

    def test_case_insensitive(self, isolated_fc):
        fc = isolated_fc
        a = fc.suggest_severity.fn(bug_class="HEAP-BUFFER-OVERFLOW-WRITE")
        b = fc.suggest_severity.fn(bug_class="heap-buffer-overflow-write")
        assert a["suggested_severity"] == b["suggested_severity"] == "high"


class TestCallGraphPersistence:
    def test_store_and_get(self, isolated_fc, tmp_path):
        fc = isolated_fc
        dot = str(tmp_path / "g.dot")
        svg = str(tmp_path / "g.svg")
        result = fc.store_call_graph.fn(
            repo="ex/g", dot_path=dot, svg_path=svg,
            functions_total=100, functions_in_graph=80,
            functions_reached=30, functions_unreached=50,
            untouched_surface_json='["foo","bar"]',
        )
        assert "created call_graph" in result
        rows = fc.get_call_graphs.fn(repo="ex/g")
        assert len(rows) == 1
        r = rows[0]
        assert r["functions_total"] == 100
        assert r["functions_reached"] == 30
        assert r["dot_path"] == dot
        assert r["untouched_surface_json"] == '["foo","bar"]'

    def test_upsert_per_repo_target(self, isolated_fc):
        fc = isolated_fc
        # First snapshot.
        fc.store_call_graph.fn(repo="ex/g", functions_reached=10)
        # Second snapshot for same (repo, target_id=None) — should UPDATE,
        # not insert a second row.
        result = fc.store_call_graph.fn(repo="ex/g", functions_reached=42)
        assert "updated call_graph" in result
        rows = fc.get_call_graphs.fn(repo="ex/g")
        assert len(rows) == 1
        assert rows[0]["functions_reached"] == 42

    def test_per_target_separate_rows(self, isolated_fc):
        fc = isolated_fc
        fc.store_call_graph.fn(repo="ex/g", target_id=1, functions_reached=10)
        fc.store_call_graph.fn(repo="ex/g", target_id=2, functions_reached=20)
        rows = fc.get_call_graphs.fn(repo="ex/g")
        assert len(rows) == 2
        assert sorted(r["target_id"] for r in rows) == [1, 2]


class TestRepoReachedFunctions:
    def test_empty_when_no_runs(self, isolated_fc):
        fc = isolated_fc
        assert fc.get_repo_reached_functions.fn(repo="ex/none") == []

    def test_returns_union_across_runs(self, isolated_fc, tmp_path):
        fc = isolated_fc
        # Build 2 LCOV files with different reached fns; persist via
        # store_coverage_from_lcov so the harness/run/report linkage exists.
        target_msg = fc.store_fuzz_target.fn(
            repo="ex/g", file="src/p.c", function="parse",
            signature="void(const char*)", input_kind="bytes",
        )
        target_id = int(target_msg.rsplit("=", 1)[-1])
        h_msg = fc.store_harness.fn(
            target_id=target_id, repo="ex/g",
            harness_path=str(tmp_path / "h.c"), sanitizers="address",
        )
        harness_id = int(h_msg.rsplit("=", 1)[-1])
        run_id = fc.start_fuzz_run.fn(
            harness_id=harness_id, iteration_number=1, time_budget_seconds=30,
        )
        lcov1 = tmp_path / "1.lcov"
        lcov1.write_text("SF:src/p.c\nFNDA:5,parse\nFNDA:0,unused\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
        fc.store_coverage_from_lcov.fn(run_id=run_id, lcov_path=str(lcov1))
        run2_id = fc.start_fuzz_run.fn(
            harness_id=harness_id, iteration_number=2, time_budget_seconds=30,
        )
        lcov2 = tmp_path / "2.lcov"
        lcov2.write_text("SF:src/p.c\nFNDA:7,helper\nDA:1,1\nLF:1\nLH:1\nend_of_record\n")
        fc.store_coverage_from_lcov.fn(run_id=run2_id, lcov_path=str(lcov2))

        names = fc.get_repo_reached_functions.fn(repo="ex/g")
        assert "parse" in names
        assert "helper" in names
        # Hits=0 functions are excluded.
        assert "unused" not in names


class TestGetCrashesGrouped:
    def _seed_repo_with_crashes(self, fc, tmp_path, rows):
        """rows: list of (verdict, bug_class, severity, hash)."""
        target_msg = fc.store_fuzz_target.fn(
            repo="ex/g", file="src/p.c", function="parse",
            signature="void(const char*)", input_kind="bytes",
        )
        tid = int(target_msg.rsplit("=", 1)[-1])
        h_msg = fc.store_harness.fn(
            target_id=tid, repo="ex/g",
            harness_path=str(tmp_path / "h.c"), sanitizers="address",
        )
        hid = int(h_msg.rsplit("=", 1)[-1])
        rid = fc.start_fuzz_run.fn(
            harness_id=hid, iteration_number=1, time_budget_seconds=30,
        )
        for verdict, bug_class, severity, sth in rows:
            crash_msg = fc.store_crash.fn(
                run_id=rid, input_blob_path=str(tmp_path / "x"),
                minimized_path=str(tmp_path / "x.min"),
                stack_top_hash=sth, sanitizer_output="...", classification="...",
            )
            cid = int(crash_msg.rsplit("=", 1)[-1])
            fc.update_crash_verdict.fn(
                crash_id=cid, verdict=verdict, bug_class=bug_class,
                severity=severity, cwe="", vuln_report_path="",
            )

    def test_groups_by_verdict_bug_class(self, isolated_fc, tmp_path):
        fc = isolated_fc
        self._seed_repo_with_crashes(fc, tmp_path, [
            ("vulnerability", "heap-buffer-overflow-write", "high", "x1"),
            ("vulnerability", "heap-buffer-overflow-write", "high", "x2"),
            ("library_hardening", "null-deref", "low", "x3"),
        ])
        groups = fc.get_crashes_grouped.fn(repo="ex/g", by="verdict_bug_class")
        # Sorted by count desc.
        assert groups[0]["count"] == 2
        assert "vulnerability" in groups[0]["group"]
        assert "heap-buffer-overflow-write" in groups[0]["group"]

    def test_groups_by_severity(self, isolated_fc, tmp_path):
        fc = isolated_fc
        self._seed_repo_with_crashes(fc, tmp_path, [
            ("vulnerability", "heap-buffer-overflow-write", "high", "x1"),
            ("library_hardening", "heap-buffer-overflow-read", "medium", "x2"),
            ("library_hardening", "null-deref", "low", "x3"),
        ])
        groups = fc.get_crashes_grouped.fn(repo="ex/g", by="severity")
        assert {g["group"] for g in groups} == {"high", "medium", "low"}

    def test_invalid_by_returns_error(self, isolated_fc):
        fc = isolated_fc
        result = fc.get_crashes_grouped.fn(repo="ex/g", by="bogus")
        assert "error" in result[0]

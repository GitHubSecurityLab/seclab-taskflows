# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Tests for the fuzzing dashboard's HTML renderer (no HTTP server here)."""

import importlib.util
import json
import sqlite3
from pathlib import Path

import pytest


def _load_dashboard():
    spec = importlib.util.spec_from_file_location(
        "fuzz_dashboard",
        Path(__file__).parent.parent / "scripts" / "fuzzing" / "dashboard.py",
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def dashboard():
    return _load_dashboard()


@pytest.fixture
def populated_db(tmp_path, dashboard):
    db = tmp_path / "fuzz.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE fuzz_target (id INTEGER PRIMARY KEY, repo TEXT, component_id INTEGER,
            file TEXT, function TEXT, signature TEXT, input_kind TEXT, notes TEXT);
        CREATE TABLE harness (id INTEGER PRIMARY KEY, target_id INTEGER, repo TEXT,
            harness_path TEXT, afl_binary_path TEXT, cov_binary_path TEXT,
            build_cmd_afl TEXT, build_cmd_cov TEXT, sanitizers TEXT,
            version INTEGER, build_status TEXT, notes TEXT);
        CREATE TABLE seed_corpus (id INTEGER PRIMARY KEY, target_id INTEGER, source TEXT,
            path TEXT, bytes_count INTEGER, added_in_iteration INTEGER);
        CREATE TABLE fuzz_run (id INTEGER PRIMARY KEY, harness_id INTEGER,
            iteration_number INTEGER, time_budget_seconds INTEGER,
            started_at TEXT, ended_at TEXT, exec_per_sec REAL,
            paths_total INTEGER, crashes_count INTEGER, hangs_count INTEGER,
            output_dir TEXT, status TEXT);
        CREATE TABLE coverage_report (id INTEGER PRIMARY KEY, run_id INTEGER,
            lines_total INTEGER, lines_hit INTEGER, line_pct REAL,
            fns_total INTEGER, fns_hit INTEGER, fn_pct REAL,
            branches_total INTEGER, branches_hit INTEGER, branch_pct REAL,
            lcov_path TEXT);
        CREATE TABLE coverage_gap (id INTEGER PRIMARY KEY, report_id INTEGER,
            file TEXT, function TEXT, line INTEGER, kind TEXT, reason_hint TEXT);
        CREATE TABLE crash (id INTEGER PRIMARY KEY, run_id INTEGER,
            input_blob_path TEXT, minimized_path TEXT, stack_top_hash TEXT,
            sanitizer_output TEXT, classification TEXT, notes TEXT);
        """
    )
    conn.commit()
    conn.close()
    # Run the migration to add the v3 columns to the bare-bones schema above.
    dashboard._migrate_if_writable(db)
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        INSERT INTO fuzz_target VALUES (1, 'demo/lib', NULL, 'src/parser.c', 'parse', '', 'bytes', '');
        INSERT INTO harness VALUES (1, 1, 'demo/lib', '/tmp/h.c', '/tmp/h.afl', '/tmp/h.cov',
            'afl-clang-lto ...', 'clang ...', 'address,undefined', 1, 'ok', '');
        INSERT INTO fuzz_run VALUES (1, 1, 1, 30, '2026-01-01T00:00:00', '2026-01-01T00:00:30',
            12345.6, 7, 1, 0, '/tmp/run1', 'completed');
        INSERT INTO coverage_report (id, run_id, lines_total, lines_hit, line_pct,
            fns_total, fns_hit, fn_pct, branches_total, branches_hit, branch_pct, lcov_path)
            VALUES (1, 1, 100, 30, 30.0, 10, 3, 30.0, 50, 10, 20.0, '/tmp/cov.lcov');
        INSERT INTO coverage_gap VALUES (1, 1, 'src/parser.c', 'unreached_helper', 42, 'fn', NULL);
        INSERT INTO crash (id, run_id, input_blob_path, minimized_path, stack_top_hash,
            sanitizer_output, classification, notes)
            VALUES (1, 1, '/tmp/c1', '/tmp/c1.min', 'hash1',
                'AddressSanitizer: heap-buffer-overflow READ 4',
                'heap-buffer-overflow READ 4 in parse', 'orig notes');
        UPDATE crash SET verdict='vulnerability', bug_class='heap-buffer-overflow-read',
            cwe='CWE-125', severity='high',
            vuln_report_path='/home/vscode/.local/share/seclab-taskflow-agent/fake/vuln_1.md'
            WHERE id=1;
        INSERT INTO crash (id, run_id, input_blob_path, minimized_path, stack_top_hash,
            sanitizer_output, classification, notes)
            VALUES (2, 1, '/tmp/c2', '/tmp/c2.min', 'hash2', 'SEGV', 'SEGV', 'orig notes 2');
        UPDATE crash SET verdict='harness_bug' WHERE id=2;
        """
    )
    conn.commit()
    conn.close()
    return db


def test_render_with_data(dashboard, populated_db):
    html = dashboard.render_dashboard(populated_db, None, refresh=False)
    assert "Fuzzing dashboard" in html
    assert "demo/lib" in html
    assert "Crashes" in html
    assert "vulnerability" in html
    assert "harness_bug" in html
    assert "heap-buffer-overflow-read" in html
    assert "CWE-125" in html
    assert "Coverage trend" in html
    assert "30.0%" in html
    assert "unreached_helper" in html
    # Vulnerability sorts before harness_bug in the Crashes table.
    crashes_section = html[html.index("<h2>Crashes"):]
    assert crashes_section.index("vulnerability") < crashes_section.index("harness_bug")
    # v4 additions
    assert "/api/json" in html
    assert "chip" in html


def test_render_json_aggregate(dashboard, populated_db):
    out = dashboard.render_json(populated_db, None)
    parsed = json.loads(out)
    assert parsed["repos"] == ["demo/lib"]


def test_render_json_per_repo(dashboard, populated_db):
    out = dashboard.render_json(populated_db, "demo/lib")
    parsed = json.loads(out)
    assert parsed["repo"] == "demo/lib"
    assert len(parsed["harnesses"]) == 1
    assert parsed["harnesses"][0]["coverage"][0]["line_pct"] == 30.0
    assert len(parsed["crashes"]) == 2
    assert any(c["verdict"] == "vulnerability" for c in parsed["crashes"])


def test_render_missing_db(dashboard, tmp_path):
    html = dashboard.render_dashboard(tmp_path / "no_such.db", None, refresh=False)
    assert "No database yet" in html


def test_render_empty_db(dashboard, tmp_path):
    db = tmp_path / "empty.db"
    sqlite3.connect(db).executescript(
        "CREATE TABLE fuzz_target (id INTEGER PRIMARY KEY, repo TEXT);"
    )
    html = dashboard.render_dashboard(db, None, refresh=False)
    # Either "no data" message or graceful "not fully initialised".
    assert "No fuzzing data yet" in html or "not fully initialised" in html


def test_refresh_meta_toggle(dashboard, populated_db):
    on = dashboard.render_dashboard(populated_db, None, refresh=True)
    off = dashboard.render_dashboard(populated_db, None, refresh=False)
    assert 'http-equiv="refresh"' in on
    assert 'http-equiv="refresh"' not in off


def test_html_escapes_repo_name(dashboard, tmp_path):
    db = tmp_path / "evil.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        "CREATE TABLE fuzz_target (id INTEGER PRIMARY KEY, repo TEXT, component_id INTEGER, "
        "    file TEXT, function TEXT, signature TEXT, input_kind TEXT, notes TEXT);"
        "CREATE TABLE harness (id INTEGER PRIMARY KEY, repo TEXT);"
        "CREATE TABLE fuzz_run (id INTEGER PRIMARY KEY, harness_id INTEGER, status TEXT);"
        "CREATE TABLE crash (id INTEGER PRIMARY KEY, run_id INTEGER);"
        "INSERT INTO fuzz_target (repo) VALUES ('<script>alert(1)</script>');"
    )
    conn.commit()
    conn.close()
    html = dashboard.render_dashboard(db, None, refresh=False)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html


def test_sparkline(dashboard):
    svg = dashboard._sparkline_svg([1.0, 2.0, 3.0, 5.0])
    assert svg.startswith("<svg")
    assert "polyline" in svg
    assert dashboard._sparkline_svg([]) == ""
    # Single-value series doesn't divide-by-zero.
    assert "<svg" in dashboard._sparkline_svg([42.0])


def test_v8_heatmap_renders(dashboard, populated_db):
    html = dashboard.render_dashboard(populated_db, None, refresh=False)
    assert "Crash heatmap" in html
    assert "iter 1" in html
    assert "h.c" in html


def test_v8_iteration_timeline_section_exists(dashboard, populated_db):
    html = dashboard.render_dashboard(populated_db, None, refresh=False)
    assert "Iteration timeline" in html


def test_v8_iteration_timeline_with_data(dashboard, tmp_path):
    db = tmp_path / "v8.db"
    conn = sqlite3.connect(db)
    conn.executescript(
        """
        CREATE TABLE fuzz_target (id INTEGER PRIMARY KEY, repo TEXT);
        CREATE TABLE harness (id INTEGER PRIMARY KEY, target_id INTEGER, repo TEXT,
            harness_path TEXT);
        CREATE TABLE fuzz_run (id INTEGER PRIMARY KEY, harness_id INTEGER,
            iteration_number INTEGER, status TEXT);
        CREATE TABLE crash (id INTEGER PRIMARY KEY, run_id INTEGER);
        CREATE TABLE iteration_note (id INTEGER PRIMARY KEY, repo TEXT, harness_id INTEGER,
            iteration_number INTEGER, note TEXT, created_at TEXT);
        INSERT INTO fuzz_target VALUES (1, 'demo/x');
        INSERT INTO harness VALUES (1, 1, 'demo/x', '/tmp/h.c');
        INSERT INTO iteration_note VALUES (1, 'demo/x', 1, 1, 'first note',
            '2026-01-01T10:00:00');
        INSERT INTO iteration_note VALUES (2, 'demo/x', 1, 2, 'second note',
            '2026-01-01T11:00:00');
        """
    )
    conn.commit()
    conn.close()
    html = dashboard.render_dashboard(db, "demo/x", refresh=False)
    assert "second note" in html
    assert "first note" in html
    assert html.index("second note") < html.index("first note")


def test_v8_fixed_verdict_color_present(dashboard):
    assert "fixed" in dashboard.VERDICT_ORDER
    assert dashboard.VERDICT_COLOR.get("fixed")

#!/usr/bin/env python3
# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

"""Live HTML dashboard for the fuzzing taskflow.

Runs a stdlib HTTP server on localhost. Reads the fuzz_context SQLite database
in read-only mode (safe to run alongside an active fuzzing campaign), so the
``run_fuzzing.sh`` wrapper can spawn it in the background.

Usage:
    python scripts/fuzzing/dashboard.py            # default port 8765
    python scripts/fuzzing/dashboard.py --port 9000
    python scripts/fuzzing/dashboard.py --no-refresh   # disable auto-refresh

Open http://localhost:8765 in a browser. In a Codespace, port 8765 is
auto-forwarded.
"""

from __future__ import annotations

import argparse
import datetime
import html
import json as _json
import os
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

DEFAULT_DB = (
    Path.home()
    / ".local/share/seclab-taskflow-agent/seclab-taskflows/fuzz_context/fuzz_context.db"
)


def _connect(db_path: Path) -> sqlite3.Connection | None:
    """Open the database read-only. Returns None if it doesn't exist yet."""
    if not db_path.is_file():
        return None
    uri = f"file:{db_path}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=2)
    conn.row_factory = sqlite3.Row
    return conn


def _migrate_if_writable(db_path: Path) -> None:
    """Add columns added in later schema versions to an existing DB.

    The dashboard normally opens the DB read-only, but it does this one-shot
    write at startup so that fuzz_context.db files created by older versions of
    the taskflow are upgraded transparently.
    """
    if not db_path.is_file() or not os.access(db_path, os.W_OK):
        return
    expected = {
        "crash": [
            ("verdict", "TEXT"),
            ("bug_class", "TEXT"),
            ("cwe", "TEXT"),
            ("severity", "TEXT"),
            ("vuln_report_path", "TEXT"),
        ],
        "coverage_report": [
            ("html_path", "TEXT"),
        ],
    }
    conn = sqlite3.connect(db_path, timeout=5)
    try:
        for table, cols in expected.items():
            existing = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
            for name, sqltype in cols:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {sqltype}")
        conn.commit()
    except sqlite3.OperationalError:
        # Tables not yet created (DB is brand new) — fuzz_context.py will create them.
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

VERDICT_ORDER = [
    "vulnerability", "library_hardening", "oom", "timeout",
    "assertion_failure", "non_reproducible", "harness_bug",
    "fixed", "duplicate", "needs_investigation",
]
VERDICT_COLOR = {
    "vulnerability": "#d11",
    "library_hardening": "#e67e22",
    "oom": "#e67e22",
    "timeout": "#e67e22",
    "assertion_failure": "#7c3aed",
    "non_reproducible": "#777",
    "harness_bug": "#999",
    "fixed": "#0a7",
    "duplicate": "#999",
    "needs_investigation": "#3b82f6",
}


def _h(s) -> str:
    return html.escape("" if s is None else str(s))


def _sparkline_svg(values: list[float], width: int = 120, height: int = 24) -> str:
    """Render a tiny line sparkline."""
    if not values:
        return ""
    if len(values) == 1:
        values = [values[0], values[0]]
    vmin = min(values)
    vmax = max([*values, vmin + 0.001])
    pts = []
    for i, v in enumerate(values):
        x = i * (width - 4) / (len(values) - 1) + 2
        y = height - 2 - (v - vmin) / (vmax - vmin) * (height - 4)
        pts.append(f"{x:.1f},{y:.1f}")
    return (
        f'<svg width="{width}" height="{height}" style="vertical-align:middle;">'
        f'<polyline fill="none" stroke="#3b82f6" stroke-width="1.5" '
        f'points="{" ".join(pts)}"/></svg>'
    )


def _render_repos(conn: sqlite3.Connection) -> tuple[str, list[str]]:
    try:
        rows = conn.execute(
            "SELECT t.repo, "
            "       (SELECT COUNT(*) FROM fuzz_target tt WHERE tt.repo = t.repo) AS targets, "
            "       (SELECT COUNT(*) FROM harness h WHERE h.repo = t.repo) AS harnesses, "
            "       (SELECT COUNT(*) FROM fuzz_run fr JOIN harness h ON fr.harness_id = h.id WHERE h.repo = t.repo) AS runs, "
            "       (SELECT COUNT(*) FROM crash c JOIN fuzz_run fr ON c.run_id = fr.id JOIN harness h ON fr.harness_id = h.id WHERE h.repo = t.repo) AS crashes, "
            "       (SELECT COUNT(*) FROM fuzz_run fr JOIN harness h ON fr.harness_id = h.id WHERE h.repo = t.repo AND fr.status = 'running') AS running "
            "FROM fuzz_target t GROUP BY t.repo ORDER BY t.repo"
        ).fetchall()
    except sqlite3.OperationalError:
        return '<p class="muted">Database not fully initialised yet.</p>', []
    if not rows:
        return '<p class="muted">No fuzzing data yet. Run <code>./scripts/fuzzing/run_fuzzing.sh &lt;owner/repo&gt;</code>.</p>', []

    body = ['<table><thead><tr><th>Repo</th><th>Status</th><th>Targets</th><th>Harnesses</th><th>Runs</th><th>Crashes</th></tr></thead><tbody>']
    repos = []
    for r in rows:
        repos.append(r["repo"])
        if r["running"]:
            status = '<span class="dot dot-live"></span> live'
        else:
            status = '<span class="dot dot-idle"></span> idle'
        body.append(
            f'<tr><td><strong>{_h(r["repo"])}</strong></td>'
            f'<td>{status}</td>'
            f'<td>{r["targets"]}</td><td>{r["harnesses"]}</td>'
            f'<td>{r["runs"]}</td><td>{r["crashes"]}</td></tr>'
        )
    body.append("</tbody></table>")
    return "\n".join(body), repos


def _render_summary_strip(conn: sqlite3.Connection, repo: str) -> str:
    """Verdict-count chips + total exec / paths / crashes for the selected repo."""
    try:
        agg = conn.execute(
            "SELECT "
            "  (SELECT COUNT(*) FROM crash c JOIN fuzz_run fr ON c.run_id=fr.id JOIN harness h ON fr.harness_id=h.id WHERE h.repo=?) AS crashes, "
            "  (SELECT COUNT(*) FROM fuzz_run fr JOIN harness h ON fr.harness_id=h.id WHERE h.repo=?) AS runs, "
            "  (SELECT COUNT(*) FROM fuzz_run fr JOIN harness h ON fr.harness_id=h.id WHERE h.repo=? AND fr.status='running') AS running, "
            "  (SELECT COALESCE(SUM(paths_total),0) FROM fuzz_run fr JOIN harness h ON fr.harness_id=h.id WHERE h.repo=?) AS paths_sum, "
            "  (SELECT COALESCE(SUM(time_budget_seconds * exec_per_sec),0) FROM fuzz_run fr JOIN harness h ON fr.harness_id=h.id WHERE h.repo=?) AS exec_sum "
            "",
            (repo, repo, repo, repo, repo),
        ).fetchone()
        verdicts = conn.execute(
            "SELECT COALESCE(c.verdict, '(unclassified)') AS v, COUNT(*) AS n "
            "FROM crash c JOIN fuzz_run fr ON c.run_id=fr.id JOIN harness h ON fr.harness_id=h.id "
            "WHERE h.repo=? GROUP BY c.verdict",
            (repo,),
        ).fetchall()
    except sqlite3.OperationalError as e:
        return f'<p class="muted">summary unavailable: {_h(e)}</p>'
    chips = []
    chips.append(f'<span class="chip"><strong>{agg["runs"]}</strong> runs</span>')
    if agg["running"]:
        chips.append(f'<span class="chip chip-live"><strong>{agg["running"]}</strong> running</span>')
    chips.append(f'<span class="chip"><strong>{agg["paths_sum"]}</strong> paths</span>')
    chips.append(f'<span class="chip"><strong>{int(agg["exec_sum"]):,}</strong> total execs</span>')
    chips.append(f'<span class="chip"><strong>{agg["crashes"]}</strong> crashes</span>')
    for v in verdicts:
        if not v["v"] or v["v"] == "(unclassified)":
            label = "(unclassified)"
            color = "#888"
        else:
            label = v["v"]
            color = VERDICT_COLOR.get(v["v"], "#666")
        chips.append(
            f'<span class="chip" style="border-color:{color};color:{color}">'
            f'<strong>{v["n"]}</strong> {_h(label)}</span>'
        )
    return '<div class="strip">' + " ".join(chips) + "</div>"


def _safe(fn, *args, **kwargs) -> str:
    try:
        return fn(*args, **kwargs)
    except sqlite3.OperationalError as e:
        return f'<p class="muted">section unavailable: {_h(e)}</p>'


def _render_harnesses(conn: sqlite3.Connection, repo: str) -> str:
    harnesses = conn.execute(
        "SELECT h.id, h.target_id, h.harness_path, h.build_status, h.sanitizers, h.version, "
        "       t.file AS target_file, t.function AS target_function "
        "FROM harness h LEFT JOIN fuzz_target t ON t.id = h.target_id "
        "WHERE h.repo = ? ORDER BY h.id", (repo,),
    ).fetchall()
    if not harnesses:
        return '<p class="muted">No harnesses for this repo yet.</p>'
    out = ['<table><thead><tr><th>ID</th><th>Target</th><th>Build</th><th>Sanitisers</th><th>Version</th></tr></thead><tbody>']
    for h in harnesses:
        target = f'{_h(h["target_file"])}:{_h(h["target_function"])}' if h["target_file"] else "-"
        status = h["build_status"] or "?"
        color = "#0a0" if status == "ok" else "#c00" if status else "#888"
        out.append(
            f'<tr><td>{h["id"]}</td><td>{target}</td>'
            f'<td><span style="color:{color}">●</span> {_h(status)}</td>'
            f'<td>{_h(h["sanitizers"] or "")}</td>'
            f'<td>{h["version"]}</td></tr>'
        )
    out.append("</tbody></table>")
    return "\n".join(out)


def _render_coverage(conn: sqlite3.Connection, repo: str) -> str:
    harnesses = conn.execute(
        "SELECT h.id, t.file AS f, t.function AS fn, "
        "  (SELECT COUNT(*) FROM fuzz_run fr WHERE fr.harness_id = h.id AND fr.status='running') AS running "
        "FROM harness h "
        "LEFT JOIN fuzz_target t ON t.id = h.target_id WHERE h.repo = ?", (repo,),
    ).fetchall()
    if not harnesses:
        return ""
    out = ['<table><thead><tr><th></th><th>Harness</th><th>Iters</th><th>Trend</th><th>Latest line %</th><th>Δ</th><th>Latest fn %</th><th>Latest branch %</th><th>Exec/sec</th><th>HTML cov</th></tr></thead><tbody>']
    for h in harnesses:
        runs = conn.execute(
            "SELECT fr.iteration_number, cr.line_pct, cr.fn_pct, cr.branch_pct, fr.exec_per_sec, cr.html_path "
            "FROM fuzz_run fr LEFT JOIN coverage_report cr ON cr.run_id = fr.id "
            "WHERE fr.harness_id = ? AND cr.id IS NOT NULL "
            "ORDER BY fr.iteration_number", (h["id"],),
        ).fetchall()
        target = f'{_h(h["f"])}:{_h(h["fn"])}' if h["f"] else f'h{h["id"]}'
        live_dot = '<span class="dot dot-live"></span>' if h["running"] else '<span class="dot dot-idle"></span>'
        if not runs:
            out.append(f'<tr><td>{live_dot}</td><td>{target}</td><td colspan=8 class="muted">no coverage yet</td></tr>')
            continue
        spark = _sparkline_svg([r["line_pct"] or 0 for r in runs])
        last = runs[-1]
        delta = (last["line_pct"] or 0) - (runs[-2]["line_pct"] or 0) if len(runs) > 1 else 0.0
        if delta > 0.5:
            delta_str = f'<span style="color:#0a7">+{delta:.1f}</span>'
        elif delta < -0.5:
            delta_str = f'<span style="color:#a44">{delta:.1f}</span>'
        else:
            delta_str = f'<span class="muted">{delta:+.1f}</span>'
        html_link = (
            f'<a href="/file?path={_h(last["html_path"])}">view</a>'
            if last["html_path"] else '<span class="muted">—</span>'
        )
        out.append(
            f'<tr><td>{live_dot}</td><td>{target}</td><td>{len(runs)}</td><td>{spark}</td>'
            f'<td>{last["line_pct"]:.1f}%</td><td>{delta_str}</td>'
            f'<td>{last["fn_pct"]:.1f}%</td>'
            f'<td>{last["branch_pct"]:.1f}%</td>'
            f'<td>{(last["exec_per_sec"] or 0):.0f}</td>'
            f'<td>{html_link}</td></tr>'
        )
    out.append("</tbody></table>")
    return "\n".join(out)


def _render_runs(conn: sqlite3.Connection, repo: str) -> str:
    runs = conn.execute(
        "SELECT fr.id, fr.iteration_number, fr.time_budget_seconds, fr.exec_per_sec, "
        "       fr.paths_total, fr.crashes_count, fr.hangs_count, fr.status, "
        "       fr.started_at, h.id AS hid, t.function AS fn "
        "FROM fuzz_run fr JOIN harness h ON h.id = fr.harness_id "
        "LEFT JOIN fuzz_target t ON t.id = h.target_id "
        "WHERE h.repo = ? ORDER BY fr.id DESC LIMIT 20", (repo,),
    ).fetchall()
    if not runs:
        return '<p class="muted">No runs yet.</p>'
    out = ['<table><thead><tr><th>Run</th><th>Harness</th><th>Iter</th><th>Budget (s)</th><th>Exec/sec</th><th>Paths</th><th>Crashes</th><th>Hangs</th><th>Status</th><th>Started</th></tr></thead><tbody>']
    for r in runs:
        target = _h(r["fn"]) if r["fn"] else f'h{r["hid"]}'
        c_color = "#d11" if r["crashes_count"] else "#000"
        out.append(
            f'<tr><td>{r["id"]}</td><td>{target} (h{r["hid"]})</td>'
            f'<td>{r["iteration_number"]}</td><td>{r["time_budget_seconds"]}</td>'
            f'<td>{(r["exec_per_sec"] or 0):.0f}</td>'
            f'<td>{r["paths_total"]}</td>'
            f'<td style="color:{c_color}"><strong>{r["crashes_count"]}</strong></td>'
            f'<td>{r["hangs_count"]}</td>'
            f'<td>{_h(r["status"])}</td>'
            f'<td class="muted">{_h(r["started_at"] or "")}</td></tr>'
        )
    out.append("</tbody></table>")
    return "\n".join(out)


def _render_crashes(conn: sqlite3.Connection, repo: str) -> str:
    crashes = conn.execute(
        "SELECT c.id, c.classification, c.verdict, c.bug_class, c.cwe, c.severity, "
        "       c.stack_top_hash, c.minimized_path, c.vuln_report_path, "
        "       h.id AS hid, t.function AS fn "
        "FROM crash c JOIN fuzz_run fr ON fr.id = c.run_id "
        "JOIN harness h ON h.id = fr.harness_id "
        "LEFT JOIN fuzz_target t ON t.id = h.target_id "
        "WHERE h.repo = ?", (repo,),
    ).fetchall()
    if not crashes:
        return '<p class="muted">No crashes (yet 😊).</p>'

    def sort_key(c):
        v = c["verdict"] or "zzz"
        idx = VERDICT_ORDER.index(v) if v in VERDICT_ORDER else len(VERDICT_ORDER)
        return (idx, c["id"])

    crashes_sorted = sorted(crashes, key=sort_key)
    out = ['<table><thead><tr><th>ID</th><th>Verdict</th><th>Bug class</th><th>CWE</th><th>Sev</th><th>Target</th><th>Classification</th><th>Min input</th><th>Report</th></tr></thead><tbody>']
    for c in crashes_sorted:
        verdict = c["verdict"] or "—"
        color = VERDICT_COLOR.get(verdict, "#000")
        target = _h(c["fn"]) if c["fn"] else f'h{c["hid"]}'
        report_link = ""
        if c["vuln_report_path"]:
            report_link = f'<a href="/file?path={_h(c["vuln_report_path"])}">report</a>'
        min_link = ""
        if c["minimized_path"]:
            min_link = f'<a href="/file?path={_h(c["minimized_path"])}">{_h(Path(c["minimized_path"]).name)}</a>'
        out.append(
            f'<tr><td>{c["id"]}</td>'
            f'<td><span style="color:{color};font-weight:600">{_h(verdict)}</span></td>'
            f'<td>{_h(c["bug_class"] or "")}</td>'
            f'<td>{_h(c["cwe"] or "")}</td>'
            f'<td>{_h(c["severity"] or "")}</td>'
            f'<td>{target}</td>'
            f'<td>{_h((c["classification"] or "")[:80])}</td>'
            f'<td>{min_link}</td><td>{report_link}</td></tr>'
        )
    out.append("</tbody></table>")
    return "\n".join(out)


def _render_gaps(conn: sqlite3.Connection, repo: str) -> str:
    rows = conn.execute(
        "SELECT g.file, g.function, g.line, g.kind, h.id AS hid, t.function AS hfn "
        "FROM coverage_gap g JOIN coverage_report cr ON cr.id = g.report_id "
        "JOIN fuzz_run fr ON fr.id = cr.run_id "
        "JOIN harness h ON h.id = fr.harness_id "
        "LEFT JOIN fuzz_target t ON t.id = h.target_id "
        "WHERE h.repo = ? AND g.kind = 'fn' "
        "ORDER BY h.id, g.id LIMIT 40", (repo,),
    ).fetchall()
    if not rows:
        return ""
    out = ['<details><summary>Top uncovered functions (40)</summary><table><thead><tr><th>Harness</th><th>File</th><th>Function</th><th>Line</th></tr></thead><tbody>']
    for r in rows:
        target = _h(r["hfn"]) if r["hfn"] else f'h{r["hid"]}'
        out.append(
            f'<tr><td>{target}</td><td>{_h(r["file"])}</td>'
            f'<td>{_h(r["function"] or "")}</td><td>{r["line"]}</td></tr>'
        )
    out.append("</tbody></table></details>")
    return "\n".join(out)


def _render_call_graph(conn: sqlite3.Connection, repo: str) -> str:
    """E3: render the latest CallGraph snapshot + untouched-API summary."""
    try:
        rows = conn.execute(
            "SELECT id, dot_path, svg_path, functions_total, functions_in_graph, "
            "       functions_reached, functions_unreached, untouched_surface_json, generated_at "
            "FROM call_graph WHERE repo = ? ORDER BY generated_at DESC LIMIT 1",
            (repo,),
        ).fetchone()
    except sqlite3.OperationalError:
        return ""
    if not rows:
        return '<p class="muted">No call graph computed yet (run the analyze_call_graph stage).</p>'
    dot, svg = rows["dot_path"], rows["svg_path"]
    total = rows["functions_total"] or 0
    reached = rows["functions_reached"] or 0
    unreached = rows["functions_unreached"] or 0
    pct = (100.0 * reached / max(reached + unreached, 1))
    parts = [
        f'<p>Functions in graph: <strong>{rows["functions_in_graph"]}</strong> · '
        f'reached: <strong style="color:#0a7">{reached}</strong> · '
        f'unreached: <strong style="color:#a44">{unreached}</strong> '
        f'({pct:.1f}% of plotted functions reached) · '
        f'total in repo: <strong>{total}</strong>'
    ]
    if svg:
        parts.append(
            f'<p><a href="/file?path={_h(svg)}">📊 view interactive call graph (SVG)</a> · '
            f'<a href="/file?path={_h(dot)}">.dot source</a></p>'
        )
    elif dot:
        parts.append(f'<p><a href="/file?path={_h(dot)}">.dot source</a> (SVG not rendered)</p>')

    if rows["untouched_surface_json"]:
        try:
            untouched = _json.loads(rows["untouched_surface_json"])
            if isinstance(untouched, list) and untouched:
                head = untouched[:30]
                items = "".join(f"<li><code>{_h(name)}</code></li>" for name in head)
                parts.append(
                    f'<details open><summary>'
                    f'<strong>Untouched public API ({len(untouched)} total, showing top {len(head)})</strong>'
                    f' — these are public functions defined in the repo that no fuzzing run reached'
                    f'</summary><ul>{items}</ul></details>'
                )
        except (ValueError, TypeError):
            pass
    return "\n".join(parts)


def _render_crash_heatmap(conn: sqlite3.Connection, repo: str) -> str:
    """v8 C: per-(harness, iteration) crash count grid, colored by intensity."""
    try:
        rows = conn.execute(
            """
            SELECT h.id AS hid, h.harness_path, fr.iteration_number AS it,
                   COUNT(c.id) AS n
            FROM harness h
            JOIN fuzz_target t ON t.id = h.target_id
            JOIN fuzz_run fr ON fr.harness_id = h.id
            LEFT JOIN crash c ON c.run_id = fr.id
            WHERE t.repo = ?
            GROUP BY h.id, fr.iteration_number
            ORDER BY h.id, fr.iteration_number
            """,
            (repo,),
        ).fetchall()
    except sqlite3.OperationalError:
        return ""
    if not rows:
        return '<p class="muted">No fuzz runs yet.</p>'

    grid: dict[tuple[int, int], int] = {}
    harness_names: dict[int, str] = {}
    iters: set[int] = set()
    max_n = 0
    for r in rows:
        hid = r["hid"]
        it = r["it"] if r["it"] is not None else 0
        n = r["n"] or 0
        grid[(hid, it)] = n
        harness_names[hid] = Path(r["harness_path"]).name if r["harness_path"] else f"harness_{hid}"
        iters.add(it)
        max_n = max(max_n, n)

    iter_list = sorted(iters)
    if not iter_list:
        return '<p class="muted">No iterations recorded.</p>'

    head_cells = "".join(f'<th>iter {i}</th>' for i in iter_list)
    body_rows = []
    for hid in sorted(harness_names):
        cells = [f'<th style="text-align:left">{_h(harness_names[hid])}</th>']
        for it in iter_list:
            n = grid.get((hid, it))
            if n is None:
                cells.append('<td style="background:#f5f5f5;color:#bbb">·</td>')
            elif n == 0:
                cells.append('<td style="background:#eaf6ea;color:#666">0</td>')
            else:
                opacity = 0.25 + 0.75 * (n / max(max_n, 1))
                cells.append(
                    f'<td style="background:rgba(221,17,17,{opacity:.2f});color:white;'
                    f'text-align:center;font-weight:600">{n}</td>'
                )
        body_rows.append(f'<tr>{"".join(cells)}</tr>')

    return (
        '<table><thead><tr><th style="text-align:left">harness</th>'
        f'{head_cells}</tr></thead><tbody>{"".join(body_rows)}</tbody></table>'
        '<p class="muted" style="margin-top:0.4rem;font-size:0.85rem">'
        'Cells show distinct crashes per iteration. Darker = more. '
        '<code>·</code> = no run for that (harness, iteration) pair.</p>'
    )


def _render_iteration_timeline(conn: sqlite3.Connection, repo: str) -> str:
    """v8 C: chronological feed of agent-written iteration notes."""
    try:
        rows = conn.execute(
            """
            SELECT iter.iteration_number, iter.harness_id, iter.note, iter.created_at,
                   h.harness_path
            FROM iteration_note iter
            LEFT JOIN harness h ON h.id = iter.harness_id
            WHERE iter.repo = ?
            ORDER BY iter.created_at DESC
            LIMIT 40
            """,
            (repo,),
        ).fetchall()
    except sqlite3.OperationalError:
        return ""
    if not rows:
        return '<p class="muted">No iteration notes recorded yet.</p>'

    items = []
    for r in rows:
        ts = (r["created_at"] or "")[:19].replace("T", " ")
        hname = Path(r["harness_path"]).name if r["harness_path"] else f"harness_{r['harness_id']}"
        items.append(
            f'<li><span class="muted">{_h(ts)}</span> · '
            f'<strong>iter {r["iteration_number"]}</strong> · '
            f'<code>{_h(hname)}</code> — {_h(r["note"] or "")}</li>'
        )
    return f'<ul style="line-height:1.6;padding-left:1.2rem">{"".join(items)}</ul>'


CSS = """
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 1.5rem; color: #1a1a1a; background: #fafafa; }
h1 { margin-top: 0; }
h2 { border-bottom: 1px solid #ddd; padding-bottom: 0.3rem; margin-top: 2rem; }
table { border-collapse: collapse; width: 100%; background: white; }
th, td { padding: 0.4rem 0.6rem; text-align: left; border-bottom: 1px solid #eee; font-size: 0.92rem; }
th { background: #f0f0f0; font-weight: 600; }
tr:hover { background: #fafafa; }
.muted { color: #888; }
code { background: #f0f0f0; padding: 0.1rem 0.3rem; border-radius: 3px; }
header { display: flex; align-items: baseline; gap: 1rem; flex-wrap: wrap; }
.repo-pill { padding: 0.2rem 0.6rem; background: #e8f0ff; border-radius: 12px; font-size: 0.85rem; }
.timestamp { color: #888; font-size: 0.85rem; margin-left: auto; }
.strip { display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.6rem 0 1.2rem; }
.chip { display: inline-block; padding: 0.25rem 0.7rem; border: 1px solid #cdd; border-radius: 999px; background: white; font-size: 0.85rem; }
.chip-live { border-color: #d11; color: #d11; animation: pulse 2s ease-in-out infinite; }
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.55; } }
.dot { display: inline-block; width: 0.6rem; height: 0.6rem; border-radius: 50%; margin-right: 0.3rem; vertical-align: middle; }
.dot-live { background: #d11; box-shadow: 0 0 6px rgba(221,17,17,0.6); animation: pulse 1.5s ease-in-out infinite; }
.dot-idle { background: #bbb; }
"""


def render_dashboard(db_path: Path, repo: str | None, refresh: bool) -> str:
    conn = _connect(db_path)
    refresh_meta = '<meta http-equiv="refresh" content="5">' if refresh else ""
    head = (
        f"<!doctype html><html><head><meta charset='utf-8'>{refresh_meta}"
        f"<title>Fuzzing dashboard</title><style>{CSS}</style></head><body>"
    )
    if conn is None:
        return (
            head
            + f'<h1>Fuzzing dashboard</h1>'
            + f'<p class="muted">No database yet at <code>{_h(db_path)}</code>.</p></body></html>'
        )

    repos_html, repos = _render_repos(conn)
    if not repos:
        return head + '<h1>Fuzzing dashboard</h1>' + repos_html + "</body></html>"

    selected = repo if repo in repos else repos[0]
    repo_links = " ".join(
        f'<a class="repo-pill" href="/?repo={_h(r)}">{_h(r)}</a>'
        if r != selected
        else f'<span class="repo-pill" style="background:#3b82f6;color:white">{_h(r)}</span>'
        for r in repos
    )
    now = datetime.datetime.now(tz=datetime.timezone.utc).strftime("%H:%M:%S UTC")
    sections = [
        head,
        f'<header><h1>Fuzzing dashboard</h1>{repo_links}<span class="timestamp">refreshed {now}</span></header>',
        _safe(_render_summary_strip, conn, selected),
        "<h2>Repositories</h2>",
        repos_html,
        f"<h2>Coverage trend — {_h(selected)}</h2>",
        _safe(_render_coverage, conn, selected),
        f"<h2>Call graph & untouched API surface — {_h(selected)}</h2>",
        _safe(_render_call_graph, conn, selected),
        f"<h2>Harnesses — {_h(selected)}</h2>",
        _safe(_render_harnesses, conn, selected),
        f"<h2>Recent fuzz runs — {_h(selected)}</h2>",
        _safe(_render_runs, conn, selected),
        f"<h2>Crashes — {_h(selected)}</h2>",
        _safe(_render_crashes, conn, selected),
        f"<h2>Crash heatmap — {_h(selected)}</h2>",
        _safe(_render_crash_heatmap, conn, selected),
        f"<h2>Iteration timeline — {_h(selected)}</h2>",
        _safe(_render_iteration_timeline, conn, selected),
        f"<h2>Coverage gaps — {_h(selected)}</h2>",
        _safe(_render_gaps, conn, selected),
        '<p class="muted" style="margin-top:2rem">JSON API: <a href="/api/json">/api/json</a> · '
        '<a href="/api/json?repo=' + _h(selected) + '">/api/json?repo=' + _h(selected) + '</a></p>',
        "</body></html>",
    ]
    conn.close()
    return "\n".join(sections)


def render_json(db_path: Path, repo: str | None) -> str:
    """Return a JSON snapshot of the database for programmatic consumers.

    With no ``repo``: returns aggregate counts plus a list of repos. With a
    ``repo``: returns per-harness coverage trend + crashes for that repo.
    """
    conn = _connect(db_path)
    if conn is None:
        return _json.dumps({"error": "database not found"})
    try:
        if repo:
            harnesses = [dict(r) for r in conn.execute(
                "SELECT h.id, h.harness_path, h.build_status, h.sanitizers, h.version, "
                "       t.file AS target_file, t.function AS target_function "
                "FROM harness h LEFT JOIN fuzz_target t ON t.id=h.target_id WHERE h.repo=?",
                (repo,))]
            for h in harnesses:
                h["coverage"] = [dict(r) for r in conn.execute(
                    "SELECT fr.iteration_number AS iter, fr.time_budget_seconds AS budget, "
                    "       fr.exec_per_sec, fr.paths_total, fr.crashes_count, fr.status, "
                    "       cr.line_pct, cr.fn_pct, cr.branch_pct "
                    "FROM fuzz_run fr LEFT JOIN coverage_report cr ON cr.run_id=fr.id "
                    "WHERE fr.harness_id=? ORDER BY fr.iteration_number", (h["id"],))]
            crashes = [dict(r) for r in conn.execute(
                "SELECT c.id, c.classification, c.verdict, c.bug_class, c.cwe, c.severity, "
                "       c.stack_top_hash, c.minimized_path, c.vuln_report_path, h.id AS harness_id "
                "FROM crash c JOIN fuzz_run fr ON fr.id=c.run_id "
                "JOIN harness h ON h.id=fr.harness_id WHERE h.repo=?", (repo,))]
            return _json.dumps({"repo": repo, "harnesses": harnesses, "crashes": crashes}, indent=2)
        repos = [r[0] for r in conn.execute(
            "SELECT DISTINCT repo FROM fuzz_target ORDER BY repo")]
        return _json.dumps({"repos": repos}, indent=2)
    except sqlite3.OperationalError as e:
        return _json.dumps({"error": str(e)})
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class _Handler(BaseHTTPRequestHandler):
    db_path: Path = DEFAULT_DB
    refresh: bool = True

    def log_message(self, format, *args):  # noqa: ARG002 (signature dictated by BaseHTTPRequestHandler)
        return

    def do_GET(self):
        u = urlparse(self.path)
        qs = parse_qs(u.query)
        if u.path == "/file":
            self._send_file(qs.get("path", [""])[0])
            return
        if u.path == "/api/json":
            repo = qs.get("repo", [None])[0]
            body = render_json(self.db_path, repo).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path not in ("/", "/index.html"):
            self.send_error(404)
            return
        repo = qs.get("repo", [None])[0]
        body = render_dashboard(self.db_path, repo, self.refresh).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, path: str):
        # Serve only files under the seclab-taskflow-agent data dir, to avoid
        # accidental disclosure of arbitrary host files via the dashboard.
        allowed_root = (Path.home() / ".local/share/seclab-taskflow-agent").resolve()
        try:
            real = Path(path).resolve()
            real.relative_to(allowed_root)
        except (OSError, ValueError):
            self.send_error(403, "path outside allowed root")
            return
        if not real.is_file():
            self.send_error(404)
            return
        data = real.read_bytes()
        # Guess content type. Coverage HTML reports include relative <link>s to
        # CSS / JS / per-file pages — we serve all of them with the right type
        # so the page renders properly.
        suffix = real.suffix.lower()
        ctype_map = {
            ".html": "text/html; charset=utf-8",
            ".htm": "text/html; charset=utf-8",
            ".md": "text/markdown; charset=utf-8",
            ".css": "text/css; charset=utf-8",
            ".js": "application/javascript; charset=utf-8",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".jpeg": "image/jpeg",
            ".gif": "image/gif",
            ".json": "application/json; charset=utf-8",
            ".txt": "text/plain; charset=utf-8",
        }
        ctype = ctype_map.get(suffix, "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=int(os.environ.get("FUZZ_DASHBOARD_PORT", "8765")))
    parser.add_argument("--db", type=Path, default=DEFAULT_DB)
    parser.add_argument("--no-refresh", action="store_true", help="Disable HTML auto-refresh")
    args = parser.parse_args()

    _Handler.db_path = args.db
    _Handler.refresh = not args.no_refresh

    # One-shot migration so DBs from older taskflow versions render correctly.
    _migrate_if_writable(args.db)

    server = ThreadingHTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"[dashboard] serving http://127.0.0.1:{args.port}  (db={args.db})", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())

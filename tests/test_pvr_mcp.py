# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

# Unit tests for the PVR MCP server extensions and reporter reputation backend.
#
# Run with: pytest tests/test_pvr_mcp.py -v

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers: patch mcp_data_dir so imports don't fail in CI (no platformdirs dir)
# ---------------------------------------------------------------------------

def _patch_report_dir(tmp_path):
    """Return a context manager that patches REPORT_DIR in pvr_ghsa."""
    import seclab_taskflows.mcp_servers.pvr_ghsa as pvr_mod
    return patch.object(pvr_mod, "REPORT_DIR", tmp_path)


# ---------------------------------------------------------------------------
# TestPvrGhsaTools
# ---------------------------------------------------------------------------

class TestPvrGhsaTools(unittest.TestCase):
    """Tests for the new write-back and similarity tools in pvr_ghsa.py."""

    def setUp(self):
        import seclab_taskflows.mcp_servers.pvr_ghsa as pvr_mod
        self.pvr = pvr_mod
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.tmp = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    # --- reject_pvr_advisory ---

    def test_reject_pvr_advisory_calls_correct_api(self):
        """reject_pvr_advisory should PATCH state=closed then post a comment."""
        calls = []

        def fake_gh_api(path, method="GET", body=None):
            calls.append({"path": path, "method": method, "body": body})
            if method == "PATCH":
                return {"ghsa_id": "GHSA-1234-5678-abcd", "state": "closed"}, None
            return {}, None

        with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
            with patch.object(self.pvr, "_post_advisory_comment", return_value="Comment posted: https://github.com/test"):
                result = self.pvr.reject_pvr_advisory.fn(
                    owner="owner",
                    repo="repo",
                    ghsa_id="GHSA-1234-5678-abcd",
                    comment="Rejecting: not a valid report.",
                )

        # First call must be the PATCH to set state=closed
        self.assertEqual(calls[0]["method"], "PATCH")
        self.assertIn("GHSA-1234-5678-abcd", calls[0]["path"])
        self.assertEqual(calls[0]["body"], {"state": "closed"})
        self.assertIn("closed", result)

    # --- add_pvr_advisory_comment ---

    def test_add_pvr_advisory_comment_returns_url_on_success(self):
        """add_pvr_advisory_comment returns comment URL on API success."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({"html_url": "https://github.com/comment/1"})
        with patch("subprocess.run", return_value=mock_result):
            result = self.pvr.add_pvr_advisory_comment.fn(
                owner="owner",
                repo="repo",
                ghsa_id="GHSA-1234-5678-abcd",
                body="Thank you for the report.",
            )
        self.assertIn("https://github.com/comment/1", result)

    def test_add_pvr_advisory_comment_fallback_on_api_failure(self):
        """add_pvr_advisory_comment falls back to description update when comments API unavailable."""
        # First subprocess call (comments POST) fails
        mock_fail = MagicMock()
        mock_fail.returncode = 1
        mock_fail.stderr = "Not Found"
        mock_fail.stdout = ""

        def fake_gh_api(path, method="GET", body=None):
            if method == "GET":
                return {"description": "Original description.", "ghsa_id": "GHSA-x"}, None
            if method == "PATCH":
                return {"description": "updated"}, None
            return {}, None

        with patch("subprocess.run", return_value=mock_fail):
            with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
                result = self.pvr.add_pvr_advisory_comment.fn(
                    owner="owner",
                    repo="repo",
                    ghsa_id="GHSA-1234-5678-abcd",
                    body="Maintainer note.",
                )
        self.assertIn("description", result.lower())

    # --- find_similar_triage_reports ---

    def test_find_similar_reports_matches_vuln_type(self):
        """find_similar_triage_reports returns matching reports by vuln_type."""
        report_dir = self.tmp
        # Write a fixture report
        (report_dir / "GHSA-aaaa-bbbb-cccc_triage.md").write_text(
            "## PVR Triage Analysis: GHSA-aaaa-bbbb-cccc\n"
            "**Vulnerability Type:** path traversal\n"
            "**[UNCONFIRMED]**\n"
            "Rate overall quality: Low\n",
            encoding="utf-8",
        )

        with _patch_report_dir(report_dir):
            result_json = self.pvr.find_similar_triage_reports.fn(
                vuln_type="path traversal",
                affected_component="upload handler",
            )

        results = json.loads(result_json)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ghsa_id"], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(results[0]["verdict"], "UNCONFIRMED")

    def test_find_similar_reports_no_matches(self):
        """find_similar_triage_reports returns empty list when nothing matches."""
        report_dir = self.tmp
        (report_dir / "GHSA-aaaa-bbbb-dddd_triage.md").write_text(
            "## PVR Triage Analysis: GHSA-aaaa-bbbb-dddd\n"
            "**Vulnerability Type:** SQL injection\n"
            "**[CONFIRMED]**\n",
            encoding="utf-8",
        )

        with _patch_report_dir(report_dir):
            result_json = self.pvr.find_similar_triage_reports.fn(
                vuln_type="XSS",
                affected_component="login form",
            )

        results = json.loads(result_json)
        self.assertEqual(results, [])

    def test_find_similar_reports_empty_dir(self):
        """find_similar_triage_reports returns empty list for non-existent REPORT_DIR."""
        empty_dir = self.tmp / "nonexistent"
        with _patch_report_dir(empty_dir):
            result_json = self.pvr.find_similar_triage_reports.fn(
                vuln_type="IDOR",
                affected_component="profile",
            )
        results = json.loads(result_json)
        self.assertEqual(results, [])

    # --- save_triage_report path sanitization ---

    def test_save_triage_report_path_sanitization(self):
        """save_triage_report strips path traversal characters from the GHSA ID."""
        with _patch_report_dir(self.tmp):
            out_path = self.pvr.save_triage_report.fn(
                ghsa_id="../../../etc/passwd",
                report="malicious content",
            )
        # The file must be inside REPORT_DIR, not outside.
        # Resolve both paths to handle macOS /var -> /private/var symlinks.
        self.assertTrue(out_path.startswith(str(self.tmp.resolve())))
        # The filename should not contain path separators
        saved = Path(out_path)
        self.assertFalse(".." in saved.name)
        self.assertFalse("/" in saved.name)

    def test_save_triage_report_empty_after_sanitization(self):
        """save_triage_report returns an error when ghsa_id is all special chars."""
        with _patch_report_dir(self.tmp):
            result = self.pvr.save_triage_report.fn(
                ghsa_id="!@#$%^&*()",
                report="some content",
            )
        self.assertIn("Error", result)

    # --- read_triage_report ---

    def test_read_triage_report_returns_content(self):
        """read_triage_report reads back a previously saved report."""
        content = "## PVR Triage Analysis: GHSA-test\n\n**[CONFIRMED]**\n"
        (self.tmp / "GHSA-test_triage.md").write_text(content, encoding="utf-8")

        with _patch_report_dir(self.tmp):
            result = self.pvr.read_triage_report.fn(ghsa_id="GHSA-test")

        self.assertEqual(result, content)

    def test_read_triage_report_missing_file(self):
        """read_triage_report returns an error string for a missing report."""
        with _patch_report_dir(self.tmp):
            result = self.pvr.read_triage_report.fn(ghsa_id="GHSA-does-not-exist")

        self.assertIn("not found", result.lower())

    # --- list_pending_responses ---

    def test_list_pending_responses_empty(self):
        """list_pending_responses returns [] when no response drafts exist."""
        with _patch_report_dir(self.tmp):
            result_json = self.pvr.list_pending_responses.fn()
        results = json.loads(result_json)
        self.assertEqual(results, [])

    def test_list_pending_responses_returns_pending(self):
        """list_pending_responses includes an entry when a draft exists but no sent marker."""
        (self.tmp / "GHSA-1111-2222-3333_response_triage.md").write_text(
            "Response draft.", encoding="utf-8"
        )
        with _patch_report_dir(self.tmp):
            result_json = self.pvr.list_pending_responses.fn()
        results = json.loads(result_json)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ghsa_id"], "GHSA-1111-2222-3333")

    def test_list_pending_responses_excludes_sent(self):
        """list_pending_responses skips entries where a _response_sent.md marker exists."""
        (self.tmp / "GHSA-1111-2222-3333_response_triage.md").write_text(
            "Response draft.", encoding="utf-8"
        )
        (self.tmp / "GHSA-1111-2222-3333_response_sent.md").write_text(
            "Response sent: 2026-03-03T00:00:00+00:00\n", encoding="utf-8"
        )
        with _patch_report_dir(self.tmp):
            result_json = self.pvr.list_pending_responses.fn()
        results = json.loads(result_json)
        self.assertEqual(results, [])

    # --- mark_response_sent ---

    def test_mark_response_sent_creates_marker(self):
        """mark_response_sent creates a _response_sent.md marker and returns its path."""
        with _patch_report_dir(self.tmp):
            result = self.pvr.mark_response_sent.fn(ghsa_id="GHSA-1111-2222-3333")
        marker = self.tmp / "GHSA-1111-2222-3333_response_sent.md"
        self.assertTrue(marker.exists())
        self.assertTrue(result.startswith(str(self.tmp.resolve())))
        content = marker.read_text(encoding="utf-8")
        self.assertIn("Response sent:", content)

    def test_mark_response_sent_empty_ghsa_id(self):
        """mark_response_sent returns an error string when ghsa_id sanitizes to empty."""
        with _patch_report_dir(self.tmp):
            result = self.pvr.mark_response_sent.fn(ghsa_id="!@#$%")
        self.assertIn("Error", result)


# ---------------------------------------------------------------------------
# TestReporterReputationBackend
# ---------------------------------------------------------------------------

class TestReporterReputationBackend(unittest.TestCase):
    """Tests for the ReporterReputationBackend class using in-memory SQLite."""

    def setUp(self):
        from seclab_taskflows.mcp_servers.reporter_reputation import ReporterReputationBackend
        # Use explicit in-memory sentinel for tests
        self.backend = ReporterReputationBackend(db_dir="sqlite://")

    def test_record_and_retrieve(self):
        """record_triage_result inserts a record and get_reporter_history retrieves it."""
        self.backend.record_triage_result(
            login="alice",
            ghsa_id="GHSA-1111-2222-3333",
            repo="owner/repo",
            verdict="CONFIRMED",
            quality="High",
        )
        history = self.backend.get_reporter_history("alice")
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["login"], "alice")
        self.assertEqual(history[0]["ghsa_id"], "GHSA-1111-2222-3333")
        self.assertEqual(history[0]["verdict"], "CONFIRMED")
        self.assertEqual(history[0]["quality"], "High")

    def test_upsert_same_ghsa(self):
        """record_triage_result updates an existing record when called again for the same GHSA."""
        self.backend.record_triage_result(
            login="bob",
            ghsa_id="GHSA-aaaa-bbbb-cccc",
            repo="owner/repo",
            verdict="UNCONFIRMED",
            quality="Low",
        )
        # Re-triage the same advisory — should update, not duplicate
        self.backend.record_triage_result(
            login="bob",
            ghsa_id="GHSA-aaaa-bbbb-cccc",
            repo="owner/repo",
            verdict="CONFIRMED",
            quality="High",
        )
        history = self.backend.get_reporter_history("bob")
        # Should still be exactly 1 record
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["verdict"], "CONFIRMED")
        self.assertEqual(history[0]["quality"], "High")

    def test_get_reporter_score_empty(self):
        """get_reporter_score returns zero totals for an unknown login."""
        score = self.backend.get_reporter_score("nobody")
        self.assertEqual(score["total_reports"], 0)
        self.assertEqual(score["confirmed_pct"], 0.0)
        self.assertEqual(score["quality_breakdown"], {"High": 0, "Medium": 0, "Low": 0})
        self.assertEqual(score["recommendation"], "no history")

    def test_get_reporter_score_recommendation_skepticism(self):
        """5 Low-quality UNCONFIRMED reports → recommendation is 'treat with skepticism'."""
        for i in range(5):
            self.backend.record_triage_result(
                login="spammer",
                ghsa_id=f"GHSA-{i:04d}-0000-0000",
                repo="owner/repo",
                verdict="UNCONFIRMED",
                quality="Low",
            )
        score = self.backend.get_reporter_score("spammer")
        self.assertEqual(score["recommendation"], "treat with skepticism")
        self.assertEqual(score["quality_breakdown"]["Low"], 5)
        self.assertEqual(score["confirmed_pct"], 0.0)

    def test_get_reporter_score_recommendation_trust(self):
        """5 High-quality CONFIRMED reports → recommendation is 'high trust'."""
        for i in range(5):
            self.backend.record_triage_result(
                login="expert",
                ghsa_id=f"GHSA-{i:04d}-1111-1111",
                repo="owner/repo",
                verdict="CONFIRMED",
                quality="High",
            )
        score = self.backend.get_reporter_score("expert")
        self.assertEqual(score["recommendation"], "high trust")
        self.assertEqual(score["confirmed_pct"], 1.0)

    def test_get_reporter_history_empty(self):
        """get_reporter_history returns empty list for unknown login."""
        history = self.backend.get_reporter_history("ghost")
        self.assertEqual(history, [])

    def test_record_invalid_verdict_raises(self):
        """record_triage_result rejects unknown verdict strings."""
        with self.assertRaises(ValueError):
            self.backend.record_triage_result("alice", "GHSA-x", "r/r", "MAYBE", "High")

    def test_record_invalid_quality_raises(self):
        """record_triage_result rejects unknown quality strings."""
        with self.assertRaises(ValueError):
            self.backend.record_triage_result("alice", "GHSA-x", "r/r", "CONFIRMED", "Excellent")

    def test_multiple_reporters_isolated(self):
        """Records for different reporters are independent."""
        self.backend.record_triage_result("alice", "GHSA-a", "r/r", "CONFIRMED", "High")
        self.backend.record_triage_result("bob", "GHSA-b", "r/r", "UNCONFIRMED", "Low")

        alice_history = self.backend.get_reporter_history("alice")
        bob_history = self.backend.get_reporter_history("bob")

        self.assertEqual(len(alice_history), 1)
        self.assertEqual(len(bob_history), 1)
        self.assertEqual(alice_history[0]["ghsa_id"], "GHSA-a")
        self.assertEqual(bob_history[0]["ghsa_id"], "GHSA-b")


# ---------------------------------------------------------------------------
# TestYamlStructure
# ---------------------------------------------------------------------------

class TestYamlStructure(unittest.TestCase):
    """Tests that the new YAML files parse correctly via AvailableTools."""

    def setUp(self):
        from seclab_taskflow_agent.available_tools import AvailableTools
        self.tools = AvailableTools()

    def test_pvr_triage_yaml_parses(self):
        """pvr_triage.yaml loads without error and is a taskflow."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_triage")
        self.assertIsNotNone(result)
        header = result["seclab-taskflow-agent"]
        self.assertEqual(header["filetype"], "taskflow")

    def test_pvr_respond_yaml_parses(self):
        """pvr_respond.yaml loads without error and declares required globals."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_respond")
        self.assertIsNotNone(result)
        header = result["seclab-taskflow-agent"]
        self.assertEqual(header["filetype"], "taskflow")
        globals_keys = result.get("globals", {})
        self.assertIn("repo", globals_keys)
        self.assertIn("ghsa", globals_keys)
        self.assertIn("action", globals_keys)

    def test_pvr_triage_batch_yaml_parses(self):
        """pvr_triage_batch.yaml loads without error and declares repo global."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch")
        self.assertIsNotNone(result)
        header = result["seclab-taskflow-agent"]
        self.assertEqual(header["filetype"], "taskflow")
        globals_keys = result.get("globals", {})
        self.assertIn("repo", globals_keys)

    def test_reporter_reputation_toolbox_parses(self):
        """reporter_reputation.yaml loads without error and is a toolbox."""
        result = self.tools.get_toolbox("seclab_taskflows.toolboxes.reporter_reputation")
        self.assertIsNotNone(result)
        header = result["seclab-taskflow-agent"]
        self.assertEqual(header["filetype"], "toolbox")

    def test_pvr_ghsa_toolbox_has_confirm(self):
        """pvr_ghsa.yaml toolbox declares write-back tools in confirm list."""
        result = self.tools.get_toolbox("seclab_taskflows.toolboxes.pvr_ghsa")
        self.assertIsNotNone(result)
        confirm = result.get("confirm", [])
        self.assertIn("reject_pvr_advisory", confirm)
        self.assertIn("add_pvr_advisory_comment", confirm)

    def test_pvr_respond_batch_yaml_parses(self):
        """pvr_respond_batch.yaml loads without error and declares repo + action globals."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_respond_batch")
        self.assertIsNotNone(result)
        header = result["seclab-taskflow-agent"]
        self.assertEqual(header["filetype"], "taskflow")
        globals_keys = result.get("globals", {})
        self.assertIn("repo", globals_keys)
        self.assertIn("action", globals_keys)

    def test_pvr_triage_yaml_has_reporter_reputation_toolbox(self):
        """pvr_triage.yaml references reporter_reputation toolbox in at least one task."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_triage")
        taskflow = result.get("taskflow", [])
        toolbox_refs = []
        for task_wrapper in taskflow:
            task = task_wrapper.get("task", {})
            toolboxes = task.get("toolboxes", [])
            toolbox_refs.extend(toolboxes)
        self.assertIn(
            "seclab_taskflows.toolboxes.reporter_reputation",
            toolbox_refs,
            "pvr_triage.yaml must reference the reporter_reputation toolbox",
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

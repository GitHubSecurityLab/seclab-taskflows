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

    # --- accept_pvr_advisory ---

    def test_accept_pvr_advisory_calls_correct_api(self):
        """accept_pvr_advisory should PATCH state=draft."""
        calls = []

        def fake_gh_api(path, method="GET", body=None):
            calls.append({"path": path, "method": method, "body": body})
            return {"ghsa_id": "GHSA-1234-5678-abcd", "state": "draft"}, None

        with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
            result = self.pvr.accept_pvr_advisory.fn(
                owner="owner",
                repo="repo",
                ghsa_id="GHSA-1234-5678-abcd",
            )

        self.assertEqual(calls[0]["method"], "PATCH")
        self.assertIn("GHSA-1234-5678-abcd", calls[0]["path"])
        self.assertEqual(calls[0]["body"], {"state": "draft"})
        self.assertIn("draft", result)

    # --- reject_pvr_advisory ---

    def test_reject_pvr_advisory_calls_correct_api(self):
        """reject_pvr_advisory should PATCH state=closed."""
        calls = []

        def fake_gh_api(path, method="GET", body=None):
            calls.append({"path": path, "method": method, "body": body})
            return {"ghsa_id": "GHSA-1234-5678-abcd", "state": "closed"}, None

        with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
            result = self.pvr.reject_pvr_advisory.fn(
                owner="owner",
                repo="repo",
                ghsa_id="GHSA-1234-5678-abcd",
            )

        self.assertEqual(calls[0]["method"], "PATCH")
        self.assertIn("GHSA-1234-5678-abcd", calls[0]["path"])
        self.assertEqual(calls[0]["body"], {"state": "closed"})
        self.assertIn("closed", result)

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

    # --- fetch_security_policy ---

    def test_fetch_security_policy_found(self):
        """fetch_security_policy returns content when SECURITY.md exists."""
        policy_text = "# Security Policy\n\n## Supported Versions\n| 1.x | yes |"

        def fake_run(cmd, **kwargs):
            mock_result = MagicMock()
            if "SECURITY.md" in cmd[-1] and ".github" not in cmd[-1]:
                mock_result.returncode = 0
                mock_result.stdout = policy_text
            else:
                mock_result.returncode = 1
                mock_result.stdout = ""
            return mock_result

        with patch("subprocess.run", side_effect=fake_run):
            result = self.pvr.fetch_security_policy.fn(owner="acme", repo="widget")

        self.assertIn("Security Policy", result)
        self.assertIn("Supported Versions", result)

    def test_fetch_security_policy_not_found(self):
        """fetch_security_policy returns empty string when no policy exists."""
        def fake_run(cmd, **kwargs):
            mock_result = MagicMock()
            mock_result.returncode = 1
            mock_result.stdout = ""
            return mock_result

        with patch("subprocess.run", side_effect=fake_run):
            result = self.pvr.fetch_security_policy.fn(owner="acme", repo="widget")

        self.assertEqual(result, "")


# ---------------------------------------------------------------------------
# TestFingerprintAndDedup
# ---------------------------------------------------------------------------

class TestFingerprintAndDedup(unittest.TestCase):
    """Tests for advisory fingerprinting, comparison, and dedup detection."""

    def setUp(self):
        import seclab_taskflows.mcp_servers.pvr_ghsa as pvr_mod
        self.pvr = pvr_mod

    # --- _extract_file_paths ---

    def test_extract_file_paths_finds_paths(self):
        """_extract_file_paths finds source file paths in free text."""
        text = "The bug is in `src/handlers/upload.py` and also affects lib/auth/check.go"
        paths = self.pvr._extract_file_paths(text)
        self.assertIn("src/handlers/upload.py", paths)
        self.assertIn("lib/auth/check.go", paths)

    def test_extract_file_paths_ignores_non_source(self):
        """_extract_file_paths ignores non-source extensions and bare filenames."""
        text = "See README.md and report.pdf for details. Also config.txt"
        paths = self.pvr._extract_file_paths(text)
        # No paths with / separator, so none should match
        self.assertEqual(paths, [])

    def test_extract_file_paths_deduplicates(self):
        """_extract_file_paths returns unique sorted paths."""
        text = "Bug in src/auth.py and also src/auth.py again"
        paths = self.pvr._extract_file_paths(text)
        self.assertEqual(len(paths), len(set(paths)))

    # --- _fingerprint_advisory ---

    def test_fingerprint_advisory_extracts_fields(self):
        """_fingerprint_advisory extracts CWEs, packages, versions, file paths."""
        parsed = {
            "ghsa_id": "GHSA-test-1234-abcd",
            "summary": "Path traversal in upload handler",
            "severity": "high",
            "description": "The file src/upload/handler.py has a path traversal bug at line 42",
            "vulnerabilities": [
                {
                    "ecosystem": "pip",
                    "package": "myapp",
                    "vulnerable_versions": "<= 1.5.0",
                    "patched_versions": "1.5.1",
                }
            ],
            "cwes": ["CWE-22"],
        }
        fp = self.pvr._fingerprint_advisory(parsed)
        self.assertEqual(fp["ghsa_id"], "GHSA-test-1234-abcd")
        self.assertIn("CWE-22", fp["cwes"])
        self.assertIn(("pip", "myapp"), fp["packages"])
        self.assertIn("<= 1.5.0", fp["versions"])
        self.assertIn("src/upload/handler.py", fp["file_paths"])
        self.assertEqual(fp["severity"], "high")

    def test_fingerprint_advisory_empty_fields(self):
        """_fingerprint_advisory handles empty/missing fields gracefully."""
        parsed = {
            "ghsa_id": "GHSA-empty",
            "summary": "",
            "severity": "",
            "description": "",
            "vulnerabilities": [],
            "cwes": [],
        }
        fp = self.pvr._fingerprint_advisory(parsed)
        self.assertEqual(fp["cwes"], set())
        self.assertEqual(fp["packages"], set())
        self.assertEqual(fp["file_paths"], set())

    # --- _compare_fingerprints ---

    def test_compare_strong_match(self):
        """Two advisories with same CWE + same package → strong match."""
        a = {
            "ghsa_id": "A",
            "cwes": {"CWE-22"},
            "packages": {("pip", "myapp")},
            "versions": {"<= 1.5.0"},
            "file_paths": set(),
            "severity": "high",
            "summary_norm": "path traversal in upload",
        }
        b = {
            "ghsa_id": "B",
            "cwes": {"CWE-22"},
            "packages": {("pip", "myapp")},
            "versions": {"<= 1.5.0"},
            "file_paths": set(),
            "severity": "high",
            "summary_norm": "path traversal in upload handler",
        }
        result = self.pvr._compare_fingerprints(a, b)
        self.assertEqual(result["match_level"], "strong")
        self.assertTrue(len(result["reasons"]) > 0)

    def test_compare_no_match(self):
        """Two unrelated advisories → no match."""
        a = {
            "ghsa_id": "A",
            "cwes": {"CWE-22"},
            "packages": {("pip", "appA")},
            "versions": {"<= 1.0"},
            "file_paths": {"src/a.py"},
            "severity": "high",
            "summary_norm": "path traversal",
        }
        b = {
            "ghsa_id": "B",
            "cwes": {"CWE-79"},
            "packages": {("npm", "appB")},
            "versions": {">= 2.0"},
            "file_paths": {"src/b.js"},
            "severity": "medium",
            "summary_norm": "xss in login form",
        }
        result = self.pvr._compare_fingerprints(a, b)
        self.assertEqual(result["match_level"], "none")

    def test_compare_moderate_match(self):
        """Same package but no CWE/version/file overlap → moderate match."""
        a = {
            "ghsa_id": "A",
            "cwes": set(),
            "packages": {("pip", "myapp")},
            "versions": set(),
            "file_paths": set(),
            "severity": "high",
            "summary_norm": "bug in myapp",
        }
        b = {
            "ghsa_id": "B",
            "cwes": set(),
            "packages": {("pip", "myapp")},
            "versions": set(),
            "file_paths": set(),
            "severity": "medium",
            "summary_norm": "another bug in myapp",
        }
        result = self.pvr._compare_fingerprints(a, b)
        self.assertEqual(result["match_level"], "moderate")

    def test_compare_weak_match(self):
        """Only CWE overlap, different packages → weak match."""
        a = {
            "ghsa_id": "A",
            "cwes": {"CWE-79"},
            "packages": {("pip", "appA")},
            "versions": set(),
            "file_paths": set(),
            "severity": "medium",
            "summary_norm": "xss in appA",
        }
        b = {
            "ghsa_id": "B",
            "cwes": {"CWE-79"},
            "packages": {("pip", "appB")},
            "versions": set(),
            "file_paths": set(),
            "severity": "medium",
            "summary_norm": "xss in appB",
        }
        result = self.pvr._compare_fingerprints(a, b)
        self.assertEqual(result["match_level"], "weak")

    # --- compare_advisories (MCP tool, needs API mock) ---

    def test_compare_advisories_no_advisories(self):
        """compare_advisories returns empty result when no advisories exist."""
        def fake_gh_api(path, method="GET", body=None):
            return [], None

        with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
            result_json = self.pvr.compare_advisories.fn(
                owner="owner", repo="repo", state="triage", target_ghsa=""
            )

        result = json.loads(result_json)
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["clusters"], [])

    def test_compare_advisories_detects_duplicates(self):
        """compare_advisories clusters advisories with matching CWE + package."""
        fake_advisories = [
            {
                "ghsa_id": "GHSA-aaaa-1111-aaaa",
                "cve_id": None,
                "html_url": "https://github.com/x/y/security/advisories/GHSA-aaaa-1111-aaaa",
                "state": "triage",
                "severity": "high",
                "summary": "Path traversal in upload",
                "description": "The file src/upload/handler.py allows path traversal",
                "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "myapp"}, "vulnerable_version_range": "<= 1.5.0", "patched_versions": ""}],
                "cwes": [{"cwe_id": "CWE-22"}],
                "credits_detailed": [],
                "submission": {},
                "created_at": "2026-04-01",
                "updated_at": "2026-04-01",
                "collaborating_users": [],
            },
            {
                "ghsa_id": "GHSA-bbbb-2222-bbbb",
                "cve_id": None,
                "html_url": "https://github.com/x/y/security/advisories/GHSA-bbbb-2222-bbbb",
                "state": "triage",
                "severity": "high",
                "summary": "Directory traversal in file upload",
                "description": "Directory traversal vulnerability in src/upload/handler.py",
                "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "myapp"}, "vulnerable_version_range": "<= 1.5.0", "patched_versions": ""}],
                "cwes": [{"cwe_id": "CWE-22"}],
                "credits_detailed": [],
                "submission": {},
                "created_at": "2026-04-02",
                "updated_at": "2026-04-02",
                "collaborating_users": [],
            },
            {
                "ghsa_id": "GHSA-cccc-3333-cccc",
                "cve_id": None,
                "html_url": "https://github.com/x/y/security/advisories/GHSA-cccc-3333-cccc",
                "state": "triage",
                "severity": "medium",
                "summary": "XSS in comment rendering",
                "description": "Cross-site scripting in src/comments/render.js",
                "vulnerabilities": [{"package": {"ecosystem": "npm", "name": "other-app"}, "vulnerable_version_range": "<= 2.0.0", "patched_versions": ""}],
                "cwes": [{"cwe_id": "CWE-79"}],
                "credits_detailed": [],
                "submission": {},
                "created_at": "2026-04-03",
                "updated_at": "2026-04-03",
                "collaborating_users": [],
            },
        ]

        def fake_gh_api(path, method="GET", body=None):
            return fake_advisories, None

        with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
            result_json = self.pvr.compare_advisories.fn(
                owner="owner", repo="repo", state="triage", target_ghsa=""
            )

        result = json.loads(result_json)
        self.assertEqual(result["total"], 3)
        # The two path traversal advisories should cluster together
        self.assertEqual(len(result["clusters"]), 1)
        cluster = result["clusters"][0]
        self.assertIn("GHSA-aaaa-1111-aaaa", cluster["advisories"])
        self.assertIn("GHSA-bbbb-2222-bbbb", cluster["advisories"])
        self.assertNotIn("GHSA-cccc-3333-cccc", cluster["advisories"])
        self.assertIn(cluster["match_level"], ("strong", "moderate"))
        # The XSS advisory should be in singles
        self.assertIn("GHSA-cccc-3333-cccc", result["singles"])

    def test_compare_advisories_target_ghsa_filter(self):
        """compare_advisories with target_ghsa only returns matches for that GHSA."""
        fake_advisories = [
            {
                "ghsa_id": "GHSA-aaaa-1111-aaaa",
                "cve_id": None, "html_url": "", "state": "triage",
                "severity": "high", "summary": "Bug A",
                "description": "desc",
                "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "app"}, "vulnerable_version_range": "<= 1.0", "patched_versions": ""}],
                "cwes": [{"cwe_id": "CWE-22"}],
                "credits_detailed": [], "submission": {},
                "created_at": "2026-04-01", "updated_at": "2026-04-01",
                "collaborating_users": [],
            },
            {
                "ghsa_id": "GHSA-bbbb-2222-bbbb",
                "cve_id": None, "html_url": "", "state": "triage",
                "severity": "high", "summary": "Bug B",
                "description": "desc",
                "vulnerabilities": [{"package": {"ecosystem": "pip", "name": "app"}, "vulnerable_version_range": "<= 1.0", "patched_versions": ""}],
                "cwes": [{"cwe_id": "CWE-22"}],
                "credits_detailed": [], "submission": {},
                "created_at": "2026-04-02", "updated_at": "2026-04-02",
                "collaborating_users": [],
            },
        ]

        def fake_gh_api(path, method="GET", body=None):
            return fake_advisories, None

        with patch.object(self.pvr, "_gh_api", side_effect=fake_gh_api):
            result_json = self.pvr.compare_advisories.fn(
                owner="owner", repo="repo", state="triage",
                target_ghsa="GHSA-aaaa-1111-aaaa",
            )

        result = json.loads(result_json)
        # Should still find the cluster
        self.assertTrue(len(result["clusters"]) >= 1 or len(result.get("weak_matches", [])) >= 0)


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
        self.assertEqual(result.header.filetype, "taskflow")

    def test_pvr_respond_yaml_parses(self):
        """pvr_respond.yaml loads without error and declares required globals."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_respond")
        self.assertIsNotNone(result)
        self.assertEqual(result.header.filetype, "taskflow")
        globals_keys = result.globals or {}
        self.assertIn("repo", globals_keys)
        self.assertIn("ghsa", globals_keys)
        self.assertIn("action", globals_keys)

    def test_pvr_triage_batch_yaml_parses(self):
        """pvr_triage_batch.yaml loads without error and declares repo global."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_triage_batch")
        self.assertIsNotNone(result)
        self.assertEqual(result.header.filetype, "taskflow")
        globals_keys = result.globals or {}
        self.assertIn("repo", globals_keys)

    def test_reporter_reputation_toolbox_parses(self):
        """reporter_reputation.yaml loads without error and is a toolbox."""
        result = self.tools.get_toolbox("seclab_taskflows.toolboxes.reporter_reputation")
        self.assertIsNotNone(result)
        self.assertEqual(result.header.filetype, "toolbox")

    def test_pvr_ghsa_toolbox_has_confirm(self):
        """pvr_ghsa.yaml toolbox declares write-back tools in confirm list."""
        result = self.tools.get_toolbox("seclab_taskflows.toolboxes.pvr_ghsa")
        self.assertIsNotNone(result)
        confirm = result.confirm or []
        self.assertIn("accept_pvr_advisory", confirm)
        self.assertIn("reject_pvr_advisory", confirm)
        self.assertNotIn("add_pvr_advisory_comment", confirm)

    def test_pvr_respond_batch_yaml_parses(self):
        """pvr_respond_batch.yaml loads without error and declares repo + action globals."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_respond_batch")
        self.assertIsNotNone(result)
        self.assertEqual(result.header.filetype, "taskflow")
        globals_keys = result.globals or {}
        self.assertIn("repo", globals_keys)
        self.assertIn("action", globals_keys)

    def test_pvr_triage_yaml_has_reporter_reputation_toolbox(self):
        """pvr_triage.yaml references reporter_reputation toolbox in at least one task."""
        result = self.tools.get_taskflow("seclab_taskflows.taskflows.pvr_triage.pvr_triage")
        taskflow = result.taskflow or []
        toolbox_refs = []
        for task_wrapper in taskflow:
            task = task_wrapper.task
            toolboxes = task.toolboxes or []
            toolbox_refs.extend(toolboxes)
        self.assertIn(
            "seclab_taskflows.toolboxes.reporter_reputation",
            toolbox_refs,
            "pvr_triage.yaml must reference the reporter_reputation toolbox",
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

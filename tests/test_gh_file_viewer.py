# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import json
import os
import tempfile
import zipfile
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import seclab_taskflows.mcp_servers.gh_file_viewer as gfv_mod

# Run all tests in this module on a single xdist worker to avoid DB races.
pytestmark = pytest.mark.xdist_group("gh_file_viewer")


# ---------------------------------------------------------------------------
# Mock Contents for GitHub API responses
# ---------------------------------------------------------------------------

SAMPLE_FILE_CONTENT = """\
import os
import sys

def main():
    print("Setec Astronomy")

if __name__ == "__main__":
    main()
"""

SAMPLE_DIR_JSON = [
    {"path": "src/main.py", "type": "file"},
    {"path": "src/utils.py", "type": "file"},
    {"path": "src/tests", "type": "dir"},
]


def _make_response(text="", json_data=None, status_code=200):
    """Build a fake httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text
    resp.json.return_value = json_data
    return resp


def _make_zip_bytes(files: dict[str, str]) -> bytes:
    """Create an in-memory zip with a root directory prefix (like GitHub zipball)."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, content in files.items():
            zf.writestr(f"owner-repo-abc1234/{path}", content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# fetch_file_from_gh tests
# ---------------------------------------------------------------------------

class TestFetchFileFromGh:
    @pytest.mark.asyncio
    async def test_fetch_file_success(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.fetch_file_from_gh(owner="Owner", repo="Repo", path="src/main.py")
            assert "1: import os" in result
            assert "5:     print(\"Setec Astronomy\")" in result

    @pytest.mark.asyncio
    async def test_fetch_file_lowercases_owner_repo(self):
        resp = _make_response(text="line1\nline2\n")
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp) as mock_api:
            await gfv_mod.fetch_file_from_gh(owner="OWNER", repo="REPO", path="file.py")
            url = mock_api.call_args[1]["url"]
            assert "/owner/repo/" in url

    @pytest.mark.asyncio
    async def test_fetch_file_api_error(self):
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value="HTTP error: 404"):
            result = await gfv_mod.fetch_file_from_gh(owner="owner", repo="repo", path="missing.py")
            assert result == "HTTP error: 404"


# ---------------------------------------------------------------------------
# get_file_lines_from_gh tests
# ---------------------------------------------------------------------------

class TestGetFileLinesFromGh:
    @pytest.mark.asyncio
    async def test_get_lines_range(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.get_file_lines_from_gh(
                owner="owner", repo="repo", path="main.py", start_line=4, length=2
            )
            lines = result.strip().splitlines()
            assert len(lines) == 2
            assert "4: def main():" in lines[0]

    @pytest.mark.asyncio
    async def test_get_lines_clamps_start(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.get_file_lines_from_gh(
                owner="owner", repo="repo", path="main.py", start_line=-5, length=2
            )
            assert "1: import os" in result

    @pytest.mark.asyncio
    async def test_get_lines_out_of_range(self):
        resp = _make_response(text="one\ntwo\n")
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.get_file_lines_from_gh(
                owner="owner", repo="repo", path="main.py", start_line=100, length=10
            )
            assert "No lines found" in result

    @pytest.mark.asyncio
    async def test_get_lines_api_error(self):
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value="Request error: timeout"):
            result = await gfv_mod.get_file_lines_from_gh(
                owner="owner", repo="repo", path="main.py", start_line=1, length=5
            )
            assert result == "Request error: timeout"


# ---------------------------------------------------------------------------
# search_file_from_gh tests
# ---------------------------------------------------------------------------

class TestSearchFileFromGh:
    @pytest.mark.asyncio
    async def test_search_file_finds_matches(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.search_file_from_gh(
                owner="owner", repo="repo", path="main.py", search_term="import"
            )
            assert "1: import os" in result
            assert "2: import sys" in result

    @pytest.mark.asyncio
    async def test_search_file_no_matches(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.search_file_from_gh(
                owner="owner", repo="repo", path="main.py", search_term="nonexistent_term"
            )
            assert "No matches found" in result

    @pytest.mark.asyncio
    async def test_search_file_api_error(self):
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value="HTTP error: 500"):
            result = await gfv_mod.search_file_from_gh(
                owner="owner", repo="repo", path="main.py", search_term="import"
            )
            assert result == "HTTP error: 500"


# ---------------------------------------------------------------------------
# search_files_from_gh tests
# ---------------------------------------------------------------------------

class TestSearchFilesFromGh:
    @pytest.mark.asyncio
    async def test_search_files_multiple_paths(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.search_files_from_gh(
                owner="owner", repo="repo", paths="main.py, utils.py", search_term="import",
                save_to_db=False,
            )
            data = json.loads(result)
            assert len(data) > 0
            assert all(r["search_term"] == "import" for r in data)

    @pytest.mark.asyncio
    async def test_search_files_no_paths(self):
        resp = _make_response(text="")
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.search_files_from_gh(
                owner="owner", repo="repo", paths="", search_term="import", save_to_db=False,
            )
            # empty string split yields [""], which hits the API for an empty path
            assert "No matches found" in result

    @pytest.mark.asyncio
    async def test_search_files_no_matches(self):
        resp = _make_response(text="nothing here\n")
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.search_files_from_gh(
                owner="owner", repo="repo", paths="main.py", search_term="zzzzz"
            )
            assert "No matches found" in result

    @pytest.mark.asyncio
    async def test_search_files_save_to_db(self):
        resp = _make_response(text=SAMPLE_FILE_CONTENT)
        with (
            patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp),
            patch.object(gfv_mod, "Session") as mock_session_cls,
        ):
            mock_session = MagicMock()
            mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
            mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)
            result = await gfv_mod.search_files_from_gh(
                owner="owner", repo="repo", paths="main.py", search_term="import", save_to_db=True
            )
            assert "saved to database" in result
            assert mock_session.add.called
            assert mock_session.commit.called

    @pytest.mark.asyncio
    async def test_search_files_api_error(self):
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value="Request error: timeout"):
            result = await gfv_mod.search_files_from_gh(
                owner="owner", repo="repo", paths="main.py", search_term="import"
            )
            assert result == "Request error: timeout"


# ---------------------------------------------------------------------------
# fetch_last_search_results tests
# ---------------------------------------------------------------------------

class TestFetchLastSearchResults:
    def test_fetch_last_results(self):
        mock_result = MagicMock()
        mock_result.path = "src/main.py"
        mock_result.line = 1
        mock_result.search_term = "import"
        mock_result.owner = "owner"
        mock_result.repo = "repo"

        with patch.object(gfv_mod, "Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
            mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_session.query.return_value.all.return_value = [mock_result]
            mock_session.query.return_value.delete.return_value = None

            result = gfv_mod.fetch_last_search_results()
            data = json.loads(result)
            assert len(data) == 1
            assert data[0]["path"] == "src/main.py"
            assert data[0]["line"] == 1

    def test_fetch_last_results_empty(self):
        with patch.object(gfv_mod, "Session") as mock_session_cls:
            mock_session = MagicMock()
            mock_session_cls.return_value.__enter__ = MagicMock(return_value=mock_session)
            mock_session_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_session.query.return_value.all.return_value = []
            mock_session.query.return_value.delete.return_value = None

            result = gfv_mod.fetch_last_search_results()
            assert json.loads(result) == []


# ---------------------------------------------------------------------------
# list_directory_from_gh tests
# ---------------------------------------------------------------------------

class TestListDirectoryFromGh:
    @pytest.mark.asyncio
    async def test_list_directory_success(self):
        resp = _make_response(json_data=SAMPLE_DIR_JSON)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.list_directory_from_gh(owner="Owner", repo="Repo", path="src")
            data = json.loads(result)
            assert "src/main.py" in data
            assert "src/utils.py" in data
            assert "src/tests" in data

    @pytest.mark.asyncio
    async def test_list_directory_empty(self):
        resp = _make_response(json_data=[])
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.list_directory_from_gh(owner="owner", repo="repo", path="empty")
            assert json.loads(result) == []

    @pytest.mark.asyncio
    async def test_list_directory_api_error(self):
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value="HTTP error: 404"):
            result = await gfv_mod.list_directory_from_gh(owner="owner", repo="repo", path="missing")
            assert result == "HTTP error: 404"

    @pytest.mark.asyncio
    async def test_list_directory_path_is_file(self):
        """When the path points to a file, the API returns a dict instead of a list."""
        file_obj = {"path": "src/main.py", "type": "file", "size": 123, "sha": "abc"}
        resp = _make_response(json_data=file_obj)
        with patch.object(gfv_mod, "call_api", new_callable=AsyncMock, return_value=resp):
            result = await gfv_mod.list_directory_from_gh(owner="owner", repo="repo", path="src/main.py")
            assert "not a directory" in result


# ---------------------------------------------------------------------------
# search_repo_from_gh tests
# ---------------------------------------------------------------------------

class TestSearchRepoFromGh:
    @pytest.mark.asyncio
    async def test_search_repo_finds_matches(self):
        zip_bytes = _make_zip_bytes({
            "src/main.py": "import os\nimport sys\n",
            "src/utils.py": "import os\ndef helper(): pass\n",
        })

        async def fake_fetch_source_zip(owner, repo, tmp_dir):
            os.makedirs(f"{tmp_dir}/{owner}", exist_ok=True)
            Path(f"{tmp_dir}/{owner}/{repo}.zip").write_bytes(zip_bytes)
            return "source code fetched"

        with patch.object(gfv_mod, "_fetch_source_zip", side_effect=fake_fetch_source_zip):
            result = await gfv_mod.search_repo_from_gh(
                owner="Owner", repo="Repo", search_term="import"
            )
            data = json.loads(result)
            assert len(data) >= 2
            paths = [item["path"] for item in data]
            assert "src/main.py" in paths
            assert "src/utils.py" in paths

    @pytest.mark.asyncio
    async def test_search_repo_no_matches(self):
        zip_bytes = _make_zip_bytes({"src/main.py": "hello world\n"})

        async def fake_fetch_source_zip(owner, repo, tmp_dir):
            os.makedirs(f"{tmp_dir}/{owner}", exist_ok=True)
            Path(f"{tmp_dir}/{owner}/{repo}.zip").write_bytes(zip_bytes)
            return "source code fetched"

        with patch.object(gfv_mod, "_fetch_source_zip", side_effect=fake_fetch_source_zip):
            result = await gfv_mod.search_repo_from_gh(
                owner="owner", repo="repo", search_term="nonexistent"
            )
            assert json.loads(result) == []

    @pytest.mark.asyncio
    async def test_search_repo_zip_missing(self):
        async def fake_fetch_source_zip(owner, repo, tmp_dir):
            return "Error: HTTP error: 404"

        with patch.object(gfv_mod, "_fetch_source_zip", side_effect=fake_fetch_source_zip):
            result = await gfv_mod.search_repo_from_gh(
                owner="owner", repo="repo", search_term="import"
            )
            data = json.loads(result)
            assert "Error" in data[0]


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_remove_root_dir(self):
        assert gfv_mod.remove_root_dir("root/src/main.py") == "src/main.py"

    def test_remove_root_dir_single_segment(self):
        assert gfv_mod.remove_root_dir("root") == ""

    def test_search_zipfile(self):
        zip_bytes = _make_zip_bytes({
            "main.py": "import os\nimport sys\nprint('hello')\n",
            "utils.py": "def helper(): pass\n",
        })
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(zip_bytes)
            f.flush()
            results = gfv_mod.search_zipfile(f.name, "import")
        os.unlink(f.name)
        assert "main.py" in results
        assert 1 in results["main.py"]
        assert 2 in results["main.py"]
        assert "utils.py" not in results


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

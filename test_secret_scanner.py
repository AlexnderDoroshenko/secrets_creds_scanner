import pytest
import asyncio
import re
from pathlib import Path
from secret_scanner import (
    parse_gitignore,
    should_ignore,
    get_files_to_scan,
    find_secrets_in_file,
)


@pytest.fixture
def temp_project(tmp_path):
    """Creates a temporary project structure for testing."""
    (tmp_path / ".gitignore").write_text("*.log\nsecret_folder/\n", encoding="utf-8")
    (tmp_path / "test.py").write_text("API_KEY = '123456'\npassword = 'secret'", encoding="utf-8")
    (tmp_path / "ignore.log").write_text("Should be ignored", encoding="utf-8")
    (tmp_path / "secret_folder").mkdir()
    (tmp_path / "secret_folder" / "hidden.py").write_text("HIDDEN_KEY = 'should not be found'", encoding="utf-8")
    return tmp_path


def test_parse_gitignore(temp_project):
    """Tests .gitignore parsing."""
    gitignore_path = temp_project / ".gitignore"
    ignored_patterns = parse_gitignore(gitignore_path)
    assert "*.log" in ignored_patterns
    assert "secret_folder/" in ignored_patterns


def test_should_ignore(temp_project):
    """Tests whether files are correctly ignored based on .gitignore."""
    ignored_patterns = parse_gitignore(temp_project / ".gitignore")
    assert should_ignore(temp_project / "ignore.log", ignored_patterns)
    assert should_ignore(temp_project / "secret_folder", ignored_patterns)
    assert not should_ignore(temp_project / "test.py", ignored_patterns)


def test_get_files_to_scan(temp_project):
    """Tests file scanning while respecting .gitignore rules."""
    ignored_patterns = parse_gitignore(temp_project / ".gitignore")
    files = get_files_to_scan(temp_project, ignored_patterns)
    assert temp_project / "test.py" in files
    assert temp_project / "ignore.log" not in files
    assert temp_project / "secret_folder" / "hidden.py" not in files


@pytest.mark.asyncio
async def test_find_secrets_in_file(temp_project):
    """Tests if secrets are correctly detected in files."""
    secret_patterns = [
        re.compile(r"(?i)(API_KEY|password)[\s=:\"]+([A-Za-z0-9-_]+)"),
    ]
    file_path = temp_project / "test.py"
    results = await find_secrets_in_file(file_path, secret_patterns)
    
    assert len(results) == 2
    assert results[0]["secret"] == "API_KEY = '123456'"
    assert results[1]["secret"] == "password = 'secret'"


if __name__ == "__main__":
    pytest.main()

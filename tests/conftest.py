import subprocess
from pathlib import Path

import pytest


def git(root: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True, text=True).stdout.strip()


def commit_all(root: Path, message: str) -> str:
    git(root, "add", "-A")
    git(root, "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """main has app.py; branch `feature` changes it and adds a tracked .env and a key file."""
    root = tmp_path / "repo"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "app.py").write_text("def total(xs):\n    return sum(xs)\n", encoding="utf-8")
    (root / "docs").mkdir()
    (root / "docs" / "environment.md").write_text("how to set up\n", encoding="utf-8")
    commit_all(root, "base commit")
    git(root, "checkout", "-q", "-b", "feature")
    (root / "app.py").write_text("def total(xs):\n    return sum(xs[1:])\n", encoding="utf-8")
    (root / ".env").write_text("OPENAI_API_KEY=sk-proj-" + "A" * 28 + "\n", encoding="utf-8")
    commit_all(root, "fix: total now skips the header row SECRET-COMMIT-MESSAGE")
    return root


@pytest.fixture
def neighbour(tmp_path: Path) -> Path:
    root = tmp_path / "web"
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "client.ts").write_text("export const schema = strictObject({ total: number })\n", encoding="utf-8")
    commit_all(root, "web")
    return root

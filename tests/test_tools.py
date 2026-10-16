import json
from pathlib import Path

import pytest

from conftest import commit_all
from outsider.gitio import GitError, Repo
from outsider.guard import DEFAULT_DENY
from outsider.tools import Toolbox


def box(repo: Path, neighbour: Path | None = None, **kw) -> Toolbox:
    repos = {"": Repo.open(repo, "feature")}
    if neighbour:
        repos["web"] = Repo.open(neighbour, "main")
    return Toolbox(repos, deny=DEFAULT_DENY, **kw)


def call(b: Toolbox, name: str, **args) -> str:
    return b.call(name, json.dumps(args))


def test_read_file_numbers_lines_at_reviewed_commit(repo):
    out = call(box(repo), "read_file", path="app.py")
    assert "1\tdef total(xs):" in out and "2\t    return sum(xs[1:])" in out


def test_G7_working_tree_and_untracked_files_invisible(repo):
    (repo / "app.py").write_text("LOCAL EDIT\n", encoding="utf-8")
    (repo / "notes.txt").write_text("untracked\n", encoding="utf-8")
    b = box(repo)
    assert "LOCAL EDIT" not in call(b, "read_file", path="app.py")
    assert "error" in call(b, "read_file", path="notes.txt").lower()
    assert "notes.txt" not in call(b, "list_dir", path="")


def test_G1_escape_refused_by_tool(repo):
    assert "error" in call(box(repo), "read_file", path="../../etc/passwd").lower()


def test_G2_denylisted_read_refused_and_hidden_from_listing_and_grep(repo):
    b = box(repo)
    out = call(b, "read_file", path=".env")
    assert "denied" in out.lower() and "sk-proj" not in out
    assert ".env" not in call(b, "list_dir", path="").split()
    assert "sk-proj" not in call(b, "grep", pattern="OPENAI")


def test_grep_finds_code(repo):
    out = call(box(repo), "grep", pattern=r"sum\(")
    assert "app.py:2:" in out


def test_grep_pattern_cannot_inject_options(repo):
    out = call(box(repo), "grep", pattern="--open-files-in-pager=touch /tmp/x")
    assert "error" in out.lower() or out.strip() == "(no matches)"


def test_G5_secret_in_read_file_redacted(repo):
    (repo / "settings.py").write_text("TOKEN = 'ghp_" + "b" * 36 + "'\n", encoding="utf-8")
    commit_all(repo, "add settings")
    out = call(box(repo), "read_file", path="settings.py")
    assert "ghp_" not in out and "[REDACTED by outsider]" in out


def test_G8_neighbour_read_at_ref_not_working_tree(repo, neighbour):
    (neighbour / "client.ts").write_text("LOCAL\n", encoding="utf-8")
    out = call(box(repo, neighbour), "read_file", path="client.ts", repo="web")
    assert "strictObject" in out and "LOCAL" not in out


def test_unknown_neighbour_is_an_error(repo):
    assert "error" in call(box(repo), "read_file", path="x", repo="nope").lower()


def test_A3_malformed_arguments_answered_with_error(repo):
    b = box(repo)
    assert "error" in b.call("read_file", "{not json").lower()
    assert "error" in b.call("read_file", json.dumps({"nope": 1})).lower()
    assert "error" in b.call("rm_rf", "{}").lower()


def test_A7_huge_output_truncated(repo):
    (repo / "big.py").write_text("x = 1\n" * 5000, encoding="utf-8")
    commit_all(repo, "big")
    out = call(box(repo, max_chars=2000), "read_file", path="big.py")
    assert len(out) < 2600 and "truncated" in out


def test_read_file_line_range(repo):
    out = call(box(repo), "read_file", path="app.py", start_line=2, end_line=2)
    assert "def total" not in out and "2\t" in out


def test_diff_tool_returns_one_file_section(repo):
    b = box(repo, diff_sections={"app.py": "@@ -1 +1 @@\n-a\n+b\n"})
    assert "+b" in call(b, "diff", path="app.py")
    assert "error" in call(b, "diff", path="other.py").lower()


def test_V3_bad_ref(repo):
    with pytest.raises(GitError):
        Repo.open(repo, "no-such-branch")


def test_B1_no_tool_exposes_commit_messages(repo):
    b = box(repo)
    names = {s["function"]["name"] for s in b.schemas()}
    assert names == {"read_file", "grep", "list_dir", "diff"}
    for name, args in [("read_file", {"path": "app.py"}), ("grep", {"pattern": "total"}), ("list_dir", {"path": ""})]:
        assert "SECRET-COMMIT-MESSAGE" not in call(b, name, **args)


KEY_BODY = "MIIEowIBAAKCAQEAsecretkeybodyline"


def _key_block() -> str:
    return "-----BEGIN RSA " + "PRIVATE KEY-----\n" + KEY_BODY + "\nMORELINE\n-----END RSA " + "PRIVATE KEY-----\n"


@pytest.mark.parametrize("folder", ["configuração", "x:y", "we\tird", "espaço vazio"])
def test_H1_grep_and_list_dir_respect_denylist_in_odd_folder_names(repo, folder):
    (repo / folder).mkdir()
    (repo / folder / ".env").write_text("DBPASS=SECRETVAL_odd\n", encoding="utf-8")
    commit_all(repo, "odd folder")
    b = box(repo)
    assert "SECRETVAL" not in call(b, "grep", pattern="SECRETVAL")
    assert ".env" not in call(b, "list_dir", path=folder)


def test_H1_grep_reports_odd_paths_unquoted(repo):
    (repo / "configuração").mkdir()
    (repo / "configuração" / "mod.py").write_text("FOUND_ME = 1\n", encoding="utf-8")
    commit_all(repo, "accent")
    assert "configuração/mod.py:1:FOUND_ME = 1" in call(box(repo), "grep", pattern="FOUND_ME")


def test_L1_list_dir_root_actually_lists(repo):
    out = call(box(repo), "list_dir", path="")
    assert "app.py" in out.split() and "docs/" in out.split() and "error" not in out.lower()


@pytest.mark.parametrize("name", ["sa.json", "key.txt"])
def test_H2_private_key_body_redacted_everywhere(repo, name):
    (repo / name).write_text('{"private_key": "' + _key_block().replace("\n", "\\n") + '"}\n' if name.endswith(".json")
                             else "header\n" + _key_block(), encoding="utf-8")
    commit_all(repo, "key")
    b = box(repo)
    for out in (call(b, "read_file", path=name), call(b, "read_file", path=name, start_line=3),
                call(b, "grep", pattern="MIIE|MORELINE")):
        assert KEY_BODY not in out and "MORELINE" not in out, out


def test_L4_error_messages_are_redacted(repo):
    out = call(box(repo), "read_file", path="ghp_" + "d" * 36 + ".py")
    assert "ghp_" not in out


def test_G10_redaction_keeps_line_numbers(repo):
    (repo / "k.txt").write_text("header\n" + _key_block() + "code_after = 1\n", encoding="utf-8")
    commit_all(repo, "key then code")
    b = box(repo)
    assert "6\tcode_after = 1" in call(b, "read_file", path="k.txt")
    assert "code_after" in call(b, "read_file", path="k.txt", start_line=6)


@pytest.mark.parametrize("args", [{"path": None}, {"path": 3}, {"pattern": None}, {"path": "app.py", "start_line": "x"}])
def test_A3_wrong_argument_types_answered_with_error(repo, args):
    b = box(repo)
    for name in ("read_file", "list_dir", "grep", "diff"):
        assert "error" in b.call(name, json.dumps(args)).lower()


def test_A7_diff_of_a_huge_file_can_be_paged(repo):
    section = "".join(f"+line {i}\n" for i in range(1, 20001))
    b = box(repo, diff_sections={"big.py": section}, max_chars=2000)
    first = call(b, "diff", path="big.py")
    assert "truncated" in first
    tail = call(b, "diff", path="big.py", start_line=19990, end_line=20000)
    assert "+line 20000" in tail and "19990\t" in tail

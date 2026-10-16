import json

import pytest
import sys
from pathlib import Path

from conftest import commit_all, git
from fakes import FakeLLM, finding, flat_cost, submit, verdict
from outsider.review import Options, review


def opts(repo, tmp_path, **kw):
    base = dict(root=repo, base="main", head="feature", out=tmp_path / "out", model="m", max_usd=1.0)
    base.update(kw)
    return Options(**base)


def run(repo, tmp_path, llm, cost=0.001, **kw):
    return review(opts(repo, tmp_path, **kw), completion=llm, cost_fn=flat_cost(cost))


def everything_sent(llm) -> str:
    return json.dumps(llm.calls, default=str)


def test_happy_path_confirmed_high_blocks(repo, tmp_path):
    llm = FakeLLM(blind=submit([finding()]), verify=verdict("confirmed"))
    out = run(repo, tmp_path, llm)
    assert out.exit_code == 1
    f = out.report["findings"][0]
    assert f["verdict"] == "confirmed" and f["pass"] == "blind"
    assert (out.out_dir / "report.json").exists() and (out.out_dir / "report.md").exists()


def test_V1_plausible_high_does_not_block(repo, tmp_path):
    llm = FakeLLM(blind=submit([finding()]), verify=verdict("plausible"))
    assert run(repo, tmp_path, llm).exit_code == 0


def test_V1_confirmed_medium_does_not_block(repo, tmp_path):
    llm = FakeLLM(blind=submit([finding(severity="medium")]), verify=verdict("confirmed", "medium"))
    assert run(repo, tmp_path, llm).exit_code == 0


def test_verifier_can_downgrade(repo, tmp_path):
    llm = FakeLLM(blind=submit([finding(severity="critical")]), verify=verdict("confirmed", "low"))
    out = run(repo, tmp_path, llm)
    assert out.exit_code == 0 and out.report["findings"][0]["severity"] == "low"


def test_B1_blind_pass_never_sees_messages_branch_or_spec(repo, tmp_path):
    spec = tmp_path / "spec.md"
    spec.write_text("SPEC-TEXT-MARKER: total must skip the header row\n", encoding="utf-8")
    llm = FakeLLM(blind=submit([finding()]), intent=submit([]), verify=verdict("confirmed"))
    run(repo, tmp_path, llm, spec=spec)
    blind = json.dumps(llm.of("blind"))
    assert "SECRET-COMMIT-MESSAGE" not in everything_sent(llm)
    assert "SPEC-TEXT-MARKER" not in blind
    assert "feature" not in blind
    assert "SPEC-TEXT-MARKER" in json.dumps(llm.of("intent"))


def test_B2_intent_never_sees_blind_findings(repo, tmp_path):
    spec = tmp_path / "spec.md"
    spec.write_text("the spec\n", encoding="utf-8")
    llm = FakeLLM(blind=submit([finding(title="BLIND-ONLY-TITLE")]), intent=submit([]), verify=verdict("refuted"))
    run(repo, tmp_path, llm, spec=spec)
    assert "BLIND-ONLY-TITLE" not in json.dumps(llm.of("intent"))


def test_B3_verifier_sees_one_claim_and_no_spec_for_blind(repo, tmp_path):
    spec = tmp_path / "spec.md"
    spec.write_text("SPEC-TEXT-MARKER\n", encoding="utf-8")
    llm = FakeLLM(blind=submit([finding(title="CLAIM-ONE"), finding(title="CLAIM-TWO", line=1)]),
                  intent=submit([]), verify=verdict("plausible"))
    run(repo, tmp_path, llm, spec=spec)
    calls = llm.of("verify")
    assert len(calls) == 2
    for c in calls:
        sent = json.dumps(c)
        assert ("CLAIM-ONE" in sent) != ("CLAIM-TWO" in sent)
        assert "SPEC-TEXT-MARKER" not in sent


def test_intent_finding_verified_with_the_spec(repo, tmp_path):
    spec = tmp_path / "spec.md"
    spec.write_text("SPEC-TEXT-MARKER\n", encoding="utf-8")
    llm = FakeLLM(blind=submit([]), intent=submit([finding(title="INTENT-CLAIM")]), verify=verdict("confirmed"))
    out = run(repo, tmp_path, llm, spec=spec)
    assert out.report["findings"][0]["pass"] == "intent"
    assert "SPEC-TEXT-MARKER" in json.dumps(llm.of("verify"))


def test_A4_finding_without_scenario_or_file_dropped(repo, tmp_path):
    llm = FakeLLM(blind=submit([finding(failure_scenario="maybe"), finding(file=""), finding()]),
                  verify=verdict("confirmed"))
    out = run(repo, tmp_path, llm)
    assert len(out.report["findings"]) == 1 and out.report["meta"]["dropped"] == 2
    assert len(llm.of("verify")) == 1


def test_G3_denylisted_file_withheld_from_everything_sent(repo, tmp_path):
    llm = FakeLLM(blind=submit([]))
    out = run(repo, tmp_path, llm)
    assert out.report["meta"]["withheld"] == [".env"]
    assert "sk-proj" not in everything_sent(llm)


def test_G4_secret_in_diff_aborts_before_any_call(repo, tmp_path):
    (repo / "settings.py").write_text("TOKEN = 'ghp_" + "c" * 36 + "'\n", encoding="utf-8")
    commit_all(repo, "oops")
    llm = FakeLLM(blind=submit([]))
    out = run(repo, tmp_path, llm)
    assert out.exit_code == 3 and llm.calls == []
    assert "ghp_" not in json.dumps(out.report)
    assert out.report["meta"]["aborted"]["secrets"][0]["path"] == "settings.py"


def test_G4_secret_in_spec_aborts(repo, tmp_path):
    spec = tmp_path / "spec.md"
    spec.write_text("use AKIA" + "ABCDEFGHIJKLMNOP\n", encoding="utf-8")
    llm = FakeLLM(blind=submit([]))
    assert run(repo, tmp_path, llm, spec=spec).exit_code == 3 and llm.calls == []


def test_G6_pre_send_hook_failure_aborts(repo, tmp_path):
    llm = FakeLLM(blind=submit([]))
    hook = [sys.executable, "-c", "import sys; sys.exit(1)"]
    out = run(repo, tmp_path, llm, pre_send=hook)
    assert out.exit_code == 3 and llm.calls == []


def test_G6_pre_send_hook_gets_the_diff(repo, tmp_path):
    seen = tmp_path / "seen.txt"
    hook = [sys.executable, "-c",
            f"import os,shutil; shutil.copy(os.environ['OUTSIDER_DIFF_FILE'], {str(seen)!r})"]
    run(repo, tmp_path, FakeLLM(blind=submit([])), pre_send=hook)
    assert "sum(xs[1:])" in seen.read_text(encoding="utf-8")


def test_G6_missing_hook_binary_aborts(repo, tmp_path):
    llm = FakeLLM(blind=submit([]))
    assert run(repo, tmp_path, llm, pre_send=["no-such-binary-xyz"]).exit_code == 3 and llm.calls == []


def test_V2_empty_diff_makes_no_call(repo, tmp_path):
    llm = FakeLLM(blind=submit([]))
    out = run(repo, tmp_path, llm, base="feature")
    assert out.exit_code == 0 and llm.calls == []


def test_V3_bad_ref_is_usage_error(repo, tmp_path):
    assert run(repo, tmp_path, FakeLLM(blind=submit([])), base="nope").exit_code == 64


def test_A1_budget_out_during_verify_marks_incomplete(repo, tmp_path):
    many = [finding(line=i, title=f"t{i}") for i in range(1, 6)]
    llm = FakeLLM(blind=submit(many), verify=verdict("plausible"))
    out = run(repo, tmp_path, llm, cost=0.3, max_usd=1.0)
    assert out.exit_code == 2
    assert any(f["verdict"] == "unverified" for f in out.report["findings"])
    assert out.report["meta"]["incomplete"]


def test_V4_confirmed_blocker_outranks_incomplete(repo, tmp_path):
    many = [finding(line=i, title=f"t{i}") for i in range(1, 6)]
    llm = FakeLLM(blind=submit(many), verify=verdict("confirmed"))
    out = run(repo, tmp_path, llm, cost=0.3, max_usd=1.0)
    assert out.exit_code == 1 and out.report["meta"]["incomplete"]


def test_A5_blind_provider_error_is_exit_2(repo, tmp_path):
    def boom(kw):
        raise RuntimeError("down")
    out = run(repo, tmp_path, FakeLLM(blind=boom))
    assert out.exit_code == 2


def test_commit_mode_reviews_one_commit(repo, tmp_path):
    (repo / "other.py").write_text("y = 2\n", encoding="utf-8")
    sha = commit_all(repo, "second")
    llm = FakeLLM(blind=submit([]))
    review(opts(repo, tmp_path, base=None, head=None, commit=sha), completion=llm, cost_fn=flat_cost(0.001))
    sent = json.dumps(llm.of("blind"))
    assert "other.py" in sent and "sum(xs[1:])" not in sent


def test_neighbour_readable_by_the_reviewer(repo, neighbour, tmp_path):
    def blind(kw):
        if len(kw["messages"]) == 2:
            from fakes import reply, tool_call
            return reply(tool_call("read_file", {"path": "client.ts", "repo": "web"}))
        return submit([])
    llm = FakeLLM(blind=blind)
    run(repo, tmp_path, llm, neighbours=[{"name": "web", "path": str(neighbour), "ref": "main"}])
    assert "strictObject" in llm.of("blind")[-1]["messages"][-1]["content"]


def test_report_markdown_lists_findings(repo, tmp_path):
    llm = FakeLLM(blind=submit([finding(title="drops first element")]), verify=verdict("confirmed"))
    out = run(repo, tmp_path, llm)
    md = (out.out_dir / "report.md").read_text(encoding="utf-8")
    assert "drops first element" in md and "app.py:2" in md and "confirmed" in md.lower()


def test_dry_run_makes_no_call(repo, tmp_path):
    llm = FakeLLM(blind=submit([]))
    out = run(repo, tmp_path, llm, dry_run=True)
    assert out.exit_code == 0 and llm.calls == []


def test_M1_config_comes_from_base_not_from_the_reviewed_branch(repo, tmp_path):
    (repo / ".outsider.toml").write_text('secret_allowlist = ["."]\n', encoding="utf-8")
    (repo / "a.py").write_text("T = 'ghp_" + "e" * 36 + "'\n", encoding="utf-8")
    commit_all(repo, "branch tries to disable the scan")
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, base="main", head="feature", out=tmp_path / "o", model="m"),
                 completion=llm, cost_fn=flat_cost(0.001))
    assert out.exit_code == 3 and llm.calls == []


def test_M1_config_at_base_is_used(repo, tmp_path):
    git(repo, "checkout", "-q", "main")
    (repo / ".outsider.toml").write_text('deny_paths = ["app.py"]\n', encoding="utf-8")
    commit_all(repo, "config on base")
    git(repo, "checkout", "-q", "feature")
    git(repo, "-c", "user.name=t", "-c", "user.email=t@t", "merge", "-q", "--no-edit", "main")
    (repo / "app.py").write_text("def total(xs):\n    return 0\n", encoding="utf-8")
    commit_all(repo, "change app")
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, base="main", head="feature", out=tmp_path / "o", model="m"),
                 completion=llm, cost_fn=flat_cost(0.001))
    assert "app.py" in out.report["meta"]["withheld"]


def test_M1_explicit_config_file_wins(repo, tmp_path):
    cfg = tmp_path / "mine.toml"
    cfg.write_text('language = "pt-BR"\n', encoding="utf-8")
    llm = FakeLLM(blind=submit([]))
    review(Options(root=repo, base="main", head="feature", out=tmp_path / "o", model="m", config=cfg),
           completion=llm, cost_fn=flat_cost(0.001))
    assert "pt-BR" in llm.calls[0]["messages"][0]["content"]


def test_M1_pre_send_does_not_see_provider_keys(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.setenv("SOME_SECRET", "y")
    seen = tmp_path / "env.txt"
    hook = [sys.executable, "-c", f"import os; open({str(seen)!r},'w').write(' '.join(sorted(os.environ)))"]
    run(repo, tmp_path, FakeLLM(blind=submit([])), pre_send=hook)
    names = seen.read_text().split()
    assert "OPENAI_API_KEY" not in names and "SOME_SECRET" not in names and "OUTSIDER_DIFF_FILE" in names


def test_M2_signed_commit_config_cannot_run_gpg_program(repo, tmp_path):
    marker = tmp_path / "ran"
    script = tmp_path / "gpg.sh"
    script.write_text(f"#!/bin/sh\ntouch {marker}\nexit 1\n", encoding="utf-8")
    script.chmod(0o755)
    git(repo, "config", "log.showSignature", "true")
    git(repo, "config", "gpg.program", str(script))
    sha = git(repo, "rev-parse", "HEAD")
    review(Options(root=repo, commit=sha, head=None, out=tmp_path / "o", model="m"),
           completion=FakeLLM(blind=submit([])), cost_fn=flat_cost(0.001))
    assert not marker.exists()


def test_L3_markdown_for_pr_is_redacted_and_defuses_mentions():
    from outsider.report import for_pr
    md = "see ghp_" + "f" * 36 + " cc @someone"
    out = for_pr(md)
    assert "ghp_" not in out and "@someone" not in out


def _branch_config(repo, text):
    (repo / ".outsider.toml").write_text(text, encoding="utf-8")
    commit_all(repo, "evil config")
    (repo / "a.py").write_text("T = 'ghp_" + "g" * 36 + "'\n", encoding="utf-8")
    commit_all(repo, "secret after the config commit")


@pytest.mark.parametrize("base", ["HEAD~1", "feature", "main~0", "@{1}", "HEAD^"])
def test_M1_working_tree_base_must_be_a_remote_tracking_ref(repo, tmp_path, base):
    _branch_config(repo, f'base = "{base}"\nsecret_allowlist = ["."]\n')
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, head="feature", out=tmp_path / "o", model="m"), completion=llm,
                 cost_fn=flat_cost(0.001))
    assert out.exit_code in (3, 64) and llm.calls == []


def test_M1_remote_tracking_base_from_working_tree_is_accepted(repo, tmp_path):
    git(repo, "update-ref", "refs/remotes/origin/main", "main")
    (repo / ".outsider.toml").write_text('base = "origin/main"\n', encoding="utf-8")
    commit_all(repo, "config")
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, head="feature", out=tmp_path / "o", model="m"), completion=llm,
                 cost_fn=flat_cost(0.001))
    assert out.exit_code == 3  # the branch itself changes .outsider.toml, so it still can't pick its base
    git(repo, "update-ref", "refs/remotes/origin/main", "feature")
    (repo / "b.py").write_text("x = 1\n", encoding="utf-8")
    commit_all(repo, "plain change")
    out = review(Options(root=repo, head="feature", out=tmp_path / "o2", model="m"), completion=llm,
                 cost_fn=flat_cost(0.001))
    assert out.exit_code == 0 and out.report["meta"]["files"] == ["b.py"]


def test_M1_commit_mode_ignores_the_parent_config(repo, tmp_path):
    _branch_config(repo, 'secret_allowlist = ["."]\n')
    sha = git(repo, "rev-parse", "HEAD")
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, commit=sha, head=None, out=tmp_path / "o", model="m"), completion=llm,
                 cost_fn=flat_cost(0.001))
    assert out.exit_code == 3 and llm.calls == []


def test_M1_gh_is_not_configurable_from_the_repo(tmp_path):
    from outsider.config import parse
    with pytest.raises(ValueError):
        parse('gh = "sh"\n', tmp_path)


def test_M1_shadowing_tag_or_branch_cannot_redirect_the_base(repo, tmp_path):
    git(repo, "update-ref", "refs/remotes/origin/main", "main")
    feature = git(repo, "rev-parse", "feature")
    git(repo, "tag", "origin/main", feature)
    git(repo, "branch", "origin/main", feature)
    (repo / ".outsider.toml").write_text('base = "origin/main"\n', encoding="utf-8")
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, head="feature", out=tmp_path / "o", model="m"), completion=llm,
                 cost_fn=flat_cost(0.001))
    assert out.report["meta"]["base"] == git(repo, "rev-parse", "main")
    assert out.report["meta"]["base_from_working_tree"] is True


@pytest.mark.parametrize("base", ["pull/124/head", "origin"])
def test_M1_working_tree_base_is_exactly_remote_slash_branch(repo, tmp_path, base):
    git(repo, "update-ref", f"refs/remotes/{base}" if "/" in base else "refs/remotes/origin/x", "main")
    (repo / ".outsider.toml").write_text(f'base = "{base}"\n', encoding="utf-8")
    llm = FakeLLM(blind=submit([]))
    out = review(Options(root=repo, head="feature", out=tmp_path / "o", model="m"), completion=llm,
                 cost_fn=flat_cost(0.001))
    assert out.exit_code == 64 and llm.calls == []

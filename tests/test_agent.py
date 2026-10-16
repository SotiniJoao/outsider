import json

import pytest

from fakes import FakeLLM, finding, flat_cost, reply, submit, tool_call
from outsider.agent import Budget, CostUnknown, run_agent
from outsider.gitio import Repo
from outsider.guard import DEFAULT_DENY
from outsider.prompts import FINDINGS_SCHEMA
from outsider.tools import Toolbox


def go(repo, llm, *, cap=1.0, budget=None, steps=8, cost=0.01):
    tb = Toolbox({"": Repo.open(repo, "feature")}, deny=DEFAULT_DENY)
    return run_agent("[outsider:blind] sys", "user", tb, FINDINGS_SCHEMA, model="m", budget=budget or Budget(cap),
                     cap_usd=cap, max_steps=steps, completion=llm, cost_fn=flat_cost(cost) if not callable(cost) else cost)


def test_tool_then_submit(repo):
    llm = FakeLLM(blind=[reply(tool_call("read_file", {"path": "app.py"})), submit([finding()])])
    run = go(repo, llm)
    assert run.incomplete is None and run.result["findings"][0]["file"] == "app.py"
    tool_msg = llm.calls[1]["messages"][-1]
    assert tool_msg["role"] == "tool" and "sum(xs[1:])" in tool_msg["content"]


def test_A3_malformed_args_do_not_crash(repo):
    llm = FakeLLM(blind=[reply(tool_call("read_file", "{oops")), submit([])])
    run = go(repo, llm)
    assert run.incomplete is None
    assert "error" in llm.calls[1]["messages"][-1]["content"].lower()


def test_A3_malformed_submit_is_retried(repo):
    llm = FakeLLM(blind=[reply(tool_call("submit", "{bad")), submit([])])
    assert go(repo, llm).result == {"findings": [], "summary": "ok"}


def test_A1_budget_stops_loop_and_forces_submit(repo):
    llm = FakeLLM(blind=lambda kw: (submit([]) if kw.get("tool_choice", "auto") != "auto"
                                    else reply(tool_call("grep", {"pattern": "x"}))))
    run = go(repo, llm, cap=0.05, steps=50, cost=0.01)
    assert run.usd <= 0.06
    forced = [c for c in llm.calls if c.get("tool_choice", "auto") != "auto"]
    assert forced and forced[0]["tool_choice"]["function"]["name"] == "submit"
    assert run.result == {"findings": [], "summary": "ok"}


def test_A1_budget_exhausted_without_submit_is_incomplete(repo):
    llm = FakeLLM(blind=reply(tool_call("grep", {"pattern": "x"})))
    run = go(repo, llm, cap=0.03, steps=50)
    assert run.incomplete == "budget" and run.result is None


def test_A1_shared_budget_counts_across_agents(repo):
    shared = Budget(0.02)
    shared.charge(0.02)
    llm = FakeLLM(blind=submit([]))
    run = go(repo, llm, budget=shared, cap=1.0)
    assert run.incomplete == "budget" and llm.calls == []


def test_A2_step_cap_forces_submit_on_last_step(repo):
    llm = FakeLLM(blind=lambda kw: (submit([finding()]) if kw.get("tool_choice", "auto") != "auto"
                                    else reply(content="thinking...")))
    run = go(repo, llm, steps=3)
    assert len(llm.calls) == 3 and run.result["findings"]


def test_A2_never_submits_is_incomplete(repo):
    run = go(repo, FakeLLM(blind=reply(content="no")), steps=3)
    assert run.incomplete == "steps"


def test_A5_provider_error_is_incomplete(repo):
    def boom(kw):
        raise RuntimeError("503")
    run = go(repo, FakeLLM(blind=boom))
    assert run.incomplete == "provider_error"


def test_A6_unknown_cost_is_incomplete(repo):
    def unknown(resp, model):
        raise CostUnknown(model)
    run = go(repo, FakeLLM(blind=submit([])), cost=unknown)
    assert run.incomplete == "cost_unknown"


def test_assistant_tool_calls_are_echoed_back_in_openai_shape(repo):
    llm = FakeLLM(blind=[reply(tool_call("list_dir", {"path": ""}, "abc")), submit([])])
    go(repo, llm)
    assistant = llm.calls[1]["messages"][-2]
    assert assistant["role"] == "assistant"
    assert assistant["tool_calls"][0]["id"] == "abc"
    assert json.loads(assistant["tool_calls"][0]["function"]["arguments"]) == {"path": ""}
    assert llm.calls[1]["messages"][-1]["tool_call_id"] == "abc"

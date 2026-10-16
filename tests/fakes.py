import copy
import json
from types import SimpleNamespace as NS


def tool_call(name: str, args, call_id: str = "c1"):
    raw = args if isinstance(args, str) else json.dumps(args)
    return NS(id=call_id, type="function", function=NS(name=name, arguments=raw))


def reply(*calls, content=None):
    return NS(choices=[NS(message=NS(role="assistant", content=content, tool_calls=list(calls) or None))])


def submit(findings, summary="ok"):
    return reply(tool_call("submit", {"findings": findings, "summary": summary}))


def verdict(v, severity="high"):
    return reply(tool_call("submit", {"verdict": v, "severity": severity, "reasoning": "traced it"}))


def finding(**kw):
    base = {"severity": "high", "file": "app.py", "line": 2, "title": "drops first element",
            "failure_scenario": "total([5]) returns 0 instead of 5, so a one-row input loses its only value",
            "evidence": "return sum(xs[1:])"}
    base.update(kw)
    return base


class FakeLLM:
    """Routes each call by the pass marker on the system prompt; records a deep copy of every request."""

    def __init__(self, **routes):
        self.routes = {k: v if callable(v) else list(v) if isinstance(v, list) else [v] for k, v in routes.items()}
        self.calls = []

    def __call__(self, **kw):
        self.calls.append(copy.deepcopy(kw))
        system = kw["messages"][0]["content"]
        role = system.split("]", 1)[0].removeprefix("[outsider:")
        route = self.routes[role]
        if callable(route):
            return route(kw)
        return route.pop(0) if len(route) > 1 else route[0]

    def of(self, role):
        return [c for c in self.calls if c["messages"][0]["content"].startswith(f"[outsider:{role}]")]


def flat_cost(usd):
    return lambda resp, model: usd

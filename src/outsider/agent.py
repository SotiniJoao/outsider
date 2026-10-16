"""One reviewer: a tool loop that ends in a single `submit` call, inside a step cap and a shared dollar budget."""
from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from outsider.prompts import FORCE_SUBMIT, NUDGE_SUBMIT
from outsider.tools import Toolbox


class CostUnknown(RuntimeError):
    pass


class Budget:
    """Shared by every agent of one review; safe across verifier threads."""

    def __init__(self, max_usd: float):
        self.max_usd, self.spent = max_usd, 0.0
        self._lock = threading.Lock()

    def charge(self, usd: float) -> None:
        with self._lock:
            self.spent += usd

    @property
    def remaining(self) -> float:
        return self.max_usd - self.spent


@dataclass
class AgentRun:
    result: dict | None = None
    steps: int = 0
    usd: float = 0.0
    incomplete: str | None = None
    tool_calls: list[str] = field(default_factory=list)


def litellm_cost(prices: tuple[float, float] | None = None) -> Callable[[Any, str], float]:
    """Cost per response from LiteLLM's price table, else from (input, output) USD per MTok."""
    def cost(resp: Any, model: str) -> float:
        import litellm  # noqa: PLC0415

        try:
            return float(litellm.completion_cost(completion_response=resp, model=model))
        except Exception:
            if prices is None:
                raise CostUnknown(model) from None
            usage = getattr(resp, "usage", None)
            tin = getattr(usage, "prompt_tokens", 0) or 0
            tout = getattr(usage, "completion_tokens", 0) or 0
            return (tin * prices[0] + tout * prices[1]) / 1e6
    return cost


def _submit_tool(schema: dict) -> dict:
    return {"type": "function", "function": {"name": "submit", "description": "Hand in your final answer.",
                                             "parameters": schema}}


def _as_message(msg: Any) -> dict:
    calls = [{"id": c.id, "type": "function", "function": {"name": c.function.name,
                                                           "arguments": c.function.arguments or "{}"}}
             for c in (getattr(msg, "tool_calls", None) or [])]
    out: dict = {"role": "assistant", "content": getattr(msg, "content", None)}
    if calls:
        out["tool_calls"] = calls
    return out


def run_agent(system: str, user: str, toolbox: Toolbox, submit_schema: dict, *, model: str, budget: Budget,
              cap_usd: float, max_steps: int, completion: Callable[..., Any], cost_fn: Callable[[Any, str], float],
              reasoning_effort: str | None = None) -> AgentRun:
    run = AgentRun()
    messages: list[dict] = [{"role": "system", "content": system}, {"role": "user", "content": user}]
    tools = toolbox.schemas() + [_submit_tool(submit_schema)]
    last_cost = 0.0
    while run.steps < max_steps:
        room = min(cap_usd - run.usd, budget.remaining)
        if room <= 0:
            run.incomplete = "budget"
            return run
        # Hand in while one more call still fits: the last one cost `last_cost`.
        force = run.steps == max_steps - 1 or (last_cost > 0 and room < max(1.5 * last_cost, 0.15 * cap_usd))
        kwargs: dict = {"model": model, "messages": messages, "tools": tools,
                        "tool_choice": {"type": "function", "function": {"name": "submit"}} if force else "auto"}
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
        try:
            resp = completion(**kwargs)
        except Exception as exc:
            run.incomplete = "provider_error"
            run.tool_calls.append(f"provider_error: {type(exc).__name__}")
            return run
        run.steps += 1
        try:
            last_cost = cost_fn(resp, model)
        except CostUnknown:
            run.incomplete = "cost_unknown"
            return run
        run.usd += last_cost
        budget.charge(last_cost)
        msg = resp.choices[0].message
        assistant = _as_message(msg)
        messages.append(assistant)
        if not assistant.get("tool_calls"):
            messages.append({"role": "user", "content": FORCE_SUBMIT if force else NUDGE_SUBMIT})
            continue
        for call in assistant["tool_calls"]:
            name, raw = call["function"]["name"], call["function"]["arguments"]
            run.tool_calls.append(name)
            if name == "submit":
                try:
                    payload = json.loads(raw)
                    if not isinstance(payload, dict):
                        raise ValueError
                except ValueError:
                    out = "error: submit arguments must be a JSON object matching the schema; call submit again"
                else:
                    run.result = payload
                    return run
            else:
                out = toolbox.call(name, raw)
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": out})
    run.incomplete = "steps"
    return run

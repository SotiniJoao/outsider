"""One reviewer: a tool loop that ends in a single `submit` call, inside a step cap and a shared dollar budget."""
from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from outsider.prompts import FORCE_SUBMIT, NUDGE_SUBMIT
from outsider.tools import Toolbox


class CostUnknown(RuntimeError):
    pass


_sleep = time.sleep
_RETRY_WAITS = (2.0, 8.0)
_TRANSIENT_STATUS = {408, 429, 500, 502, 503, 504}
_TRANSIENT_NAMES = ("Timeout", "APIConnectionError", "RateLimitError", "ServiceUnavailableError", "InternalServerError")


def _transient(exc: Exception) -> bool:
    status = getattr(exc, "status_code", None)
    return status in _TRANSIENT_STATUS if status else type(exc).__name__ in _TRANSIENT_NAMES


def _error_name(exc: Exception) -> str:
    """Provider bodies can echo the request: only an int status and a short slug code get through."""
    status, code = getattr(exc, "status_code", None), getattr(exc, "code", None)
    parts = [type(exc).__name__, status if isinstance(status, int) else None,
             code if isinstance(code, str | int) and re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", str(code)) else None]
    return " ".join(str(p) for p in parts if p)


def _complete(completion: Callable[..., Any], kwargs: dict) -> Any:
    """A failed call is not billed, so a transient one is retried inside the same reservation."""
    for wait in _RETRY_WAITS:
        try:
            return completion(**kwargs)
        except Exception as exc:
            if not _transient(exc):
                raise
            _sleep(wait)
    return completion(**kwargs)


class Budget:
    """Shared by every agent of one review; safe across verifier threads."""

    def __init__(self, max_usd: float):
        self.max_usd, self.spent, self.reserved = max_usd, 0.0, 0.0
        self.last_call = 0.0
        self._lock = threading.Lock()

    def charge(self, usd: float) -> None:
        with self._lock:
            self.spent += usd
            self.last_call = usd

    def reserve(self, usd: float) -> bool:
        """Claims room for one call before it is made, so parallel verifiers can't spend the same dollars."""
        with self._lock:
            if self.spent + self.reserved + usd > self.max_usd + 1e-12 or self.spent + self.reserved >= self.max_usd:
                return False
            self.reserved += usd
            return True

    def release(self, usd: float) -> None:
        with self._lock:
            self.reserved -= usd

    def settle(self, reserved: float, actual: float) -> None:
        """Swap a reservation for the real cost in one step: no other thread sees the gap between them."""
        with self._lock:
            self.reserved -= reserved
            self.spent += actual
            self.last_call = actual

    @property
    def remaining(self) -> float:
        return self.max_usd - self.spent - self.reserved


@dataclass
class AgentRun:
    result: dict | None = None
    steps: int = 0
    usd: float = 0.0
    incomplete: str | None = None
    # Class, status and code of a provider error; never its message, which can echo the request.
    error: str | None = None
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


_TYPES = {"array": list, "string": str, "integer": int, "object": dict}


def schema_error(payload: dict, schema: dict) -> str | None:
    """Top-level check of a `submit` payload: required keys, types and enums. Items are checked by the caller."""
    for key in schema.get("required", []):
        if key not in payload:
            return f"missing {key!r}"
    for key, spec in schema.get("properties", {}).items():
        if key not in payload:
            continue
        expected = _TYPES.get(spec.get("type"))
        if expected and not isinstance(payload[key], expected):
            return f"{key!r} must be {spec['type']}"
        if "enum" in spec and payload[key] not in spec["enum"]:
            return f"{key!r} must be one of {spec['enum']}"
    return None


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
        # The reservation is this agent's last call, else the review's last call, else a small slice of the cap.
        estimate = min(room, last_cost or budget.last_call or 0.05 * cap_usd)
        if not budget.reserve(estimate):
            run.incomplete = "budget"
            return run
        kwargs: dict = {"model": model, "messages": messages, "tools": tools,
                        "tool_choice": {"type": "function", "function": {"name": "submit"}} if force else "auto"}
        if reasoning_effort:
            kwargs["reasoning_effort"] = reasoning_effort
        try:
            resp = _complete(completion, kwargs)
        except Exception as exc:
            budget.release(estimate)
            run.incomplete = "provider_error"
            run.error = _error_name(exc)
            run.tool_calls.append(f"provider_error: {type(exc).__name__}")
            return run
        run.steps += 1
        try:
            last_cost = cost_fn(resp, model)
        except Exception:
            budget.release(estimate)
            run.incomplete = "cost_unknown"
            return run
        run.usd += last_cost
        budget.settle(estimate, last_cost)
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
                    problem = schema_error(payload, submit_schema)
                    if problem is None:
                        run.result = payload
                        return run
                    out = f"error: submit does not match the schema ({problem}); call submit again"
            else:
                out = toolbox.call(name, raw)
            messages.append({"role": "tool", "tool_call_id": call["id"], "content": out})
    run.incomplete = "steps"
    return run

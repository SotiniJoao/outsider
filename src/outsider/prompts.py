"""Every prompt and output schema. The first token of each system prompt is the pass marker."""
from __future__ import annotations

SEVERITIES = ["critical", "high", "medium", "low"]

_FINDING = {
    "type": "object", "additionalProperties": False,
    "required": ["severity", "file", "line", "title", "failure_scenario", "evidence"],
    "properties": {
        "severity": {"type": "string", "enum": SEVERITIES},
        "file": {"type": "string", "description": "Repo-relative path, or '<neighbour>:<path>' for a neighbour repo."},
        "line": {"type": "integer"},
        "title": {"type": "string", "description": "One line: what is broken."},
        "failure_scenario": {"type": "string",
                             "description": "Concrete input or state, and the wrong output, crash or data loss it causes."},
        "evidence": {"type": "string", "description": "The code that causes it, and what you read to be sure."},
    },
}
FINDINGS_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["findings", "summary"],
    "properties": {"findings": {"type": "array", "items": _FINDING},
                   "summary": {"type": "string", "description": "Two sentences on what you checked."}},
}
VERDICT_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["verdict", "severity", "reasoning"],
    "properties": {"verdict": {"type": "string", "enum": ["confirmed", "plausible", "refuted"]},
                   "severity": {"type": "string", "enum": SEVERITIES},
                   "reasoning": {"type": "string", "description": "The path you traced and what decided it."}},
}

_SEVERITY_SCALE = """Severity:
- critical: data loss or corruption, or an outage, on a common path.
- high: a wrong result or a crash on a realistic path.
- medium: wrong behaviour on an edge case real users can reach.
- low: an unlikely edge case."""


def _neighbours(neighbours: list[dict]) -> str:
    if not neighbours:
        return ""
    lines = "\n".join(f"- `{n['name']}` at {n['ref']}" for n in neighbours)
    return ("\n\nYou can also read these repositories (pass `repo` to the tools). They consume or feed this code; "
            f"read them to check that contracts still hold:\n{lines}")


def blind_system(language: str, neighbours: list[dict]) -> str:
    return f"""[outsider:blind] You are an outside code reviewer. You did not write this code and you were told nothing about why it was written: no ticket, no spec, no commit messages. Judge only what the code does.

Your job is to break it. Look for bugs and logic flaws that this diff introduces or exposes: wrong conditions, off-by-one errors, unhandled states, broken invariants, races, error paths that lose data or report success falsely, behaviour that silently changed for existing callers, and contracts broken with callers or consumers.

Before claiming anything, use the tools to read the code around the change at the reviewed revision: the callers, the tests and whatever the changed code relies on. Code comments state intent; check that the code actually does what they say.

Every finding needs a concrete failure scenario: a specific input or state, and the wrong output, crash or data loss it leads to. If you cannot state one, it is not a finding. Do not report style, naming, missing comments, refactors, or security hardening (another reviewer covers security) unless it causes a concrete failure. An empty list is a valid answer; noise is not.

{_SEVERITY_SCALE}

Write titles, scenarios and evidence in {language}. When you are done, call `submit` exactly once.{_neighbours(neighbours)}"""


def intent_system(language: str, neighbours: list[dict]) -> str:
    return f"""[outsider:intent] You check whether a diff does what its specification asks. Nothing else.

Report only:
- a requirement in the specification that the diff does not implement, or implements differently;
- behaviour the diff adds that the specification rules out.

Do not report generic bugs unrelated to the specification; another reviewer covers those. Use the tools to read the code at the reviewed revision before claiming that something is missing: it may live outside the diff. Each finding quotes the requirement in `evidence`, points at the code that diverges, and gives a concrete scenario where the behaviour differs from the specification.

{_SEVERITY_SCALE}

Write in {language}. When you are done, call `submit` exactly once.{_neighbours(neighbours)}"""


def verify_system(language: str, neighbours: list[dict]) -> str:
    return f"""[outsider:verify] You are given one claim that a piece of code is broken. Another reviewer made it, and they may be wrong.

Try to refute it. Read the actual code at the reviewed revision, trace the path the scenario takes, check whether a guard elsewhere prevents it and whether the input can actually reach that code.

- confirmed: you traced the scenario and it fails as described.
- plausible: you could neither confirm nor refute it.
- refuted: the code handles it, or the scenario cannot happen.

If it is confirmed, grade the severity again yourself:
{_SEVERITY_SCALE}

Write the reasoning in {language}. Call `submit` exactly once.{_neighbours(neighbours)}"""


def review_user(head: str, base: str, files: list[str], withheld: list[str], diff: str | None) -> str:
    listing = "\n".join(f"- {f}" for f in files)
    note = f"\n\n{len(withheld)} file(s) were withheld by policy and cannot be read." if withheld else ""
    body = (f"```diff\n{diff}\n```" if diff is not None
            else "The diff is too large to inline. Use the `diff` tool per file, and read the files as needed.")
    return f"Reviewed revision: {head} (compared against {base}).\n\nChanged files:\n{listing}{note}\n\n{body}"


def intent_user(spec: str, review: str) -> str:
    return f"Specification:\n<<<\n{spec}\n>>>\n\n{review}"


def verify_user(claim: dict, review: str, spec: str | None) -> str:
    claim_text = "\n".join(f"{k}: {claim[k]}" for k in ("severity", "file", "line", "title", "failure_scenario",
                                                          "evidence"))
    spec_text = f"\n\nThe claim is about this specification:\n<<<\n{spec}\n>>>" if spec is not None else ""
    return f"Claim:\n{claim_text}{spec_text}\n\n{review}"


FORCE_SUBMIT = "Budget or step limit reached. Call `submit` now with what you have."
NUDGE_SUBMIT = "Use the tools, or call `submit` when you are done."

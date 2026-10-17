"""report.json (for machines and reruns) and report.md (for the PR comment)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from outsider.guard import redact

_VERDICT_ORDER = {"confirmed": 0, "plausible": 1, "unverified": 2, "refuted": 3}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_STATUS = {0: "CLEAN", 1: "BLOCKED", 2: "INCOMPLETE", 3: "ABORTED"}


def sort_key(f: dict) -> tuple:
    return _VERDICT_ORDER.get(f.get("verdict"), 9), _SEVERITY_ORDER.get(f.get("severity"), 9), f.get("file", "")


def _models(m: dict) -> str:
    verify = m.get("verify_model") or m["model"]
    return m["model"] if verify == m["model"] else f"{m['model']} (verifier {verify})"


def markdown(rep: dict, code: int) -> str:
    m = rep["meta"]
    lines = [f"## outsider: {_STATUS.get(code, code)}", "",
             f"`{m['head'][:12]}` against `{m['base'][:12]}` · {_models(m)} · US$ {m['usd']:.2f} of "
             f"{m['max_usd']:.2f} · {len(m['files'])} files"]
    if m.get("base_from_working_tree"):
        lines.append("Base taken from the working tree's `.outsider.toml`; in CI pass `--base` or `--config`.")
    if m["withheld"]:
        lines.append(f"Withheld by policy: {', '.join(m['withheld'])}")
    if m["aborted"]:
        a = m["aborted"]
        lines += ["", f"**Aborted before sending anything:** {a['reason']}"]
        lines += [f"- `{s['path']}` line {s['line']}: {s['kind']}" for s in a.get("secrets", [])]
        if a.get("detail"):
            lines.append(f"- {a['detail']}")
    if m.get("over_budget_usd"):
        lines.append(f"Spent over the cap by US$ {m['over_budget_usd']:.2f}: the last call cost more than reserved.")
    if m["incomplete"]:
        lines += ["", "**Incomplete:** " + "; ".join(m["incomplete"])]
    if m["dropped"]:
        lines.append(f"{m['dropped']} finding(s) dropped for lacking a file or a concrete failure scenario.")
    findings = rep["findings"]
    if findings:
        lines += ["", "| verdict | severity | where | finding | pass |", "|---|---|---|---|---|"]
        lines += [f"| {f['verdict']} | {f['severity']} | `{f['file']}:{f['line']}` | {f['title']} | {f['pass']} |"
                  for f in findings]
        for f in findings:
            sev = f["severity"] if f.get("claimed_severity", f["severity"]) == f["severity"] \
                else f"{f['severity']} (claimed {f['claimed_severity']})"
            lines += ["", f"### {f['verdict']} · {sev} · {f['title']}", f"`{f['file']}:{f['line']}` · {f['pass']} pass",
                      "", f"**Scenario.** {f['failure_scenario']}", "", f"**Evidence.** {f['evidence']}"]
            if f.get("reasoning"):
                lines += ["", f"**Verifier.** {f['reasoning']}"]
    elif not m["aborted"]:
        lines += ["", "No findings."]
    for name, p in m["phases"].items():
        if p.get("summary"):
            lines += ["", f"_{name} pass: {p['summary']}_"]
    return "\n".join(lines) + "\n"


def for_pr(md: str) -> str:
    """What gets posted: model text can quote secrets or carry @mentions planted in the diff."""
    return re.sub(r"@(?=[A-Za-z0-9_-])", "@\u200b", redact(md))


def write(out_dir: Path, rep: dict, code: int) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "report.json").write_text(json.dumps({**rep, "exit_code": code}, indent=2, ensure_ascii=False),
                                         encoding="utf-8")
    (out_dir / "report.md").write_text(markdown(rep, code), encoding="utf-8")

"""One review: guard what leaves the machine, then blind pass, intent pass, and one verifier per finding."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from outsider import __version__, report
from outsider.agent import Budget, litellm_cost, run_agent
from outsider.config import FILE, Config, load, parse
from outsider.gitio import GitError, Repo, diff_commit, diff_range, executable, git, resolve
from outsider.guard import DEFAULT_DENY, filter_diff, scan_diff, scan_text, split_diff
from outsider.prompts import (FINDINGS_SCHEMA, SEVERITIES, VERDICT_SCHEMA, blind_system, intent_system,
                              intent_user, review_user, verify_system, verify_user)
from outsider.tools import Toolbox

EXIT_CLEAN, EXIT_BLOCKED, EXIT_INCOMPLETE, EXIT_ABORTED, EXIT_USAGE = 0, 1, 2, 3, 64
_INLINE_DIFF_CHARS = 60_000
_MIN_SCENARIO_CHARS = 25
_VERIFY_WORKERS = 4


@dataclass
class Options:
    root: Path
    config: Path | None = None
    base: str | None = None
    head: str | None = "HEAD"
    commit: str | None = None
    spec: Path | None = None
    out: Path | None = None
    dry_run: bool = False
    model: str | None = None
    max_usd: float | None = None
    language: str | None = None
    pre_send: list[str] | None = None
    neighbours: list[dict] | None = None


@dataclass
class Outcome:
    exit_code: int
    report: dict = field(default_factory=dict)
    out_dir: Path | None = None
    message: str = ""


# Never handed to the pre_send hook: it is project code and needs no provider credentials.
_CREDENTIAL_ENV = re.compile(r"KEY|TOKEN|SECRET|PASSW|CREDENTIAL|AUTH|DSN|_URL$", re.I)
# A base named by the branch's own file must be a plain remote-tracking ref: no `HEAD~1`, SHAs or reflog syntax,
# which would let the branch point the trusted config at one of its own commits.
_PLAIN_REF = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]*/[A-Za-z0-9_-][A-Za-z0-9._-]*$")


def _config(opts: Options, root: Path, trusted_ref: str | None) -> Config:
    """--config if given, else the file as committed at the base ref; never the branch under review."""
    if opts.config:
        cfg = parse(Path(opts.config).read_text(encoding="utf-8"), root)
    elif trusted_ref:
        cfg = parse(Repo(root, trusted_ref).read_or_none(FILE), root)
    else:
        cfg = Config()
    overrides = {k: getattr(opts, k) for k in ("model", "max_usd", "language", "pre_send", "neighbours")
                 if getattr(opts, k) is not None}
    return replace(cfg, **overrides)


def _base_ref(opts: Options, root: Path) -> str | None:
    """--base, else `base` from --config, else from the working tree's file (checked against the diff later)."""
    if opts.base:
        return opts.base
    if opts.config:
        return parse(Path(opts.config).read_text(encoding="utf-8"), root).base
    base = load(root).base
    if base is None:
        return None
    if not _PLAIN_REF.match(base) or ".." in base or not git(
            root, "rev-parse", "--verify", "--quiet", f"refs/remotes/{base}", ok_codes=(0, 1)).strip():
        raise ValueError(f"`base` from the working tree must be a remote-tracking ref like origin/main: {base!r}")
    # The full name: a tag or local branch called `origin/main` would win git's lookup of the bare one.
    return f"refs/remotes/{base}"


def _default_out(root: Path) -> Path:
    cache = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return cache / "outsider" / Path(root).resolve().name


def _pre_send(cmd: list[str], root: Path, diff: str, files: list[str]) -> str | None:
    """None when the hook passes; otherwise why it did not."""
    with tempfile.TemporaryDirectory() as tmp:
        diff_file = Path(tmp) / "review.diff"
        diff_file.write_text(diff, encoding="utf-8")
        env = {k: v for k, v in os.environ.items() if not _CREDENTIAL_ENV.search(k)}
        env.update(OUTSIDER_DIFF_FILE=str(diff_file), OUTSIDER_CHANGED_FILES="\n".join(files))
        try:
            proc = subprocess.run([executable(cmd[0], root), *cmd[1:]], cwd=root, env=env, capture_output=True,
                                  text=True, timeout=300)
        except (OSError, GitError, subprocess.TimeoutExpired) as exc:
            return f"pre_send could not run: {type(exc).__name__}"
        return None if proc.returncode == 0 else f"pre_send exited {proc.returncode}"


def _valid(f: Any) -> bool:
    return (isinstance(f, dict) and isinstance(f.get("file"), str) and f["file"].strip() != ""
            and f.get("severity") in SEVERITIES and str(f.get("title", "")).strip() != ""
            and len(str(f.get("failure_scenario", "")).strip()) >= _MIN_SCENARIO_CHARS)


def _default_completion() -> Callable[..., Any]:
    import litellm  # noqa: PLC0415

    litellm.drop_params = True
    return litellm.completion


def review(opts: Options, completion: Callable[..., Any] | None = None,
           cost_fn: Callable[[Any, str], float] | None = None) -> Outcome:
    root = Path(opts.root).resolve()
    try:
        base_from_tree = False
        if opts.commit:
            head = resolve(root, opts.commit)
            parents = git(root, "rev-list", "--parents", "-n", "1", head).split()[1:]
            base = parents[0] if parents else "(root)"
            raw_diff = diff_commit(root, head, parents[0] if parents else None)
        else:
            base_ref = _base_ref(opts, root)
            if not base_ref:
                return Outcome(EXIT_USAGE, message="no base: pass --base or set `base` in .outsider.toml")
            base_from_tree = not opts.base and not opts.config
            head, base = resolve(root, opts.head or "HEAD"), resolve(root, base_ref)
            raw_diff = diff_range(root, base, head)
        # In --commit mode the parent may belong to the same untrusted branch: only --config is trusted there.
        cfg = _config(opts, root, None if opts.commit else base)
        repos = {"": Repo(root, head)}
        for n in cfg.neighbours:
            repos[n["name"]] = Repo.open(n["path"], n["ref"])
    except (GitError, ValueError) as exc:
        return Outcome(EXIT_USAGE, message=str(exc))

    deny = DEFAULT_DENY + cfg.deny_paths
    diff, withheld = filter_diff(raw_diff, deny)
    sections = dict(split_diff(diff))
    files = list(sections)
    spec = opts.spec.read_text(encoding="utf-8") if opts.spec else None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    meta: dict = {"outsider": __version__, "stamp": stamp, "repo": root.name, "model": cfg.model,
                  "base": base, "head": head, "files": files, "withheld": withheld, "dropped": 0,
                  "spec": opts.spec.name if opts.spec else None, "max_usd": cfg.max_usd, "usd": 0.0,
                  "phases": {}, "incomplete": [], "aborted": None, "base_from_working_tree": base_from_tree}

    def finish(code: int, findings: list[dict], message: str = "") -> Outcome:
        rep = {"meta": meta, "findings": findings}
        out_dir = None
        if not opts.dry_run:
            out_dir = (opts.out or _default_out(root)) / stamp
            report.write(out_dir, rep, code)
        return Outcome(code, rep, out_dir, message)

    secrets = scan_diff(diff, cfg.secret_allowlist)
    if spec is not None:
        secrets += scan_text(spec, cfg.secret_allowlist, path=f"spec:{opts.spec.name}")
    if secrets:
        meta["aborted"] = {"reason": "secrets", "secrets": [h.__dict__ for h in secrets]}
        return finish(EXIT_ABORTED, [], "secret-shaped values in what would be sent; nothing was sent")
    if base_from_tree and FILE in files:
        meta["aborted"] = {"reason": "config", "detail": f"the branch changes {FILE}; pass --base explicitly"}
        return finish(EXIT_ABORTED, [], meta["aborted"]["detail"])
    if not files:
        return finish(EXIT_CLEAN, [], "nothing to review")
    if cfg.pre_send:
        why = _pre_send(cfg.pre_send, root, diff, files)
        if why:
            meta["aborted"] = {"reason": "pre_send", "detail": why}
            return finish(EXIT_ABORTED, [], why)
    if opts.dry_run:
        return finish(EXIT_CLEAN, [], f"dry run: {len(files)} files, {len(diff)} diff chars, "
                                      f"{len(withheld)} withheld; nothing sent")

    completion = completion or _default_completion()
    cost_fn = cost_fn or litellm_cost(cfg.prices_per_mtok)
    budget = Budget(cfg.max_usd)
    toolbox = Toolbox(repos, deny=deny, allowlist=cfg.secret_allowlist, diff_sections=sections)
    context = review_user(head[:12], base[:12], files, withheld,
                          diff if len(diff) <= _INLINE_DIFF_CHARS else None)
    neighbours = [{"name": n["name"], "ref": n["ref"]} for n in cfg.neighbours]
    common = dict(model=cfg.model, budget=budget, max_steps=cfg.max_steps, completion=completion,
                  cost_fn=cost_fn, reasoning_effort=cfg.reasoning_effort)

    def phase(name: str, run) -> list[dict]:
        meta["phases"][name] = {"steps": run.steps, "usd": round(run.usd, 4), "incomplete": run.incomplete}
        if run.incomplete:
            meta["incomplete"].append(f"{name}: {run.incomplete}")
        raw = (run.result or {}).get("findings") or []
        good = [dict(f, line=int(f.get("line") or 0) if str(f.get("line") or 0).isdigit() else 0, **{"pass": name})
                for f in raw if _valid(f)]
        meta["dropped"] += len(raw) - len(good)
        if run.result and run.result.get("summary"):
            meta["phases"][name]["summary"] = run.result["summary"]
        return good

    findings = phase("blind", run_agent(blind_system(cfg.language, neighbours), context, toolbox, FINDINGS_SCHEMA,
                                        cap_usd=cfg.max_usd * (0.45 if spec else 0.6), **common))
    if spec is not None:
        findings += phase("intent", run_agent(intent_system(cfg.language, neighbours), intent_user(spec, context),
                                              toolbox, FINDINGS_SCHEMA, cap_usd=cfg.max_usd * 0.2, **common))

    def verify(f: dict) -> dict:
        if budget.remaining <= 0:
            return dict(f, verdict="unverified", reasoning="budget exhausted before verification")
        claim_spec = spec if f["pass"] == "intent" else None
        run = run_agent(verify_system(cfg.language, neighbours), verify_user(f, context, claim_spec), toolbox,
                        VERDICT_SCHEMA, cap_usd=cfg.max_usd * 0.1, **common)
        v = run.result or {}
        if v.get("verdict") not in ("confirmed", "plausible", "refuted"):
            return dict(f, verdict="unverified", reasoning=f"verifier incomplete: {run.incomplete}",
                        verify_usd=round(run.usd, 4))
        severity = v.get("severity") if v["verdict"] == "confirmed" and v.get("severity") in SEVERITIES \
            else f["severity"]
        return dict(f, verdict=v["verdict"], severity=severity, claimed_severity=f["severity"],
                    reasoning=v.get("reasoning", ""), verify_usd=round(run.usd, 4))

    with ThreadPoolExecutor(max_workers=_VERIFY_WORKERS) as pool:
        findings = list(pool.map(verify, findings))
    unverified = sum(f["verdict"] == "unverified" for f in findings)
    if unverified:
        meta["incomplete"].append(f"verify: {unverified} unverified")
    meta["usd"] = round(budget.spent, 4)
    findings.sort(key=report.sort_key)

    blocking = any(f["verdict"] == "confirmed" and f["severity"] in ("critical", "high") for f in findings)
    code = EXIT_BLOCKED if blocking else EXIT_INCOMPLETE if meta["incomplete"] else EXIT_CLEAN
    return finish(code, findings)

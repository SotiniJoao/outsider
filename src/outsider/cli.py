"""`outsider`: review the current branch against its base, from outside."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from outsider.gitio import GitError, executable
from outsider.report import for_pr
from outsider.review import EXIT_USAGE, Options, review


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="outsider", description=__doc__)
    p.add_argument("--repo", type=Path, default=Path.cwd(), help="repository to review (default: cwd)")
    p.add_argument("--config", type=Path, help="config file to use instead of .outsider.toml at the base ref")
    p.add_argument("--base", help="base ref; the diff is base...head (default: `base` in .outsider.toml)")
    p.add_argument("--head", default="HEAD")
    p.add_argument("--commit", help="review one commit instead of base...head")
    p.add_argument("--spec", type=Path, help="spec or ticket for the separate intent pass")
    p.add_argument("--model")
    p.add_argument("--max-usd", type=float)
    p.add_argument("--language")
    p.add_argument("--out", type=Path, help="where reports go (default: ~/.cache/outsider/<repo>)")
    p.add_argument("--env-file", type=Path, help="load provider API keys from this dotenv file")
    p.add_argument("--post-pr", metavar="N", help="post report.md as a comment on PR N with gh")
    p.add_argument("--gh", default=os.environ.get("OUTSIDER_GH", "gh"),
                   help="GitHub CLI binary, never read from the repo (default: $OUTSIDER_GH or gh)")
    p.add_argument("--dry-run", action="store_true", help="run the guards and show what would be sent")
    return p


def main(argv: list[str] | None = None) -> int:
    sys.stdout.reconfigure(errors="replace")
    a = _parser().parse_args(argv)
    if a.env_file:
        from dotenv import load_dotenv  # noqa: PLC0415

        if not load_dotenv(a.env_file, override=False):
            print(f"outsider: could not load {a.env_file}", file=sys.stderr)
            return EXIT_USAGE
    out = review(Options(root=a.repo, config=a.config, base=a.base, head=a.head, commit=a.commit, spec=a.spec,
                         out=a.out, dry_run=a.dry_run, model=a.model, max_usd=a.max_usd, language=a.language))
    if out.message:
        print(f"outsider: {out.message}", file=sys.stderr)
    if out.out_dir:
        print((out.out_dir / "report.md").read_text(encoding="utf-8"))
        print(f"outsider: report in {out.out_dir}", file=sys.stderr)
        if a.post_pr:
            body = for_pr((out.out_dir / "report.md").read_text(encoding="utf-8"))
            try:
                if Path(a.gh).name.lower() not in ("gh", "gh.exe"):
                    raise GitError(f"--gh must point at gh or gh.exe, not {a.gh!r}")
                gh = executable(a.gh, a.repo)
            except GitError as exc:
                print(f"outsider: {exc}", file=sys.stderr)
                return out.exit_code
            proc = subprocess.run([gh, "pr", "comment", a.post_pr, "--body-file", "-"], cwd=a.repo, input=body,
                                  text=True, encoding="utf-8")
            if proc.returncode != 0:
                print("outsider: posting to the PR failed", file=sys.stderr)
    return out.exit_code


if __name__ == "__main__":
    sys.exit(main())

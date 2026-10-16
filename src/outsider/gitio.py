"""Read-only git access. Every read is pinned to a commit, so the working tree never leaks into a review."""
from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# Config in the reviewed repo must not run anything or reach the network: no pager, external diff, fsmonitor,
# signature check (gpg.program) or transport (lazy fetch in a partial clone). Paths come back unquoted.
_SAFE = ["-c", "core.pager=cat", "-c", "core.fsmonitor=false", "-c", "diff.external=", "-c", "core.quotePath=false",
         "-c", "log.showSignature=false", "-c", "protocol.allow=never", "-c", "diff.noprefix=false",
         "-c", "diff.mnemonicPrefix=false"]
_DIFF = ["--no-color", "--no-ext-diff", "--no-textconv", "--find-renames", "--src-prefix=a/", "--dst-prefix=b/"]
_ENV = {"GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}


class GitError(RuntimeError):
    pass


def executable(name: str, root: Path) -> str:
    """Absolute path of a program, refused when it lives inside the reviewed repo (Windows searches cwd first)."""
    found = shutil.which(name)
    if not found:
        raise GitError(f"not found on PATH: {name!r}")
    resolved = Path(found).resolve()
    if resolved.is_relative_to(Path(root).resolve()):
        raise GitError(f"refusing to run {name!r} from inside the reviewed repo: {resolved}")
    return str(resolved)


def git(root: Path, *args: str, ok_codes: tuple[int, ...] = (0,)) -> str:
    proc = subprocess.run([executable("git", root), "-C", str(root), *_SAFE, *args], capture_output=True,
                          env={**os.environ, **_ENV}, encoding="utf-8", errors="replace")
    if proc.returncode not in ok_codes:
        raise GitError(proc.stderr.strip() or f"git {args[0]} failed")
    return proc.stdout


def resolve(root: Path, ref: str) -> str:
    if ref.startswith("-"):
        raise GitError(f"bad ref: {ref!r}")
    sha = git(root, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}", ok_codes=(0, 1)).strip()
    if not sha:
        raise GitError(f"ref does not resolve: {ref!r}")
    return sha


def diff_range(root: Path, base: str, head: str) -> str:
    return git(root, "diff", *_DIFF, f"{base}...{head}")


def diff_commit(root: Path, sha: str, parent: str | None) -> str:
    """Against the first parent, so a merge shows what it brought in (git show would print a combined diff)."""
    if parent:
        return git(root, "diff", *_DIFF, parent, sha)
    return git(root, "show", *_DIFF, "--no-show-signature", "--format=", sha)


@dataclass
class Repo:
    root: Path
    sha: str

    @classmethod
    def open(cls, root: Path | str, ref: str) -> "Repo":
        root = Path(root)
        return cls(root, resolve(root, ref))

    def object_type(self, path: str) -> str | None:
        out = git(self.root, "cat-file", "-t", f"{self.sha}:{path}" if path else f"{self.sha}^{{tree}}",
                  ok_codes=(0, 128))
        return out.strip() or None

    def read(self, path: str) -> str:
        if self.object_type(path) != "blob":
            raise GitError(f"no such file at the reviewed commit: {path}")
        return git(self.root, "cat-file", "-p", f"{self.sha}:{path}")

    def read_or_none(self, path: str) -> str | None:
        return self.read(path) if self.object_type(path) == "blob" else None

    def ls(self, path: str) -> list[str]:
        """Entry names of a directory; '' is the root."""
        if path and self.object_type(path) != "tree":
            raise GitError(f"no such directory at the reviewed commit: {path}")
        out = git(self.root, "ls-tree", "-z", f"{self.sha}:{path}" if path else self.sha)
        entries = []
        for record in filter(None, out.split("\0")):
            meta, name = record.split("\t", 1)
            entries.append(name + ("/" if meta.split()[1] == "tree" else ""))
        return entries

    def grep(self, pattern: str, glob: str | None) -> list[tuple[str, int, str]]:
        """(path, line, text) per match; `-z` keeps odd file names (accents, ':', tabs) intact."""
        args = ["grep", "-z", "-n", "-I", "-E", "--no-color", "-e", pattern, self.sha]
        if glob:
            args += ["--", glob]
        out = git(self.root, *args, ok_codes=(0, 1))
        prefix = f"{self.sha}:"
        hits = []
        for record in out.split("\n"):
            if not record.startswith(prefix):
                continue
            parts = record.removeprefix(prefix).split("\0", 2)
            if len(parts) == 3 and parts[1].isdigit():
                hits.append((parts[0], int(parts[1]), parts[2]))
        return hits

"""The reviewer's read-only tools. Nothing here writes, executes, or reaches outside git objects."""
from __future__ import annotations

import json

from outsider.gitio import GitError, Repo
from outsider.guard import REDACTED, GuardError, is_denied, normalize_path, private_key_lines, redact

_MAX_GREP_LINES = 200


def _fn(name: str, description: str, props: dict, required: list[str]) -> dict:
    return {"type": "function", "function": {"name": name, "description": description, "parameters": {
        "type": "object", "properties": props, "required": required, "additionalProperties": False}}}


_REPO_PROP = {"repo": {"type": "string", "description": "Neighbour repository name; omit for the reviewed repo."}}
_SCHEMAS = [
    _fn("read_file", "Read a file at the reviewed commit, with line numbers.",
        {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"},
         **_REPO_PROP}, ["path"]),
    _fn("grep", "Search file contents at the reviewed commit (extended regex). Returns path:line:text.",
        {"pattern": {"type": "string"}, "path_glob": {"type": "string", "description": "e.g. '*.py' or 'src/*'"},
         **_REPO_PROP}, ["pattern"]),
    _fn("list_dir", "List a directory at the reviewed commit ('' is the root). Directories end with '/'.",
        {"path": {"type": "string"}, **_REPO_PROP}, ["path"]),
    _fn("diff", "The diff of one changed file, with numbered lines; page a long one with start_line/end_line.",
        {"path": {"type": "string"}, "start_line": {"type": "integer"}, "end_line": {"type": "integer"}}, ["path"]),
]


def _numbered(lines: list[str], start_line: int | None, end_line: int | None) -> str:
    start = max(1, int(start_line or 1))
    end = min(len(lines), int(end_line or len(lines)))
    return "\n".join(f"{n}\t{lines[n - 1]}" for n in range(start, end + 1)) or "(empty)"


class Toolbox:
    def __init__(self, repos: dict[str, Repo], deny: tuple[str, ...], allowlist: tuple[str, ...] = (),
                 diff_sections: dict[str, str] | None = None, max_chars: int = 40_000):
        self.repos, self.deny, self.allowlist = repos, deny, allowlist
        self.diff_sections = diff_sections or {}
        self.max_chars = max_chars

    def schemas(self) -> list[dict]:
        return _SCHEMAS

    def call(self, name: str, raw_args: str) -> str:
        try:
            args = json.loads(raw_args or "{}")
            if not isinstance(args, dict):
                raise ValueError("arguments must be a JSON object")
            handler = {"read_file": self._read_file, "grep": self._grep, "list_dir": self._list_dir,
                       "diff": self._diff}.get(name)
            if handler is None:
                return f"error: unknown tool {name!r}"
            out = handler(**args)
        except Exception as exc:  # anything the model's arguments can trigger goes back to it, never up the stack
            return redact(f"error: {exc}", self.allowlist)
        return self._cap(redact(out, self.allowlist))

    def _cap(self, text: str) -> str:
        if len(text) <= self.max_chars:
            return text
        return text[: self.max_chars] + f"\n[truncated at {self.max_chars} chars; narrow with start_line/end_line or a tighter pattern]"

    def _repo(self, repo: str | None) -> Repo:
        if (repo or "") not in self.repos:
            raise ValueError(f"unknown repo {repo!r}; known: {sorted(k for k in self.repos if k)}")
        return self.repos[repo or ""]

    def _checked(self, path: str) -> str:
        p = normalize_path(path)
        if p and is_denied(p, self.deny):
            raise GuardError(f"access denied by deny_paths: {p}")
        return p

    def _read_file(self, path: str, start_line: int | None = None, end_line: int | None = None,
                   repo: str | None = None) -> str:
        p = self._checked(path)
        return _numbered(redact(self._repo(repo).read(p), self.allowlist).splitlines(), start_line, end_line)

    def _grep(self, pattern: str, path_glob: str | None = None, repo: str | None = None) -> str:
        if path_glob:
            normalize_path(path_glob)
        r = self._repo(repo)
        key_lines: dict[str, set[int]] = {}
        hits = []
        for path, n, text in r.grep(pattern, path_glob):
            if is_denied(path, self.deny):
                continue
            if path not in key_lines:
                key_lines[path] = private_key_lines(r.read(path))
            hits.append(f"{path}:{n}:{REDACTED if n in key_lines[path] else text}")
        if not hits:
            return "(no matches)"
        more = f"\n[{len(hits) - _MAX_GREP_LINES} more matches; narrow the pattern or path_glob]" \
            if len(hits) > _MAX_GREP_LINES else ""
        return "\n".join(hits[:_MAX_GREP_LINES]) + more

    def _list_dir(self, path: str, repo: str | None = None) -> str:
        p = self._checked(path)
        prefix = f"{p}/" if p else ""
        entries = [e for e in self._repo(repo).ls(p) if not is_denied(prefix + e.rstrip("/"), self.deny)]
        return "\n".join(e.removeprefix(prefix) for e in entries) or "(empty)"

    def _diff(self, path: str, start_line: int | None = None, end_line: int | None = None) -> str:
        p = normalize_path(path)
        if p not in self.diff_sections:
            raise ValueError(f"{p} is not part of the diff")
        return _numbered(self.diff_sections[p].splitlines(), start_line, end_line)


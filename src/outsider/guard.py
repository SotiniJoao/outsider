"""What may leave the machine: path confinement, the denylist, and secret detection."""
from __future__ import annotations

import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import PurePosixPath

DEFAULT_DENY: tuple[str, ...] = (
    ".env", ".env.*", "*.env", ".envrc", "*.pem", "*.key", "*.p12", "*.pfx", "*.keystore", "*.jks",
    "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "secrets.*", "credentials.*", "*service-account*.json",
    "*-sa.json", "*.asc", "*.gpg", "*.ppk", ".npmrc", ".pypirc",
    ".netrc", "*.tfstate", "*.tfstate.*",
)

# Shapes of real credentials. Only the kind is ever reported, never the matched value.
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("aws", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("slack", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("stripe", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{20,}")),
    ("elevenlabs", re.compile(r"\bsk_[0-9a-f]{40,}\b")),
    ("openai", re.compile(r"\bsk-(?:proj-|ant-|svcacct-)?[A-Za-z0-9_-]{20,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
)
REDACTED = "[REDACTED by outsider]"
# The whole block, body included; an unterminated block is cut to the end of the text.
_KEY_BLOCK = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY(?: BLOCK)?-----.*?"
                        r"(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S)


class GuardError(ValueError):
    pass


@dataclass(frozen=True)
class SecretHit:
    path: str | None
    line: int
    kind: str


def normalize_path(path: str) -> str:
    """Repo-relative POSIX path, or GuardError when it could point outside the repo."""
    p = path.replace("\\", "/").strip()
    if p.startswith("/") or re.match(r"^[A-Za-z]:", p):
        raise GuardError(f"absolute paths are not allowed: {path!r}")
    parts = [s for s in PurePosixPath(p).parts if s not in ("", ".")]
    if ".." in parts:
        raise GuardError(f"'..' is not allowed: {path!r}")
    return "/".join(parts)


def is_denied(path: str, patterns: tuple[str, ...]) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatchcase(name, pat) or fnmatchcase(path, pat) for pat in patterns)


def split_diff(diff: str) -> list[tuple[str, str]]:
    """[(path, section)] per `diff --git` header; the path is the new side (old side for deletions)."""
    sections: list[tuple[str, str]] = []
    for chunk in re.split(r"(?m)^(?=diff --git )", diff):
        if not chunk.startswith("diff --git "):
            continue
        new = re.search(r"(?m)^\+\+\+ b/(.+)$", chunk)
        old = re.search(r"(?m)^--- a/(.+)$", chunk)
        header = re.match(r"diff --git a/(.+?) b/(.+)$", chunk.splitlines()[0])
        path = new.group(1) if new else old.group(1) if old else header.group(2) if header else "?"
        sections.append((path.strip(), chunk))
    return sections


def filter_diff(diff: str, patterns: tuple[str, ...]) -> tuple[str, list[str]]:
    kept, withheld = [], []
    for path, section in split_diff(diff):
        old = re.match(r"diff --git a/(.+?) b/", section)
        if is_denied(path, patterns) or (old and is_denied(old.group(1), patterns)):
            withheld.append(path)
        else:
            kept.append(section)
    return "".join(kept), withheld


def _allowed(value: str, allowlist: tuple[str, ...]) -> bool:
    return any(re.search(a, value) for a in allowlist)


def scan_text(text: str, allowlist: tuple[str, ...] = (), path: str | None = None) -> list[SecretHit]:
    hits = []
    for n, line in enumerate(text.splitlines(), 1):
        for kind, pat in _SECRET_PATTERNS:
            if any(not _allowed(m.group(0), allowlist) for m in pat.finditer(line)):
                hits.append(SecretHit(path, n, kind))
                break
    return hits


def scan_diff(diff: str, allowlist: tuple[str, ...] = ()) -> list[SecretHit]:
    return [h for path, section in split_diff(diff) for h in scan_text(section, allowlist, path)]


def private_key_lines(text: str) -> set[int]:
    """1-based line numbers inside private key blocks, so a slice or a grep hit can't show the body alone."""
    lines: set[int] = set()
    for m in _KEY_BLOCK.finditer(text):
        first = text.count("\n", 0, m.start()) + 1
        lines.update(range(first, first + m.group(0).count("\n") + 1))
    return lines


def redact(text: str, allowlist: tuple[str, ...] = ()) -> str:
    text = _KEY_BLOCK.sub(REDACTED, text)
    for _, pat in _SECRET_PATTERNS:
        text = pat.sub(lambda m: m.group(0) if _allowed(m.group(0), allowlist) else REDACTED, text)
    return text

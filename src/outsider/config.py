"""`.outsider.toml`. Every key is optional; unknown keys are an error.

Read from the base ref (or a file the user names), never from the branch under review: the branch could
otherwise switch off its own secret scan or swap the hook that runs before sending.
"""
from __future__ import annotations

import tomllib
from dataclasses import dataclass, field, fields
from pathlib import Path

FILE = ".outsider.toml"


@dataclass
class Config:
    model: str = "gpt-6.1-sol"
    # A cheaper `model` can do the blind and intent passes while this one refutes; defaults to `model`.
    verify_model: str | None = None
    reasoning_effort: str | None = "high"
    max_usd: float = 1.0
    max_steps: int = 40
    language: str = "English"
    base: str | None = None
    deny_paths: tuple[str, ...] = ()
    secret_allowlist: tuple[str, ...] = ()
    # Runs before anything is sent, with OUTSIDER_DIFF_FILE set; a non-zero exit aborts the review.
    pre_send: list[str] | None = None
    prices_per_mtok: tuple[float, float] | None = None
    neighbours: list[dict] = field(default_factory=list)


def load(root: Path) -> Config:
    """From the working tree; for the CLI's own settings (`gh`) only, never for a review's guards."""
    path = Path(root) / FILE
    return parse(path.read_text(encoding="utf-8"), root) if path.exists() else Config()


def parse(text: str | None, root: Path) -> Config:
    if text is None:
        return Config()
    raw = tomllib.loads(text)
    known = {f.name for f in fields(Config)}
    unknown = set(raw) - known
    if unknown:
        raise ValueError(f"{FILE}: unknown keys {sorted(unknown)}")
    for key in ("deny_paths", "secret_allowlist", "prices_per_mtok"):
        if key in raw:
            raw[key] = tuple(raw[key])
    neighbours = []
    for n in raw.pop("neighbours", []):
        if set(n) != {"name", "path", "ref"}:
            raise ValueError(f"{FILE}: each [[neighbours]] needs exactly name, path and ref")
        neighbours.append({**n, "path": str((Path(root) / n["path"]).resolve())})
    return Config(**raw, neighbours=neighbours)

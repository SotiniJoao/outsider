from pathlib import Path

from outsider.config import load


def test_defaults_without_file(tmp_path):
    c = load(tmp_path)
    assert c.max_usd == 1.0 and c.model and c.neighbours == [] and c.pre_send is None


def test_file_values_and_relative_neighbour(tmp_path: Path):
    (tmp_path / ".outsider.toml").write_text(
        'model = "openai/responses/gpt-6.1-sol"\nmax_usd = 0.5\nlanguage = "pt-BR"\nbase = "origin/staging"\n'
        'deny_paths = ["data/*"]\npre_send = ["python", "scripts/check_pii.py"]\n'
        '[[neighbours]]\nname = "web"\npath = "../web"\nref = "origin/staging"\n', encoding="utf-8")
    c = load(tmp_path)
    assert c.model == "openai/responses/gpt-6.1-sol" and c.max_usd == 0.5 and c.base == "origin/staging"
    assert c.deny_paths == ("data/*",) and c.pre_send == ["python", "scripts/check_pii.py"]
    assert c.neighbours[0]["path"] == str((tmp_path / "../web").resolve())


def test_unknown_key_is_rejected(tmp_path: Path):
    import pytest
    (tmp_path / ".outsider.toml").write_text('max_usdd = 3\n', encoding="utf-8")
    with pytest.raises(ValueError):
        load(tmp_path)

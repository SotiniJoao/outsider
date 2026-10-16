import pytest

from outsider.guard import (DEFAULT_DENY, GuardError, filter_diff, is_denied, normalize_path, redact, scan_diff,
                            scan_text)

FAKE_OPENAI = "sk-proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"
FAKE_GITHUB = "ghp_" + "a" * 36
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


@pytest.mark.parametrize("bad", ["../etc/passwd", "a/../../b", "/etc/passwd", "C:/Windows", "C:\\x", "a/./../.."])
def test_G1_path_escape_refused(bad):
    with pytest.raises(GuardError):
        normalize_path(bad)


def test_G1_normal_paths_kept():
    assert normalize_path("./src/app.py") == "src/app.py"
    assert normalize_path("src\\app.py") == "src/app.py"
    assert normalize_path("") == ""


@pytest.mark.parametrize("path", [".env", "deploy/.env", ".env.local", "config/.env.production", "certs/server.pem",
                                  "id_rsa", "home/id_ed25519.pub", "secrets.json", ".npmrc", ".envrc", "x.key"])
def test_G2_default_denylist(path):
    assert is_denied(path, DEFAULT_DENY)


@pytest.mark.parametrize("path", ["docs/environment.md", "src/env.py", "docs/secrets-handling.md", "keyboard.py",
                                  "monkey.py"])
def test_G2_denylist_does_not_overreach(path):
    assert not is_denied(path, DEFAULT_DENY)


def test_G2_project_patterns_add_to_defaults():
    assert is_denied("data/real_cvs/a.pdf", DEFAULT_DENY + ("data/real_cvs/*",))


DIFF = f"""diff --git a/app.py b/app.py
index 1..2 100644
--- a/app.py
+++ b/app.py
@@ -1,2 +1,2 @@
 def total(xs):
-    return sum(xs)
+    return sum(xs[1:])
diff --git a/.env b/.env
new file mode 100644
--- /dev/null
+++ b/.env
@@ -0,0 +1 @@
+OPENAI_API_KEY={FAKE_OPENAI}
"""


def test_G3_denylisted_section_withheld():
    text, withheld = filter_diff(DIFF, DEFAULT_DENY)
    assert withheld == [".env"]
    assert "OPENAI_API_KEY" not in text
    assert "sum(xs[1:])" in text


def test_G4_secret_in_diff_reported_without_value():
    hits = scan_diff(DIFF.replace(".env", "settings.py"))
    assert [(h.path, h.kind) for h in hits] == [("settings.py", "openai")]
    assert FAKE_OPENAI not in repr(hits)


@pytest.mark.parametrize("value,kind", [(FAKE_GITHUB, "github"), (FAKE_AWS, "aws"),
                                        ("-----BEGIN RSA PRIVATE KEY-----", "private_key"),
                                        ("xoxb-1234567890-abcdefghij", "slack"),
                                        ("sk_" + "ab12" * 12, "elevenlabs")])
def test_G4_known_secret_shapes(value, kind):
    assert [h.kind for h in scan_text(f"x = '{value}'\n")] == [kind]


def test_G4_allowlist_silences_a_known_fake():
    assert scan_text(f"KEY = '{FAKE_OPENAI}'", allowlist=(r"sk-proj-A1b2",)) == []


def test_G4_ordinary_code_is_clean():
    assert scan_text("token = request.headers['x-api-key']\napi_key = os.environ['OPENAI_API_KEY']\n") == []


def test_G5_redact_hides_value_keeps_rest():
    out = redact(f"a = 1\nkey = '{FAKE_GITHUB}'\nb = 2\n")
    assert FAKE_GITHUB not in out
    assert "a = 1" in out and "b = 2" in out and "[REDACTED by outsider]" in out


def test_H2_redact_covers_whole_private_key_block():
    text = "a\n-----BEGIN OPENSSH " + "PRIVATE KEY-----\nAAAABODY\nCCCCBODY\n-----END OPENSSH " + "PRIVATE KEY-----\nb\n"
    out = redact(text)
    assert "AAAABODY" not in out and "CCCCBODY" not in out and out.startswith("a\n") and out.endswith("b\n")


def test_H2_unterminated_private_key_redacted_to_the_end():
    out = redact("-----BEGIN " + "PRIVATE KEY-----\nAAAABODY\n")
    assert "AAAABODY" not in out


@pytest.mark.parametrize("path", ["gcp-service-account.json", "deploy/prod-sa.json"])
def test_H2_service_account_files_denied(path):
    assert is_denied(path, DEFAULT_DENY)


def test_M3_pgp_private_key_scanned_and_redacted():
    block = "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----\nlQOYBGBODY\n-----END PGP " + "PRIVATE KEY BLOCK-----\n"
    assert [h.kind for h in scan_text(block)] == ["private_key"]
    assert "lQOYBGBODY" not in redact(block)


@pytest.mark.parametrize("path", ["keys/signing.asc", "backup.gpg", "putty.ppk"])
def test_M3_key_containers_denied(path):
    assert is_denied(path, DEFAULT_DENY)

import base64
import hashlib
import json
import re
from pathlib import Path

import pytest
import yaml
from argon2.low_level import hash_secret_raw

import xvault.xvault as vault_module
from xvault.meta import META_VARIABLE_PREFIX
from xvault.xvault import XVault


PASSWORD = "correct-password"


@pytest.fixture(autouse=True)
def fast_key_derivation(monkeypatch):
    def derive(secret, salt, **kwargs):
        return hashlib.sha256(secret + salt).digest()

    monkeypatch.setattr(vault_module, "hash_secret_raw", derive)


def editor_result(monkeypatch, result):
    class FakeEditor:
        def editText(self, text, **kwargs):
            return result

    monkeypatch.setattr(vault_module, "XEditor", FakeEditor)


def test_edit_secret_updates_existing_secret_and_preserves_other_ciphertext(
    tmp_path, monkeypatch
):
    path = tmp_path / "vault.env"
    path.write_text("FIRST=enc:first\nOTHER=enc:other\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    vault.set("FIRST", "first")
    before = path.read_text(encoding="utf-8")
    other = re.search(r"^OTHER=enc:(.+)$", before, re.MULTILINE).group(1)

    editor_result(monkeypatch, "replacement")
    vault.edit_secret("FIRST")

    stored = path.read_text(encoding="utf-8")
    assert "replacement" not in stored
    assert f"OTHER=enc:{other}" in stored
    reopened = XVault(str(path), password=PASSWORD, no_cache_key=True)
    assert reopened.get("FIRST") == "replacement"
    assert reopened.get("OTHER") == "other"


def test_edit_secret_initializes_plaintext_marker(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    editor_result(monkeypatch, "changed")

    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    vault.edit_secret("SECRET")

    assert "plaintext" not in path.read_text(encoding="utf-8")
    assert "changed" not in path.read_text(encoding="utf-8")
    assert XVault(str(path), password=PASSWORD, no_cache_key=True).get("SECRET") == "changed"


def test_edit_secret_cancel_does_not_modify_file(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    original = path.read_bytes()
    editor_result(monkeypatch, None)

    XVault(str(path), password=PASSWORD, no_cache_key=True).edit_secret("SECRET")

    assert path.read_bytes() == original


def test_edit_secret_no_cache_key_never_touches_keyring(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    editor_result(monkeypatch, "changed")
    monkeypatch.setattr(
        vault_module.keyring,
        "get_password",
        lambda *args: (_ for _ in ()).throw(AssertionError("keyring read")),
    )
    monkeypatch.setattr(
        vault_module.keyring,
        "set_password",
        lambda *args: (_ for _ in ()).throw(AssertionError("keyring write")),
    )

    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    vault.edit_secret("SECRET")

    assert XVault(str(path), password=PASSWORD, no_cache_key=True).get("SECRET") == "changed"


@pytest.mark.parametrize("suffix", [".md", ".jsonc"])
def test_edit_secret_rejects_non_addressable_formats(tmp_path, suffix):
    path = tmp_path / f"vault{suffix}"
    path.write_text("Secret: enc:plaintext\n", encoding="utf-8")

    with pytest.raises(NotImplementedError, match="Single-secret editing"):
        XVault(str(path), password=PASSWORD, no_cache_key=True).edit_secret("SECRET")


def test_edit_secret_failed_persistence_preserves_state_and_file(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    original = path.read_bytes()
    original_text = vault._text
    original_meta = vault._meta.to_dict()
    editor_result(monkeypatch, "changed")
    monkeypatch.setattr(
        vault_module.os,
        "replace",
        lambda *args: (_ for _ in ()).throw(OSError("simulated replace failure")),
    )

    with pytest.raises(OSError, match="simulated replace failure"):
        vault.edit_secret("SECRET")

    assert path.read_bytes() == original
    assert vault._text == original_text
    assert vault._meta.to_dict() == original_meta
    assert vault.is_uninitialized()


def test_full_edit_serialization_failure_preserves_state(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    original = path.read_bytes()
    original_text = vault._text
    editor_result(monkeypatch, "SECRET=enc:changed\n")
    monkeypatch.setattr(
        vault._handler,
        "stringify",
        lambda *args: (_ for _ in ()).throw(ValueError("serialization failed")),
    )

    with pytest.raises(ValueError, match="serialization failed"):
        vault.edit()

    assert path.read_bytes() == original
    assert vault._text == original_text
    assert vault.is_uninitialized()


def test_full_edit_encryption_failure_preserves_state(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    original = path.read_bytes()
    original_text = vault._text
    editor_result(monkeypatch, "SECRET=enc:changed\n")
    monkeypatch.setattr(
        vault_module.CryptoV2,
        "encrypt",
        lambda *args: (_ for _ in ()).throw(ValueError("encryption failed")),
    )

    with pytest.raises(ValueError, match="encryption failed"):
        vault.edit()

    assert path.read_bytes() == original
    assert vault._text == original_text
    assert vault.is_uninitialized()


def test_full_edit_failed_initial_commit_preserves_active_state(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    original = path.read_bytes()
    original_text = vault._text
    original_meta = vault._meta.to_dict()
    editor_result(monkeypatch, "SECRET=enc:changed\n")
    monkeypatch.setattr(
        vault_module.os,
        "replace",
        lambda *args: (_ for _ in ()).throw(OSError("simulated replace failure")),
    )

    with pytest.raises(OSError, match="simulated replace failure"):
        vault.edit()

    assert path.read_bytes() == original
    assert vault._text == original_text
    assert vault._meta.to_dict() == original_meta
    assert vault.is_uninitialized()
    assert not list(tmp_path.glob("*.tmp"))


def _decode_markdown_meta(stored):
    front = re.match(r"^---\n(.*?)\n---", stored, re.DOTALL).group(1)
    data = yaml.safe_load(front)
    encoded = data["_xvault"][len(META_VARIABLE_PREFIX) :]
    return json.loads(base64.urlsafe_b64decode(encoded))


def test_markdown_front_matter_survives_initialization_and_round_trip(
    tmp_path, monkeypatch
):
    path = tmp_path / "notes.md"
    original_front = (
        "title: Production notes\n"
        "# keep this comment\n"
        "tags:\n"
        "  - infrastructure\n"
        "nested:\n"
        "  owner: platform\n"
    )
    path.write_text(
        f"---\n{original_front}---\n\n# Notes\n\nPassword: ${{enc:secret}}\n",
        encoding="utf-8",
    )
    editor_result(
        monkeypatch,
        f"---\n{original_front}---\n\n# Notes\n\nPassword: ${{enc:secret}}\n",
    )

    XVault(str(path), password=PASSWORD, no_cache_key=True).edit()

    stored = path.read_text(encoding="utf-8")
    assert original_front in stored
    assert stored.count("\n---") == 1
    assert stored.count("_xvault:") == 1
    assert "# Notes\n\nPassword:" in stored
    assert "${enc:secret}" not in stored
    assert _decode_markdown_meta(stored)["crypto_version"] == 2
    exported = XVault(str(path), password=PASSWORD, no_cache_key=True).export()
    assert "title: Production notes" in exported
    assert "Password: secret" in exported


def test_markdown_front_matter_preserves_crlf_style(tmp_path, monkeypatch):
    path = tmp_path / "notes.md"
    path.write_bytes(
        b"---\r\ntitle: Notes\r\n# retained\r\n---\r\n\r\nSecret: ${enc:value}\r\n"
    )
    editor_result(
        monkeypatch,
        "---\r\ntitle: Notes\r\n# retained\r\n---\r\n\r\nSecret: ${enc:value}\r\n",
    )

    XVault(str(path), password=PASSWORD, no_cache_key=True).edit()

    stored = path.read_bytes()
    assert b"title: Notes\r\n# retained\r\n" in stored
    assert stored.count(b"_xvault:") == 1
    assert b"\r\n---\r\n" in stored


def test_markdown_existing_front_matter_survives_v1_to_v2_upgrade(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(vault_module, "hash_secret_raw", hash_secret_raw)
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    env_text = fixture.read_text(encoding="utf-8")
    metadata = re.search(r"^_xvault=(.+)$", env_text, re.MULTILINE).group(1)
    ciphertext = re.search(r"^SECRET=enc:(.+)$", env_text, re.MULTILINE).group(1)
    path = tmp_path / "notes.md"
    path.write_text(
        "---\ntitle: Legacy\n# retained\n_xvault: "
        + metadata
        + "\n---\n\nSecret: ${enc:"
        + ciphertext
        + "}\n",
        encoding="utf-8",
    )

    vault = XVault(str(path), password="fixture-password", no_cache_key=True)
    vault.upgrade("fixture-password")

    stored = path.read_text(encoding="utf-8")
    assert "title: Legacy\n# retained\n" in stored
    assert stored.count("_xvault:") == 1
    assert _decode_markdown_meta(stored)["crypto_version"] == 2
    assert "Secret: fixture-secret" in XVault(
        str(path), password="fixture-password", no_cache_key=True
    ).export()


def test_edit_secret_supports_crypto_v1(tmp_path, monkeypatch):
    monkeypatch.setattr(vault_module, "hash_secret_raw", hash_secret_raw)
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "v1.env"
    path.write_bytes(fixture.read_bytes())
    editor_result(monkeypatch, "replacement")

    vault = XVault(str(path), password="fixture-password", no_cache_key=True)
    vault.edit_secret("SECRET")

    assert vault._meta.crypto_version == 1
    assert XVault(str(path), password="fixture-password", no_cache_key=True).get(
        "SECRET"
    ) == "replacement"


def test_real_cli_edit_with_and_without_key(tmp_path, monkeypatch):
    from xvault import __main__ as cli

    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    monkeypatch.setattr(cli, "ask_password", lambda **kwargs: PASSWORD)
    editor_result(monkeypatch, "changed")

    assert cli.edit(str(path), key="SECRET", no_cache_key=True) is None
    assert XVault(str(path), password=PASSWORD, no_cache_key=True).get("SECRET") == "changed"

    editor_result(monkeypatch, "SECRET=enc:again\n")
    assert cli.edit(str(path), no_cache_key=True) is None
    assert XVault(str(path), password=PASSWORD, no_cache_key=True).get("SECRET") == "again"


def test_strict_and_verbose_validation_semantics(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    vault.set("SECRET", "secret")

    verified = vault.validate(strict=True, verbose=True)
    assert verified["status"] == "ok"
    assert any(c["name"] == "strict" and c["severity"] == "info" for c in verified["checks"])
    assert any(c["name"] == "crypto-version" and c["message"] == "2" for c in verified["checks"])
    assert any(c["name"] == "marked-secrets" and c["message"] == "1" for c in verified["checks"])

    vault.lock()
    locked = XVault(str(path)).validate(strict=True)
    assert locked["status"] == "error"
    assert any(c["name"] == "strict" and c["severity"] == "error" for c in locked["checks"])

    plain = tmp_path / "plain.env"
    plain.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    assert XVault(str(plain)).validate()["status"] == "warning"
    assert XVault(str(plain)).validate(strict=True)["status"] == "error"


def test_verbose_validation_does_not_expose_secret_or_password(tmp_path):
    path = tmp_path / "vault.env"
    secret = "do-not-report-secret"
    password = "do-not-report-password"
    path.write_text(f"SECRET=enc:{secret}\n", encoding="utf-8")
    vault = XVault(str(path), password=password, no_cache_key=True)
    vault.set("SECRET", secret)

    rendered = repr(vault.validate(strict=True, verbose=True))

    assert secret not in rendered
    assert password not in rendered

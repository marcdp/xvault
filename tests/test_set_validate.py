import base64
import hashlib
import re

import pytest

import xvault.xvault as vault_module
from xvault.xvault import XVault


PASSWORD = "correct-password"


@pytest.fixture(autouse=True)
def fast_key_derivation(monkeypatch):
    def derive(secret, salt, **kwargs):
        return hashlib.sha256(secret + salt).digest()

    monkeypatch.setattr(vault_module, "hash_secret_raw", derive)


@pytest.mark.parametrize(
    ("suffix", "content", "key", "value", "expected"),
    [
        (".env", "PLAIN=visible\n", "SECRET", "env-secret-value", "env-secret-value"),
        (".json", '{"plain": "visible"}\n', "secret", "json-secret-value", "json-secret-value"),
        (".yaml", "plain: visible\n", "secret", "yaml-secret-value", "yaml-secret-value"),
        (
            ".ovpn",
            "client\nverb 3\n",
            "auth-user-pass",
            "vpn-user-value\nvpn-pass-value",
            "vpn-user-value\nvpn-pass-value",
        ),
    ],
)
def test_set_encrypts_new_value_immediately(tmp_path, suffix, content, key, value, expected):
    path = tmp_path / f"vault{suffix}"
    path.write_text(content, encoding="utf-8")

    vault = XVault(str(path), password=PASSWORD)
    vault.set(key, value)

    stored = path.read_text(encoding="utf-8")
    for plaintext_line in value.splitlines():
        assert plaintext_line not in stored
    assert "enc:" in stored
    assert XVault(str(path), password=PASSWORD).get(key) == expected


def test_set_replaces_secret_without_changing_other_values(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text("HOST=localhost\nMODE=production\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD)
    vault.set("FIRST", "first-secret")
    vault.set("OTHER", "other-secret")
    before = path.read_text(encoding="utf-8")
    other_ciphertext = re.search(r"^OTHER=enc:(.+)$", before, re.MULTILINE).group(1)

    vault.set("FIRST", "replacement-secret")

    stored = path.read_text(encoding="utf-8")
    assert "first-secret" not in stored
    assert "replacement-secret" not in stored
    assert "other-secret" not in stored
    assert f"OTHER=enc:{other_ciphertext}" in stored
    assert "HOST=localhost" in stored
    assert "MODE=production" in stored
    reopened = XVault(str(path), password=PASSWORD)
    assert reopened.get("FIRST") == "replacement-secret"
    assert reopened.get("OTHER") == "other-secret"


def test_set_openvpn_inline_value_round_trips(tmp_path):
    path = tmp_path / "vault.ovpn"
    path.write_text("client\nverb 3\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD)

    vault.set("verb", "inline-secret")

    stored = path.read_text(encoding="utf-8")
    assert "inline-secret" not in stored
    assert "verb ${enc:" in stored
    assert XVault(str(path), password=PASSWORD).get("verb") == "inline-secret"


def test_set_no_encrypt_intentionally_writes_plaintext(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text("HOST=localhost\n", encoding="utf-8")

    vault = XVault(str(path), password=PASSWORD)
    vault.set("PUBLIC_VALUE", "intentional-plaintext", encrypt=False)

    stored = path.read_text(encoding="utf-8")
    assert "PUBLIC_VALUE=intentional-plaintext" in stored
    assert "PUBLIC_VALUE=enc:" not in stored


def test_unsupported_set_does_not_modify_file(tmp_path):
    path = tmp_path / "vault.jsonc"
    original = '{\n  // comment\n  "key": "value"\n}\n'
    path.write_text(original, encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD)

    with pytest.raises(NotImplementedError):
        vault.set("key", "never-written")

    assert path.read_text(encoding="utf-8") == original


def test_failed_save_leaves_original_file_unchanged(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    original = "HOST=localhost\n"
    path.write_text(original, encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD)

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(vault_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        vault.set("SECRET", "never-persisted")

    assert path.read_text(encoding="utf-8") == original
    assert not list(tmp_path.glob("*.tmp"))


def make_initialized_vault(tmp_path, *, encrypted=True):
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD)
    vault.set("SECRET" if encrypted else "PUBLIC", "secret-value" if encrypted else "plain-value", encrypt=encrypted)
    return path, vault


def test_validate_valid_encrypted_file_is_ok(tmp_path):
    _, vault = make_initialized_vault(tmp_path)

    result = vault.validate()

    assert result["status"] == "ok"
    assert not any(check["severity"] == "error" for check in result["checks"])


def test_validate_corrupted_encrypted_value_is_error(tmp_path):
    path, vault = make_initialized_vault(tmp_path)
    match = re.search(r"^SECRET=enc:(.+)$", vault._text, re.MULTILINE)
    payload = bytearray(base64.urlsafe_b64decode(match.group(1)))
    payload[-1] ^= 1
    corrupted = base64.urlsafe_b64encode(payload).decode()
    vault._text = vault._text[: match.start(1)] + corrupted + vault._text[match.end(1) :]

    result = vault.validate()

    assert result["status"] == "error"
    assert any(check["name"] == "decryp" and check["severity"] == "error" for check in result["checks"])


def test_validate_incorrect_password_is_error(tmp_path):
    path, vault = make_initialized_vault(tmp_path)
    vault.lock()
    wrong_password_vault = XVault(str(path), password="wrong-password", no_cache_key=True)

    result = wrong_password_vault.validate()

    assert result["status"] == "error"
    assert {
        check["message"]
        for check in result["checks"]
        if check["name"] == "password-validation" and check["severity"] == "error"
    } == {"invalid password or metadata"}


def test_validate_corrupted_wrapped_key_metadata_is_error(tmp_path):
    _, vault = make_initialized_vault(tmp_path)
    vault._meta.encrypted_key = "invalid-wrapped-key"

    result = vault.validate()

    assert result["status"] == "error"
    assert any(
        check["name"] == "encrypted-key" and check["severity"] == "error"
        for check in result["checks"]
    )


def test_validate_missing_and_invalid_metadata_are_errors(tmp_path):
    missing_path = tmp_path / "missing.env"
    missing_path.write_text("PLAIN=visible\n", encoding="utf-8")
    missing_result = XVault(str(missing_path)).validate()

    invalid_path, invalid_vault = make_initialized_vault(tmp_path)
    invalid_vault._meta.salt = "not-hex"
    invalid_result = invalid_vault.validate()

    assert missing_result["status"] == "warning"
    assert invalid_result["status"] == "error"
    assert any(check["name"] == "salt" and check["severity"] == "error" for check in invalid_result["checks"])


def test_validate_warning_only_result_is_warning(tmp_path):
    path, vault = make_initialized_vault(tmp_path, encrypted=False)
    vault.lock()

    result = XVault(str(path)).validate()

    assert result["status"] == "warning"
    assert any(check["severity"] == "warning" for check in result["checks"])
    assert not any(check["severity"] == "error" for check in result["checks"])

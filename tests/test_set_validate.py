import base64
import hashlib
from pathlib import Path
import re

import pytest
from argon2.low_level import hash_secret_raw

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


@pytest.mark.parametrize(
    ("suffix", "content", "existing_key", "new_key"),
    [
        (".env", "API_KEY=enc:existing-secret\nHOST=localhost\n", "API_KEY", "PASSWORD"),
        (
            ".json",
            '{"API_KEY": "enc:existing-secret", "HOST": "localhost"}\n',
            "API_KEY",
            "PASSWORD",
        ),
        (".yaml", "API_KEY: enc:existing-secret\nHOST: localhost\n", "API_KEY", "PASSWORD"),
        (".yml", "API_KEY: enc:existing-secret\nHOST: localhost\n", "API_KEY", "PASSWORD"),
        (
            ".ovpn",
            "client\n<auth-token>\nenc:existing-secret\n</auth-token>\n",
            "auth-token",
            "auth-user-pass",
        ),
    ],
)
def test_first_set_encrypts_existing_markers_and_new_value(
    tmp_path, suffix, content, existing_key, new_key
):
    path = tmp_path / f"vault{suffix}"
    path.write_text(content, encoding="utf-8")

    vault = XVault(str(path), password=PASSWORD)
    vault.set(new_key, "new-secret")

    stored = path.read_text(encoding="utf-8")
    assert "existing-secret" not in stored
    assert "new-secret" not in stored
    assert vault._meta.crypto_version == 2
    reopened = XVault(str(path), password=PASSWORD, no_cache_key=True)
    assert reopened.get(existing_key) == "existing-secret"
    assert reopened.get(new_key) == "new-secret"


def test_first_set_replaces_target_before_encrypting_all_markers(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text(
        "API_KEY=enc:old-plaintext-secret\nOTHER=enc:another-secret\n",
        encoding="utf-8",
    )

    vault = XVault(str(path), password=PASSWORD)
    vault.set("API_KEY", "replacement-secret")

    stored = path.read_text(encoding="utf-8")
    assert "old-plaintext-secret" not in stored
    assert "replacement-secret" not in stored
    assert "another-secret" not in stored
    reopened = XVault(str(path), password=PASSWORD, no_cache_key=True)
    assert reopened.get("API_KEY") == "replacement-secret"
    assert reopened.get("OTHER") == "another-secret"


def test_set_replaces_secret_without_changing_other_values(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text("HOST=localhost\nMODE=production\n", encoding="utf-8")
    vault = XVault(str(path), password=PASSWORD)
    vault.set("FIRST", "first-secret")
    vault.set("OTHER", "other-secret")
    before = path.read_text(encoding="utf-8")
    other_ciphertext = re.search(r"^OTHER=enc:(.+)$", before, re.MULTILINE).group(1)
    encrypted_key = vault._meta.encrypted_key

    vault.set("FIRST", "replacement-secret")

    stored = path.read_text(encoding="utf-8")
    assert "first-secret" not in stored
    assert "replacement-secret" not in stored
    assert "other-secret" not in stored
    assert f"OTHER=enc:{other_ciphertext}" in stored
    assert vault._meta.encrypted_key == encrypted_key
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
    path.write_text("SECRET=enc:awaiting-encryption\nHOST=localhost\n", encoding="utf-8")

    vault = XVault(str(path), password=PASSWORD)
    vault.set("PUBLIC_VALUE", "intentional-plaintext", encrypt=False)

    stored = path.read_text(encoding="utf-8")
    assert "PUBLIC_VALUE=intentional-plaintext" in stored
    assert "PUBLIC_VALUE=enc:" not in stored
    assert "SECRET=enc:awaiting-encryption" in stored
    assert "_xvault=" not in stored
    assert vault.is_unitialized()


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


def test_failed_initial_save_with_existing_markers_can_be_retried(tmp_path, monkeypatch):
    path = tmp_path / "vault.env"
    original = b"EXISTING=enc:existing-secret\nHOST=localhost\n"
    path.write_bytes(original)
    vault = XVault(str(path), password=PASSWORD)
    real_replace = vault_module.os.replace

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr(vault_module.os, "replace", fail_replace)
    with pytest.raises(OSError, match="simulated replace failure"):
        vault.set("NEW", "new-secret")

    assert path.read_bytes() == original
    assert vault._text == original.decode()
    assert vault.is_unitialized()
    assert not list(tmp_path.glob("*.tmp"))

    monkeypatch.setattr(vault_module.os, "replace", real_replace)
    vault.set("NEW", "new-secret")
    reopened = XVault(str(path), password=PASSWORD, no_cache_key=True)
    assert reopened.get("EXISTING") == "existing-secret"
    assert reopened.get("NEW") == "new-secret"


@pytest.mark.parametrize(
    ("suffix", "content"),
    [
        (".env", b"_xvault=\nSECRET=enc:plain\n"),
        (".json", b'{"_xvault": null, "secret": "enc:plain"}\n'),
        (".jsonc", b'{// metadata\n"_xvault": 123, "secret": "enc:plain"}\n'),
        (".yaml", b"_xvault:\nsecret: enc:plain\n"),
        (".yml", b"_xvault:\nsecret: enc:plain\n"),
        (".md", b"---\n_xvault:\n---\n\n# Secrets\n"),
        (".ovpn", b"# _xvault=\nclient\n"),
    ],
)
def test_present_malformed_metadata_is_rejected_without_modifying_file(
    tmp_path, suffix, content
):
    path = tmp_path / f"malformed{suffix}"
    path.write_bytes(content)

    with pytest.raises(ValueError, match="^Unable to load vault meta:"):
        XVault(str(path), password=PASSWORD)

    assert path.read_bytes() == content


def test_malformed_metadata_never_falls_back_to_new_vault(tmp_path, monkeypatch):
    path = tmp_path / "malformed.env"
    path.write_text("_xvault=invalid-value\n", encoding="utf-8")

    def fail_new(cls, schema_version=1):
        pytest.fail("malformed metadata reached new-vault initialization")

    monkeypatch.setattr(vault_module.XVaultMeta, "new", classmethod(fail_new))

    with pytest.raises(ValueError, match="^Unable to load vault meta:"):
        XVault(str(path), password=PASSWORD)


def test_nested_metadata_names_do_not_initialize_json_or_yaml(tmp_path):
    json_path = tmp_path / "nested.json"
    json_path.write_text('{"nested": {"_xvault": "invalid"}}\n', encoding="utf-8")
    yaml_path = tmp_path / "nested.yaml"
    yaml_path.write_text("nested:\n  _xvault: invalid\n", encoding="utf-8")

    assert XVault(str(json_path)).is_unitialized()
    assert XVault(str(yaml_path)).is_unitialized()


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
    assert [
        check for check in result["checks"] if check["name"] == "password-validation"
    ] == [{"name": "password-validation", "severity": "info", "message": "ok"}]
    assert [check for check in result["checks"] if check["name"] == "decryp"] == [
        {"name": "decryp", "severity": "info", "message": "ok"}
    ]


def test_validate_corrupted_encrypted_value_is_error(tmp_path):
    path, vault = make_initialized_vault(tmp_path)
    match = re.search(r"^SECRET=enc:(.+)$", vault._text, re.MULTILINE)
    payload = bytearray(base64.urlsafe_b64decode(match.group(1)))
    payload[-1] ^= 1
    corrupted = base64.urlsafe_b64encode(payload).decode()
    vault._text = vault._text[: match.start(1)] + corrupted + vault._text[match.end(1) :]

    result = vault.validate()

    assert result["status"] == "error"
    assert [
        check for check in result["checks"] if check["name"] == "password-validation"
    ] == [{"name": "password-validation", "severity": "info", "message": "ok"}]
    decryption_checks = [
        check for check in result["checks"] if check["name"] == "decryp"
    ]
    assert len(decryption_checks) == 1
    assert decryption_checks[0]["severity"] == "error"


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
    assert len(
        [check for check in result["checks"] if check["name"] == "password-validation"]
    ) == 1
    assert [check for check in result["checks"] if check["name"] == "decryp"] == [
        {"name": "decryp", "severity": "info", "message": "unavailable"}
    ]


def test_validate_corrupted_wrapped_key_metadata_is_error(tmp_path):
    _, vault = make_initialized_vault(tmp_path)
    wrapped = bytearray(base64.urlsafe_b64decode(vault._meta.encrypted_key))
    wrapped[-1] ^= 1
    vault._meta.encrypted_key = base64.urlsafe_b64encode(wrapped).decode()

    result = vault.validate()

    assert result["status"] == "error"
    assert [
        check for check in result["checks"] if check["name"] == "password-validation"
    ] == [
        {
            "name": "password-validation",
            "severity": "error",
            "message": "invalid password or metadata",
        }
    ]
    assert [check for check in result["checks"] if check["name"] == "decryp"] == [
        {"name": "decryp", "severity": "info", "message": "unavailable"}
    ]


def test_validate_malformed_wrapped_key_metadata_is_error(tmp_path):
    _, vault = make_initialized_vault(tmp_path)
    vault._meta.encrypted_key = "invalid-wrapped-key"

    result = vault.validate()

    assert result["status"] == "error"
    assert any(
        check["name"] == "encrypted-key" and check["severity"] == "error"
        for check in result["checks"]
    )


def test_validate_locked_vault_reports_authentication_and_decryption_unavailable(
    tmp_path,
):
    path, vault = make_initialized_vault(tmp_path)
    vault.lock()

    result = XVault(str(path)).validate()

    assert result["status"] == "warning"
    assert [
        check for check in result["checks"] if check["name"] == "password-validation"
    ] == [
        {"name": "password-validation", "severity": "info", "message": "unavailable"}
    ]
    assert [check for check in result["checks"] if check["name"] == "decryp"] == [
        {"name": "decryp", "severity": "info", "message": "unavailable"}
    ]


def test_validate_v1_fixture_keeps_single_successful_authentication_check(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(vault_module, "hash_secret_raw", hash_secret_raw)
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "v1.env"
    path.write_bytes(fixture.read_bytes())

    result = XVault(
        str(path), password="fixture-password", no_cache_key=True
    ).validate()

    assert result["status"] == "ok"
    assert [
        check for check in result["checks"] if check["name"] == "password-validation"
    ] == [{"name": "password-validation", "severity": "info", "message": "ok"}]
    assert [check for check in result["checks"] if check["name"] == "decryp"] == [
        {"name": "decryp", "severity": "info", "message": "ok"}
    ]


def test_validate_missing_and_invalid_metadata_are_errors(tmp_path):
    missing_path = tmp_path / "missing.env"
    missing_path.write_text("PLAIN=visible\n", encoding="utf-8")
    missing_result = XVault(str(missing_path)).validate()

    invalid_path, invalid_vault = make_initialized_vault(tmp_path)
    invalid_vault._meta.salt = "not-hex"
    invalid_result = invalid_vault.validate()

    assert missing_result["status"] == "warning"
    assert [
        check
        for check in missing_result["checks"]
        if check["name"] == "password-validation"
    ] == [
        {"name": "password-validation", "severity": "info", "message": "unavailable"}
    ]
    assert [
        check for check in missing_result["checks"] if check["name"] == "decryp"
    ] == [{"name": "decryp", "severity": "info", "message": "unavailable"}]
    assert invalid_result["status"] == "error"
    assert any(check["name"] == "salt" and check["severity"] == "error" for check in invalid_result["checks"])


def test_validate_warning_only_result_is_warning(tmp_path):
    path, vault = make_initialized_vault(tmp_path, encrypted=False)
    vault.lock()

    result = XVault(str(path)).validate()

    assert result["status"] == "warning"
    assert any(check["severity"] == "warning" for check in result["checks"])
    assert not any(check["severity"] == "error" for check in result["checks"])

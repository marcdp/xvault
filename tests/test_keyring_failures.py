import hashlib
from pathlib import Path

import pytest
from argon2.low_level import hash_secret_raw
from keyring.errors import PasswordDeleteError

from xvault import __main__ as cli
import xvault.xvault as vault_module
from xvault.xvault import XVault


def fast_deriver(secret, salt, **kwargs):
    return hashlib.sha256(secret + salt).digest()


@pytest.fixture(autouse=True)
def fast_key_derivation(monkeypatch):
    monkeypatch.setattr(vault_module, "hash_secret_raw", fast_deriver)


def make_v2_vault(tmp_path, password="old-password"):
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path), password=password)
    vault.set("SECRET", "secret-value")
    return path, vault


def test_lock_deletes_the_active_v2_credential(tmp_path, monkeypatch):
    path, vault = make_v2_vault(tmp_path)
    calls = []

    monkeypatch.setattr(
        "keyring.delete_password", lambda service, username: calls.append((service, username))
    )

    vault.lock()

    assert calls == [("xvault:v2:" + path.resolve().as_uri(), "username")]


def test_lock_deletes_the_active_v1_credential(tmp_path, monkeypatch):
    monkeypatch.setattr(vault_module, "hash_secret_raw", hash_secret_raw)
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "vault.env"
    path.write_bytes(fixture.read_bytes())
    vault = XVault(str(path), password="fixture-password")
    calls = []
    monkeypatch.setattr(
        "keyring.delete_password", lambda service, username: calls.append((service, username))
    )

    vault.lock()

    assert calls == [("xvault:" + path.resolve().as_uri(), "username")]


def test_lock_treats_an_absent_credential_as_already_removed(tmp_path, monkeypatch):
    _, vault = make_v2_vault(tmp_path)
    monkeypatch.setattr(
        "keyring.delete_password",
        lambda *args: (_ for _ in ()).throw(PasswordDeleteError("not found")),
    )

    vault.lock()


def test_lock_propagates_unexpected_keyring_errors(tmp_path, monkeypatch):
    _, vault = make_v2_vault(tmp_path)
    monkeypatch.setattr(
        "keyring.delete_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )

    with pytest.raises(RuntimeError, match="backend unavailable"):
        vault.lock()


def test_cli_does_not_report_lock_success_when_deletion_fails(
    monkeypatch, capsys
):
    class FailingVault:
        def __init__(self, path):
            pass

        @staticmethod
        def is_uninitialized_file(path):
            return False

        @staticmethod
        def is_locked_file(path):
            return False

        def lock(self):
            raise RuntimeError("backend unavailable")

    monkeypatch.setattr(cli.os.path, "exists", lambda path: True)
    monkeypatch.setattr(cli, "XVault", FailingVault)

    with pytest.raises(RuntimeError, match="backend unavailable"):
        cli.lock("vault.env")

    assert "locked." not in capsys.readouterr().out


def test_save_warns_but_keeps_committed_file_when_cache_write_fails(
    tmp_path, monkeypatch
):
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path), password="test-password")
    monkeypatch.setattr(
        "keyring.set_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )

    with pytest.warns(RuntimeWarning, match="Vault was saved, but key caching failed"):
        vault.set("SECRET", "secret-value")

    assert "secret-value" not in path.read_text(encoding="utf-8")
    assert (
        XVault(str(path), password="test-password", no_cache_key=True).get("SECRET")
        == "secret-value"
    )


def test_v2_rekey_warns_and_invalidates_stale_cache_after_commit(
    tmp_path, monkeypatch
):
    path, vault = make_v2_vault(tmp_path)
    ciphertext = vault._handler.getValue(vault._text, "SECRET")
    store_name = vault._get_keyring_store_name()
    monkeypatch.setattr(
        "keyring.set_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )

    with pytest.warns(
        RuntimeWarning, match="Vault password was changed, but key caching failed"
    ):
        vault.rekey("new-password")

    assert vault._meta.crypto_version == 2
    assert vault._handler.getValue(vault._text, "SECRET") == ciphertext
    assert vault_module.keyring.get_password(store_name, "username") is None
    assert (
        XVault(str(path), password="new-password", no_cache_key=True).get("SECRET")
        == "secret-value"
    )
    with pytest.raises(ValueError, match="invalid password"):
        XVault(str(path), password="old-password", no_cache_key=True)._validate_password()


def test_v2_rekey_reports_when_stale_cache_cannot_be_invalidated(
    tmp_path, monkeypatch
):
    path, vault = make_v2_vault(tmp_path)
    monkeypatch.setattr(
        "keyring.set_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("cache write failed")),
    )
    monkeypatch.setattr(
        "keyring.delete_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("cache delete failed")),
    )

    with pytest.warns(RuntimeWarning) as warning_records:
        vault.rekey("new-password")

    messages = [str(record.message) for record in warning_records]
    assert any("stale cached credential could not be removed" in message for message in messages)
    assert any("Vault password was changed, but key caching failed" in message for message in messages)
    assert all("old-password" not in message and "new-password" not in message for message in messages)
    assert (
        XVault(str(path), password="new-password", no_cache_key=True).get("SECRET")
        == "secret-value"
    )
    with pytest.raises(ValueError, match="invalid password"):
        XVault(str(path))._validate_password()


def test_v1_rekey_warns_but_keeps_committed_password_change(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(vault_module, "hash_secret_raw", hash_secret_raw)
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "vault.env"
    path.write_bytes(fixture.read_bytes())
    vault = XVault(str(path), password="fixture-password")
    monkeypatch.setattr(
        "keyring.set_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )

    with pytest.warns(RuntimeWarning, match="Vault was saved, but key caching failed"):
        vault.rekey("new-password")

    assert (
        XVault(str(path), password="new-password", no_cache_key=True).get("SECRET")
        == "fixture-secret"
    )
    with pytest.raises(ValueError, match="invalid password"):
        XVault(
            str(path), password="fixture-password", no_cache_key=True
        )._validate_password()


def test_upgrade_warns_but_keeps_committed_v2_file_when_cache_write_fails(
    tmp_path, monkeypatch
):
    monkeypatch.setattr(vault_module, "hash_secret_raw", hash_secret_raw)
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "vault.env"
    path.write_bytes(fixture.read_bytes())
    vault = XVault(str(path), password="fixture-password")
    monkeypatch.setattr(
        "keyring.set_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )

    with pytest.warns(RuntimeWarning, match="Vault upgrade was saved, but key caching failed"):
        vault.upgrade("fixture-password")

    assert vault._meta.crypto_version == 2
    reopened = XVault(
        str(path), password="fixture-password", no_cache_key=True
    )
    assert reopened.get("SECRET") == "fixture-secret"


def test_explicit_unlock_propagates_cache_write_failure(tmp_path, monkeypatch):
    _, vault = make_v2_vault(tmp_path)
    monkeypatch.setattr(
        "keyring.set_password",
        lambda *args: (_ for _ in ()).throw(RuntimeError("backend unavailable")),
    )

    with pytest.raises(RuntimeError, match="backend unavailable"):
        vault.unlock()


def test_cli_does_not_report_unlock_success_when_cache_write_fails(
    monkeypatch, capsys
):
    class FailingVault:
        def __init__(self, path, password=None):
            pass

        @staticmethod
        def is_locked_file(path):
            return True

        def unlock(self):
            raise RuntimeError("backend unavailable")

    monkeypatch.setattr(cli.os.path, "exists", lambda path: True)
    monkeypatch.setattr(cli, "XVault", FailingVault)
    monkeypatch.setattr(cli, "ask_password", lambda **kwargs: "test-password")

    with pytest.raises(RuntimeError, match="backend unavailable"):
        cli.unlock("vault.env")

    assert "unlocked." not in capsys.readouterr().out

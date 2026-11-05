import base64
import hashlib
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xvault.crypto import CryptoBase, CryptoV2
from xvault.crypto.v2 import DEK_AAD
from xvault.meta import XVaultMeta
from xvault.xvault import XVault


def fast_deriver(secret, salt, **kwargs):
    return hashlib.sha256(secret + salt).digest()


def new_crypto(password="test-password", random_bytes=None):
    meta = XVaultMeta.new()
    kwargs = {"key_deriver": fast_deriver}
    if random_bytes is not None:
        kwargs["random_bytes"] = random_bytes
    return meta, CryptoV2(meta, password=password, **kwargs)


def unwrap(meta, kek):
    blob = base64.urlsafe_b64decode(meta.encrypted_key)
    return AESGCM(kek).decrypt(blob[:12], blob[12:], DEK_AAD)


def test_v2_generates_and_wraps_one_random_32_byte_dek():
    generated = []

    def random_bytes(length):
        value = bytes([len(generated) + 1]) * length
        generated.append((length, value))
        return value

    meta, crypto = new_crypto(random_bytes=random_bytes)
    encrypted = crypto.encrypt("secret")
    kek = crypto.get_cacheable_key()

    assert isinstance(crypto, CryptoBase)
    assert [length for length, _ in generated].count(32) == 1
    assert len(unwrap(meta, kek)) == 32
    assert len(base64.urlsafe_b64decode(meta.encrypted_key)[:12]) == 12
    assert len(base64.urlsafe_b64decode(encrypted)[:12]) == 12


def test_v2_round_trip_unicode_and_keeps_encryption_randomized():
    _, crypto = new_crypto()
    encrypted = crypto.encrypt("Héllo 密码 🔐")
    assert crypto.decrypt(encrypted) == "Héllo 密码 🔐"
    assert crypto.encrypt("Héllo 密码 🔐") != encrypted


def test_v2_persists_across_instances_and_cached_kek():
    meta, first = new_crypto()
    encrypted = first.encrypt("secret")
    kek = first.get_cacheable_key()
    meta.metadata_present = True
    second = CryptoV2(
        XVaultMeta.from_dict(1, meta.to_dict()),
        cached_key_loader=lambda: base64.b64encode(kek).decode(),
        key_deriver=fast_deriver,
    )
    assert second.decrypt(encrypted) == "secret"


@pytest.mark.parametrize("corrupt_key", [False, True])
def test_v2_rejects_wrong_password_or_corrupted_wrapped_dek_without_regeneration(corrupt_key):
    meta, first = new_crypto()
    first.encrypt("secret")
    meta.metadata_present = True
    if corrupt_key:
        blob = bytearray(base64.urlsafe_b64decode(meta.encrypted_key))
        blob[-1] ^= 1
        meta.encrypted_key = base64.urlsafe_b64encode(blob).decode()
    calls = []
    second = CryptoV2(
        meta,
        password="wrong-password" if not corrupt_key else "test-password",
        key_deriver=fast_deriver,
        random_bytes=lambda n: calls.append(n) or bytes(n),
    )

    with pytest.raises(ValueError, match="invalid password or encrypted key"):
        second.validate_password()
    assert 32 not in calls


def test_v2_rejects_corrupted_secret_ciphertext():
    _, crypto = new_crypto()
    blob = bytearray(base64.urlsafe_b64decode(crypto.encrypt("secret")))
    blob[-1] ^= 1
    with pytest.raises(Exception):
        crypto.decrypt(base64.urlsafe_b64encode(blob).decode())


def test_v2_real_argon2_compatibility_vector():
    meta = XVaultMeta(
        1, 2, "00112233445566778899aabbccddeeff",
        encrypted_key="EBESExQVFhcYGRobDvg8IJKxIQV8wLGgnHJ5RqwUy1AkfZ-Q6xqTcoy1mohFfn_0XAEPzJHKNiKcoRL9",
    )
    crypto = CryptoV2(meta, password="fixture-v2-password")
    assert crypto.get_cacheable_key().hex() == "affb42bf079a283dc71abb6b0ece1984c792b19d1c86320e5e303aa9bb2858ad"
    assert crypto.decrypt("ICEiIyQlJicoKSortFPeBBnqfyNsTm-9pHuGnKSvnFJQIvMVoih6kwG6xYZI") == "fixture-v2-secret"


def test_fixed_v2_fixture_reopens(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "v2.env"
    path = tmp_path / "v2.env"
    path.write_bytes(fixture.read_bytes())
    vault = XVault(str(path), password="fixture-v2-password", no_cache_key=True)
    assert vault.info()["Crypto version"] == 2
    assert vault.get("SECRET") == "fixture-v2-secret"


def test_new_vault_defaults_to_v2_without_initializing_on_info(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text("SECRET=enc:plaintext\n", encoding="utf-8")
    before = path.read_bytes()
    vault = XVault(str(path))
    assert vault.info()["Crypto version"] == 2
    assert vault.info()["Status"] == "uninitialized"
    assert vault._meta.salt is None
    assert path.read_bytes() == before


def test_v2_rekey_changes_only_metadata_and_preserves_dek(tmp_path, monkeypatch):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path), password="old-password")
    vault.set("SECRET", "secret value")
    old_salt = vault._meta.salt
    old_wrapped = vault._meta.encrypted_key
    old_ciphertext = vault._handler.getValue(vault._text, "SECRET")
    old_dek = unwrap(vault._meta, vault._crypto.get_cacheable_key())

    vault.rekey("new-password")

    assert vault._meta.salt != old_salt
    assert vault._meta.encrypted_key != old_wrapped
    assert vault._handler.getValue(vault._text, "SECRET") == old_ciphertext
    assert unwrap(vault._meta, vault._crypto.get_cacheable_key()) == old_dek
    assert XVault(str(path), password="new-password", no_cache_key=True).get("SECRET") == "secret value"
    with pytest.raises(ValueError, match="invalid password"):
        XVault(str(path), password="old-password", no_cache_key=True)._validate_password()


def test_v2_failed_rekey_save_preserves_file_and_active_state(tmp_path, monkeypatch):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path), password="old-password")
    vault.set("SECRET", "secret value")
    before = path.read_bytes()
    old_meta = vault._meta
    monkeypatch.setattr(vault, "_write_vault", lambda *args: (_ for _ in ()).throw(OSError("save failed")))

    with pytest.raises(OSError, match="save failed"):
        vault.rekey("new-password")

    assert path.read_bytes() == before
    assert vault._meta is old_meta
    assert vault.get("SECRET") == "secret value"


def test_v2_failed_rekey_preparation_preserves_file_and_active_state(
    tmp_path, monkeypatch
):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path), password="old-password")
    vault.set("SECRET", "secret value")
    before = path.read_bytes()
    old_meta = vault._meta
    old_text = vault._text
    old_crypto = vault._crypto
    monkeypatch.setattr(
        vault._crypto,
        "_derive",
        lambda *args: (_ for _ in ()).throw(RuntimeError("derivation failed")),
    )

    with pytest.raises(RuntimeError, match="derivation failed"):
        vault.rekey("new-password")

    assert path.read_bytes() == before
    assert vault._meta is old_meta
    assert vault._text == old_text
    assert vault._crypto is old_crypto
    assert vault.get("SECRET") == "secret value"


def test_upgrade_v1_fixture_to_v2_and_reject_second_upgrade(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "vault.env"
    path.write_bytes(fixture.read_bytes())
    vault = XVault(str(path), password="fixture-password", no_cache_key=True)
    vault.upgrade("fixture-password")
    assert vault._meta.crypto_version == 2
    assert vault.get("SECRET") == "fixture-secret"
    assert b"fixture-secret" not in path.read_bytes()
    assert XVault(str(path), password="fixture-password", no_cache_key=True).get("SECRET") == "fixture-secret"
    with pytest.raises(ValueError, match="already uses"):
        vault.upgrade("fixture-password")


def test_failed_upgrade_preserves_original_v1_file(tmp_path, monkeypatch):
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "vault.env"
    path.write_bytes(fixture.read_bytes())
    vault = XVault(str(path), password="fixture-password", no_cache_key=True)
    before = path.read_bytes()
    monkeypatch.setattr(vault, "_write_vault", lambda *args: (_ for _ in ()).throw(OSError("save failed")))
    with pytest.raises(OSError, match="save failed"):
        vault.upgrade("fixture-password")
    assert path.read_bytes() == before
    assert vault._meta.crypto_version == 1
    assert vault.get("SECRET") == "fixture-secret"


@pytest.mark.parametrize(("suffix", "text"), [
    (".env", "SECRET=enc:format-secret\n"),
    (".json", '{"secret": "enc:format-secret"}\n'),
    (".jsonc", '{"secret": "enc:format-secret"}\n'),
    (".yaml", "secret: enc:format-secret\n"),
    (".md", "Secret: ${enc:format-secret}\n"),
    (".ovpn", "<auth-user-pass>\nenc:format-secret\n</auth-user-pass>\n"),
])
def test_v2_round_trips_all_supported_formats(tmp_path, monkeypatch, suffix, text):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    path = tmp_path / f"vault{suffix}"
    path.write_text(text, encoding="utf-8")
    vault = XVault(str(path), password="format-password", no_cache_key=True)
    vault._text = vault._encrypt(vault._text)
    vault._save()

    reopened = XVault(str(path), password="format-password", no_cache_key=True)
    assert "format-secret" in reopened.export()


def test_no_cache_key_never_touches_keyring(tmp_path, monkeypatch):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    monkeypatch.setattr("keyring.get_password", lambda *args: (_ for _ in ()).throw(AssertionError("read")))
    monkeypatch.setattr("keyring.set_password", lambda *args: (_ for _ in ()).throw(AssertionError("write")))
    monkeypatch.setattr("keyring.delete_password", lambda *args: (_ for _ in ()).throw(AssertionError("delete")))
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")

    vault = XVault(str(path), password="test-password", no_cache_key=True)
    vault.set("SECRET", "secret")
    vault.lock()

    assert XVault(str(path), password="test-password", no_cache_key=True).get("SECRET") == "secret"


def test_v1_and_v2_keyring_identities_are_distinct(tmp_path):
    path = tmp_path / "vault.env"
    path.write_text("PLAIN=visible\n", encoding="utf-8")
    vault = XVault(str(path))

    assert vault._get_keyring_store_name(1) == "xvault:" + path.resolve().as_uri()
    assert vault._get_keyring_store_name(2) == "xvault:v2:" + path.resolve().as_uri()

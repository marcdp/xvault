import base64
import hashlib
from pathlib import Path

import pytest

from xvault.crypto import CryptoBase, CryptoV1
from xvault.meta import META_CHECK_VALUE, XVaultMeta
from xvault.xvault import XVault


def fast_deriver(secret, salt, **kwargs):
    return hashlib.sha256(secret + salt).digest()


def test_crypto_v1_encrypts_and_decrypts_one_value():
    meta = XVaultMeta(1, crypto_version=1, salt="00" * 16, check=None)
    crypto = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)

    encrypted = crypto.encrypt("secret value")

    assert isinstance(crypto, CryptoBase)
    assert len(base64.urlsafe_b64decode(encrypted)[:12]) == 12
    assert crypto.decrypt(encrypted) == "secret value"


def test_crypto_v1_validates_metadata_check_value():
    meta = XVaultMeta(1, crypto_version=1, salt="11" * 16, check=None)
    crypto = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)
    meta.check = crypto.encrypt(META_CHECK_VALUE)

    crypto.validate_password()


def test_crypto_v1_caches_the_derived_key():
    meta = XVaultMeta(1, crypto_version=1, salt="22" * 16, check=None)
    crypto = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)

    first_key = crypto.get_key()

    assert crypto.get_key() is first_key


def test_crypto_v1_derives_the_same_key_for_the_same_password_and_salt():
    meta = XVaultMeta(1, crypto_version=1, salt="23" * 16, check=None)
    first = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)
    second = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)

    assert first.get_key() == second.get_key()


def test_crypto_v1_loads_an_existing_key_from_keyring():
    meta = XVaultMeta(1, crypto_version=1, salt="33" * 16, check=None)
    original = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)
    encoded_key = base64.b64encode(original.get_key()).decode()
    crypto = CryptoV1(meta, cached_key_loader=lambda: encoded_key)

    assert crypto.get_key() == original.get_key()


def test_crypto_v1_reuses_ciphertext_after_decryption():
    meta = XVaultMeta(1, crypto_version=1, salt="44" * 16, check=None)
    crypto = CryptoV1(meta, password="test-password", key_deriver=fast_deriver)
    encrypted = crypto.encrypt("secret value")

    assert crypto.decrypt(encrypted) == "secret value"
    assert crypto.encrypt("secret value") == encrypted


def test_crypto_v1_replaces_password_and_clears_ciphertext_cache():
    meta = XVaultMeta(1, crypto_version=1, salt="55" * 16, check=None)
    crypto = CryptoV1(meta, password="old-password", key_deriver=fast_deriver)
    old_key = crypto.get_key()
    old_encrypted = crypto.encrypt("secret value")
    assert crypto.decrypt(old_encrypted) == "secret value"

    crypto.replace_password("new-password")
    new_encrypted = crypto.encrypt("secret value")

    assert crypto.get_key() != old_key
    assert new_encrypted != old_encrypted
    assert crypto.decrypt(new_encrypted) == "secret value"


def test_xvault_selects_v1_and_rejects_an_unsupported_crypto_version(tmp_path, monkeypatch):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    path = tmp_path / "vault.env"
    path.write_text("VALUE=visible\n", encoding="utf-8")

    vault = XVault(str(path), password="test-password")

    assert isinstance(vault._crypto, CryptoV1)
    vault._meta.crypto_version = 2
    with pytest.raises(ValueError, match="unsupported crypto version"):
        vault._get_key()


def test_xvault_decrypts_fixed_v1_file_fixture(tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "v1.env"
    path = tmp_path / "v1.env"
    path.write_bytes(fixture.read_bytes())

    vault = XVault(str(path), password="fixture-password", no_cache_key=True)

    assert vault._meta.crypto_version == 1
    assert vault._meta.salt == "00112233445566778899aabbccddeeff"
    assert vault.get("SECRET") == "fixture-secret"


def test_rekey_keeps_the_v1_salt_and_reencrypts_values(tmp_path, monkeypatch):
    monkeypatch.setattr("xvault.xvault.hash_secret_raw", fast_deriver)
    path = tmp_path / "vault.env"
    path.write_text("VALUE=visible\n", encoding="utf-8")
    vault = XVault(str(path), password="old-password")
    vault.set("SECRET", "secret value")
    original_salt = vault._meta.salt

    vault.rekey("new-password")

    assert vault._meta.salt == original_salt
    assert XVault(str(path), password="new-password").get("SECRET") == "secret value"
    old_password_vault = XVault(str(path), password="old-password", no_cache_key=True)
    with pytest.raises(ValueError, match="invalid password"):
        old_password_vault._validate_password()

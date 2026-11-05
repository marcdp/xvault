import hashlib

import pytest

import xvault.xvault as vault_module
from xvault.crypto import CryptoV1
from xvault.handlers import HandlerEnv
from xvault.meta import META_CHECK_VALUE, XVaultMeta
from xvault.xvault import XVault


PASSWORD = "edit-password"
PLAINTEXT = "shared-secret"


def fast_deriver(secret, salt, **kwargs):
    return hashlib.sha256(secret + salt).digest()


@pytest.fixture(autouse=True)
def fast_key_derivation(monkeypatch):
    monkeypatch.setattr(vault_module, "hash_secret_raw", fast_deriver)


def make_vault(tmp_path, crypto_version):
    path = tmp_path / f"vault-v{crypto_version}.env"
    if crypto_version == 1:
        meta = XVaultMeta(1, 1, "12" * 16)
        crypto = CryptoV1(meta, password=PASSWORD, key_deriver=fast_deriver)
        meta.check = crypto.encrypt(META_CHECK_VALUE)
        first = crypto.encrypt(PLAINTEXT)
        second = crypto.encrypt(PLAINTEXT)
        text = f"FIRST=enc:{first}\nSECOND=enc:{second}\n"
        path.write_bytes(HandlerEnv().stringify(meta, text).encode("utf-8"))
    else:
        path.write_text("FIRST=enc:initial\n", encoding="utf-8")
        vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
        vault.set("FIRST", PLAINTEXT)
        vault.set("SECOND", PLAINTEXT)

    vault = XVault(str(path), password=PASSWORD, no_cache_key=True)
    assert ciphertext(vault, "FIRST") != ciphertext(vault, "SECOND")
    return vault


def ciphertext(vault, name):
    value = vault._handler.getValue(vault._text, name)
    assert value.startswith("enc:")
    return value[len("enc:") :]


def edit_with(monkeypatch, transform):
    class FakeEditor:
        def editText(self, text, **kwargs):
            return transform(text)

    monkeypatch.setattr(vault_module, "XEditor", FakeEditor)


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_noop_full_edit_preserves_distinct_ciphertexts(
    tmp_path, monkeypatch, crypto_version
):
    vault = make_vault(tmp_path, crypto_version)
    before = (ciphertext(vault, "FIRST"), ciphertext(vault, "SECOND"))
    edit_with(monkeypatch, lambda text: text)

    vault.edit()

    assert (ciphertext(vault, "FIRST"), ciphertext(vault, "SECOND")) == before


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_changing_one_duplicate_preserves_only_the_unchanged_token(
    tmp_path, monkeypatch, crypto_version
):
    vault = make_vault(tmp_path, crypto_version)
    first_before = ciphertext(vault, "FIRST")
    second_before = ciphertext(vault, "SECOND")
    edit_with(
        monkeypatch,
        lambda text: text.replace("SECOND=enc:shared-secret", "SECOND=enc:changed"),
    )

    vault.edit()

    assert ciphertext(vault, "FIRST") == first_before
    assert ciphertext(vault, "SECOND") != second_before
    assert vault.get("FIRST") == PLAINTEXT
    assert vault.get("SECOND") == "changed"


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_new_duplicate_gets_fresh_ciphertext(tmp_path, monkeypatch, crypto_version):
    vault = make_vault(tmp_path, crypto_version)
    before = (ciphertext(vault, "FIRST"), ciphertext(vault, "SECOND"))
    edit_with(monkeypatch, lambda text: text + "THIRD=enc:shared-secret\n")

    vault.edit()

    after = (
        ciphertext(vault, "FIRST"),
        ciphertext(vault, "SECOND"),
        ciphertext(vault, "THIRD"),
    )
    assert after[:2] == before
    assert len(set(after)) == 3
    assert vault.get("THIRD") == PLAINTEXT


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_insertion_and_deletion_preserve_identifiable_existing_token(
    tmp_path, monkeypatch, crypto_version
):
    vault = make_vault(tmp_path, crypto_version)
    second_before = ciphertext(vault, "SECOND")
    edit_with(
        monkeypatch,
        lambda text: "NEW=enc:new-secret\n"
        + text.replace("FIRST=enc:shared-secret\n", ""),
    )

    vault.edit()

    assert vault.get("FIRST") is None
    assert vault.get("NEW") == "new-secret"
    assert ciphertext(vault, "SECOND") == second_before


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_reordering_preserves_ciphertext_by_logical_field(
    tmp_path, monkeypatch, crypto_version
):
    vault = make_vault(tmp_path, crypto_version)
    before = {
        "FIRST": ciphertext(vault, "FIRST"),
        "SECOND": ciphertext(vault, "SECOND"),
    }
    edit_with(
        monkeypatch,
        lambda text: "SECOND=enc:shared-secret\nFIRST=enc:shared-secret\n",
    )

    vault.edit()

    assert ciphertext(vault, "FIRST") == before["FIRST"]
    assert ciphertext(vault, "SECOND") == before["SECOND"]


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_get_export_and_repeated_edits_do_not_influence_preservation(
    tmp_path, monkeypatch, crypto_version
):
    vault = make_vault(tmp_path, crypto_version)
    before = (ciphertext(vault, "FIRST"), ciphertext(vault, "SECOND"))
    assert vault.get("FIRST") == PLAINTEXT
    assert PLAINTEXT in vault.export()
    edit_with(monkeypatch, lambda text: text)

    vault.edit()
    vault.edit()

    assert (ciphertext(vault, "FIRST"), ciphertext(vault, "SECOND")) == before


@pytest.mark.parametrize("crypto_version", [1, 2])
def test_edit_encryption_failure_preserves_file_and_active_state(
    tmp_path, monkeypatch, crypto_version
):
    vault = make_vault(tmp_path, crypto_version)
    original_file = vault.path.read_bytes()
    original_text = vault._text
    original_meta = vault._meta.to_dict()
    edit_with(
        monkeypatch,
        lambda text: text.replace("SECOND=enc:shared-secret", "SECOND=enc:changed"),
    )
    monkeypatch.setattr(
        type(vault._crypto),
        "encrypt",
        lambda *args: (_ for _ in ()).throw(ValueError("encryption failed")),
    )

    with pytest.raises(ValueError, match="encryption failed"):
        vault.edit()

    assert vault.path.read_bytes() == original_file
    assert vault._text == original_text
    assert vault._meta.to_dict() == original_meta
    assert vault.get("FIRST") == PLAINTEXT

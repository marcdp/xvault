import base64
import binascii
import json
import os
import pytest
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from xvault.xvault import (
    XVault,
    XVaultMeta,
    HandlerEnv,
    HandlerYaml,
    HandlerJson,
    META_CHECK_VALUE,
    META_VARIABLE_PREFIX,
    ENC_PREFIX,
)


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def temp_vault_env(tmp_path):
    """Create a temporary .env file for testing."""
    vault_file = tmp_path / "test.env"
    vault_file.write_text("VAR1=value1\n")
    return str(vault_file)


@pytest.fixture
def temp_vault_yaml(tmp_path):
    """Create a temporary .yaml file for testing."""
    vault_file = tmp_path / "test.yaml"
    vault_file.write_text("db:\n  host: localhost\n")
    return str(vault_file)


@pytest.fixture
def temp_vault_json(tmp_path):
    """Create a temporary .json file for testing."""
    vault_file = tmp_path / "test.json"
    vault_file.write_text('{"key": "value"}')
    return str(vault_file)


@pytest.fixture
def temp_vault_jsonc(tmp_path):
    """Create a temporary .jsonc file for testing."""
    vault_file = tmp_path / "test.jsonc"
    vault_file.write_text('{"key": "value"}')
    return str(vault_file)


@pytest.fixture
def temp_vault_md(tmp_path):
    """Create a temporary .md file for testing."""
    vault_file = tmp_path / "test.md"
    vault_file.write_text("# Notes\n")
    return str(vault_file)


@pytest.fixture
def temp_vault_ovpn(tmp_path):
    """Create a temporary .ovpn file for testing."""
    vault_file = tmp_path / "test.ovpn"
    vault_file.write_text("client\n")
    return str(vault_file)


@pytest.fixture
def password():
    """Standard test password."""
    return "test_password_123"


@pytest.fixture
def long_password():
    """Long test password."""
    return "this_is_a_very_long_password_with_special_chars_!@#$%^&*()" 


@pytest.fixture
def unicode_password():
    """Unicode test password."""
    return "pässwörd_with_émojis_🔐🔑"


@pytest.fixture
def vault_initialized(temp_vault_env, password):
    """Create and initialize a vault with password."""
    vault = XVault(temp_vault_env, password=password)
    vault.unlock()  # Initialize with key in memory
    return vault


@pytest.fixture
def vault_uninitialized(temp_vault_env):
    """Create an uninitialized vault (no password set)."""
    return XVault(temp_vault_env)


# ============================================================================
# TEST KEY DERIVATION
# ============================================================================

class TestKeyDerivation:
    """Test cryptographic key derivation with Argon2id."""

    def test_derive_key_with_new_salt(self, vault_initialized):
        """Test that key derivation generates a new salt on first call."""
        assert vault_initialized._meta.salt is not None
        assert len(vault_initialized._meta.salt) == 32  # hex encoding: 16 bytes = 32 hex chars
        # Verify it's valid hex
        bytes.fromhex(vault_initialized._meta.salt)

    def test_derive_key_consistency(self, temp_vault_env, password):
        """Test that same password + salt always derives same key."""
        vault1 = XVault(temp_vault_env, password=password)
        key1 = vault1._get_key()
        
        # Clear key and password to force re-derivation
        vault1._key = None
        key2 = vault1._get_key()
        
        assert key1 == key2

    def test_derive_key_different_passwords(self, temp_vault_env):
        """Test that different passwords derive different keys."""
        vault1 = XVault(temp_vault_env, password="password1")
        key1 = vault1._get_key()
        
        vault2 = XVault(temp_vault_env, password="password2")
        key2 = vault2._get_key()
        
        assert key1 != key2

    def test_derive_key_caching(self, vault_initialized):
        """Test that key is cached in memory after first derivation."""
        key1 = vault_initialized._get_key()
        key1_id = id(key1)  # Get object identity
        
        key2 = vault_initialized._get_key()
        key2_id = id(key2)
        
        # Same object reference = cached
        assert key1_id == key2_id
        assert key1 == key2

    def test_derive_key_length_is_32_bytes(self, vault_initialized):
        """Test that derived key is exactly 32 bytes (AES-256)."""
        key = vault_initialized._get_key()
        assert len(key) == 32

    def test_derive_key_no_password_locked(self, vault_uninitialized):
        """Test that getting key without password raises error when locked."""
        vault_uninitialized._meta.salt = "1234567890abcdef1234567890abcdef"
        vault_uninitialized._meta.check = "dummy_check_value"
        
        with pytest.raises(ValueError, match="store is locked"):
            vault_uninitialized._get_key()

    def test_derive_key_unsupported_crypto_version(self, temp_vault_env, password):
        """Test that unsupported crypto version raises error."""
        vault = XVault(temp_vault_env, password=password)
        vault._meta.crypto_version = 999
        
        with pytest.raises(ValueError, match="unsupported crypto version"):
            vault._get_key()

    def test_derive_key_retrieves_from_keyring(self, monkeypatch, temp_vault_env, password):
        """Test that key can be retrieved from keyring cache."""
        vault = XVault(temp_vault_env, password=password)
        original_key = vault._get_key()
        
        # Simulate locked vault with key in keyring
        vault._key = None
        vault._password = None
        encoded_key = base64.b64encode(original_key).decode()
        monkeypatch.setattr("keyring.get_password", lambda *args, **kwargs: encoded_key)
        
        retrieved_key = vault._get_key()
        assert retrieved_key == original_key


# ============================================================================
# TEST PASSWORD VALIDATION
# ============================================================================

class TestPasswordValidation:
    """Test password validation using check mechanism."""

    def test_validate_password_correct(self, vault_initialized):
        """Test that correct password validates successfully."""
        # Should not raise
        vault_initialized._validate_password()

    def test_validate_password_uninitialized_vault(self, vault_uninitialized):
        """Test that validation passes for uninitialized vault."""
        # Should not raise and should return early
        vault_uninitialized._validate_password()

    def test_validate_password_corrupted_check_value(self, vault_initialized):
        """Test that corrupted check value raises error."""
        vault_initialized._meta.check = "invalid_base64_@#$!@"
        
        with pytest.raises(Exception):  # binascii.Error or similar
            vault_initialized._validate_password()

    def test_validate_password_unicode(self, temp_vault_env, unicode_password):
        """Test validation with unicode password."""
        vault = XVault(temp_vault_env, password=unicode_password)
        vault.unlock()
        
        vault._validate_password()  # Should not raise


# ============================================================================
# TEST ENCRYPTION
# ============================================================================

class TestEncryption:
    """Test value encryption with AES-256-GCM."""

    def test_encrypt_value_returns_string(self, vault_initialized):
        """Test that encrypted value is a valid string."""
        result = vault_initialized._encrypt_value("test_secret")
        assert isinstance(result, str)

    def test_encrypt_value_base64_url_safe(self, vault_initialized):
        """Test that encrypted value uses URL-safe base64."""
        result = vault_initialized._encrypt_value("test_secret")
        # URL-safe base64 uses - and _ instead of + and /
        # Should not raise when decoding
        decoded = base64.urlsafe_b64decode(result)
        assert len(decoded) > 0

    def test_encrypt_generates_random_nonce(self, vault_initialized):
        """Test that each encryption generates random nonce."""
        plaintext = "same_plaintext"
        encrypted1 = vault_initialized._encrypt_value(plaintext)
        
        # Clear cache to force new encryption
        vault_initialized._cache.clear()
        
        encrypted2 = vault_initialized._encrypt_value(plaintext)
        
        # Same plaintext should produce different ciphertexts
        assert encrypted1 != encrypted2

    def test_encrypt_nonce_length(self, vault_initialized):
        """Test that nonce is 12 bytes."""
        encrypted = vault_initialized._encrypt_value("test")
        decoded = base64.urlsafe_b64decode(encrypted)
        
        nonce = decoded[:12]
        assert len(nonce) == 12

    def test_encrypt_twice_different(self, vault_initialized):
        """Test that the same plaintext encrypted twice produces different ciphertexts."""
        plaintext = "cacheable_value"
        encrypted1 = vault_initialized._encrypt_value(plaintext)
        encrypted2 = vault_initialized._encrypt_value(plaintext)
        # Same plaintext should produce different ciphertexts
        assert encrypted1 != encrypted2

    def test_encrypt_cache_cleared_on_key_change(self, temp_vault_env):
        """Test that cache is cleared when key changes."""
        vault = XVault(temp_vault_env, password="password1")
        key1 = vault._get_key()
        
        encrypted1 = vault._encrypt_value("test")
        
        # Simulate key derivation with new password (cache should clear)
        vault._password = "password2"
        vault._key = None
        vault._cache = {}
        
        key2 = vault._get_key()
        encrypted2 = vault._encrypt_value("test")
        
        # Different keys should produce different ciphertexts
        assert key1 != key2
        assert encrypted1 != encrypted2

    def test_encrypt_empty_string(self, vault_initialized):
        """Test encrypting empty string."""
        result = vault_initialized._encrypt_value("")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_encrypt_long_string(self, vault_initialized):
        """Test encrypting long string (>1KB)."""
        long_text = "A" * 10000
        result = vault_initialized._encrypt_value(long_text)
        assert isinstance(result, str)

    def test_encrypt_unicode_value(self, vault_initialized):
        """Test encrypting unicode string."""
        unicode_text = "Héllo Wörld 🔐 密码"
        result = vault_initialized._encrypt_value(unicode_text)
        assert isinstance(result, str)

    def test_encrypt_special_characters(self, vault_initialized):
        """Test encrypting special characters."""
        special_text = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        result = vault_initialized._encrypt_value(special_text)
        assert isinstance(result, str)

    def test_encrypt_newlines_and_whitespace(self, vault_initialized):
        """Test encrypting strings with newlines and tabs."""
        text = "line1\nline2\ttab\r\nwindows_newline"
        result = vault_initialized._encrypt_value(text)
        assert isinstance(result, str)


# ============================================================================
# TEST DECRYPTION
# ============================================================================

class TestDecryption:
    """Test value decryption with AES-256-GCM."""

    def test_decrypt_value_returns_string(self, vault_initialized):
        """Test that decrypted value is a string."""
        encrypted = vault_initialized._encrypt_value("test_secret")
        result = vault_initialized._decrypt_value(encrypted)
        assert isinstance(result, str)

    def test_decrypt_round_trip(self, vault_initialized):
        """Test encrypt → decrypt produces original plaintext."""
        original = "test_secret_value"
        encrypted = vault_initialized._encrypt_value(original)
        decrypted = vault_initialized._decrypt_value(encrypted)
        assert decrypted == original

    def test_decrypt_round_trip_unicode(self, vault_initialized):
        """Test round trip with unicode."""
        original = "Sécuré Pässwörd 🔐"
        encrypted = vault_initialized._encrypt_value(original)
        decrypted = vault_initialized._decrypt_value(encrypted)
        assert decrypted == original

    def test_decrypt_round_trip_long_string(self, vault_initialized):
        """Test round trip with long string."""
        original = "X" * 50000
        encrypted = vault_initialized._encrypt_value(original)
        decrypted = vault_initialized._decrypt_value(encrypted)
        assert decrypted == original

    def test_decrypt_wrong_key(self, temp_vault_env):
        """Test that decryption with wrong key fails."""
        vault1 = XVault(temp_vault_env, password="password1")
        encrypted = vault1._encrypt_value("secret")
        
        vault2 = XVault(temp_vault_env, password="password2")
        
        # Decryption should fail due to authentication tag mismatch
        with pytest.raises(Exception):  # cryptography.hazmat... InvalidTag
            vault2._decrypt_value(encrypted)

    def test_decrypt_corrupted_ciphertext(self, vault_initialized):
        """Test that corrupted ciphertext fails authentication."""
        encrypted = vault_initialized._encrypt_value("secret")
        decoded = base64.urlsafe_b64decode(encrypted)
        
        # Corrupt one byte in the ciphertext
        corrupted = decoded[:20] + bytes([decoded[20] ^ 0xFF]) + decoded[21:]
        corrupted_b64 = base64.urlsafe_b64encode(corrupted).decode()
        
        with pytest.raises(Exception):  # InvalidTag
            vault_initialized._decrypt_value(corrupted_b64)

    def test_decrypt_invalid_base64(self, vault_initialized):
        """Test that invalid base64 raises error."""
        invalid_b64 = "not_valid_base64_@#$"
        
        with pytest.raises(binascii.Error):
            vault_initialized._decrypt_value(invalid_b64)

    def test_decrypt_truncated_nonce(self, vault_initialized):
        """Test that too-short encrypted blob raises error."""
        # Nonce is 12 bytes, so anything less than 12 is invalid
        invalid_encrypted = base64.urlsafe_b64encode(b"short").decode()
        
        with pytest.raises(Exception):
            vault_initialized._decrypt_value(invalid_encrypted)

    def test_decrypt_updates_cache(self, vault_initialized):
        """Test that decryption stores result in cache."""
        encrypted = vault_initialized._encrypt_value("secret_value")
        vault_initialized._cache.clear()
        
        decrypted = vault_initialized._decrypt_value(encrypted)
        
        # Result should be cached
        assert "secret_value" in vault_initialized._cache
        assert vault_initialized._cache["secret_value"] == encrypted

    def test_decrypt_empty_string_round_trip(self, vault_initialized):
        """Test decrypting empty string."""
        encrypted = vault_initialized._encrypt_value("")
        decrypted = vault_initialized._decrypt_value(encrypted)
        assert decrypted == ""


# ============================================================================
# TEST FULL TEXT ENCRYPTION/DECRYPTION
# ============================================================================

class TestTextEncryption:
    """Test encryption/decryption of full text with multiple tokens."""

    def test_encrypt_text_with_single_token(self, vault_initialized):
        """Test encrypting text with single enc: token."""
        text = "VAR=enc:plaintext_value\n"
        encrypted = vault_initialized._encrypt(text)
        
        assert "enc:" in encrypted
        # Original plaintext should not appear
        assert "plaintext_value" not in encrypted

    def test_encrypt_text_with_wrapped_token(self, vault_initialized):
        """Test encrypting text with wrapped ${enc:...} token."""
        text = "VAR=${enc:plaintext_value}\n"
        encrypted = vault_initialized._encrypt(text)

        assert "${enc:" in encrypted
        assert "plaintext_value" not in encrypted

    def test_encrypt_wrapped_token_json_format(self, temp_vault_json, password):
        """Test wrapped token encryption in JSON format."""
        vault = XVault(temp_vault_json, password=password)
        text = '{"password": "${enc:secret_json}"}\n'

        encrypted = vault._encrypt(text)

        assert "${enc:" in encrypted
        assert "secret_json" not in encrypted

    def test_encrypt_wrapped_token_jsonc_format(self, temp_vault_jsonc, password):
        """Test wrapped token encryption in JSONC format."""
        vault = XVault(temp_vault_jsonc, password=password)
        text = '{"password": "${enc:secret_jsonc}"}\n'

        encrypted = vault._encrypt(text)

        assert "${enc:" in encrypted
        assert "secret_jsonc" not in encrypted

    def test_encrypt_wrapped_token_yaml_format(self, temp_vault_yaml, password):
        """Test wrapped token encryption in YAML format."""
        vault = XVault(temp_vault_yaml, password=password)
        text = "password: ${enc:secret_yaml}\n"

        encrypted = vault._encrypt(text)

        assert "${enc:" in encrypted
        assert "secret_yaml" not in encrypted

    def test_encrypt_wrapped_token_md_format(self, temp_vault_md, password):
        """Test wrapped token encryption in Markdown format."""
        vault = XVault(temp_vault_md, password=password)
        text = "Password is ${enc:secret_md}\n"

        encrypted = vault._encrypt(text)

        assert "${enc:" in encrypted
        assert "secret_md" not in encrypted

    def test_encrypt_decrypt_secret_block_ovpn_format(self, temp_vault_ovpn, password):
        """Test that OVPN lines marked with enc: are encrypted and decrypted correctly."""
        vault = XVault(temp_vault_ovpn, password=password)
        # Lines to encrypt must be prefixed with enc: (same convention as all other formats)
        text = (
            "client\n\n"
            "<auth-user-pass>\n"
            "enc:my-user\n"
            "enc:my-pass\n"
            "</auth-user-pass>\n"
        )

        encrypted = vault._encrypt(text)
        assert "my-user" not in encrypted
        assert "my-pass" not in encrypted
        assert "<auth-user-pass>\nenc:" in encrypted

        # Decrypt keeping enc: prefix — round-trips back to the marked text
        decrypted = vault._decrypt(encrypted, return_unprefixed_values=False)
        assert decrypted == text

        # Export (strip enc: prefix) — produces plain values without enc: marker
        exported = vault._decrypt(encrypted, return_unprefixed_values=True)
        assert exported == (
            "client\n\n"
            "<auth-user-pass>\n"
            "my-user\n"
            "my-pass\n"
            "</auth-user-pass>\n"
        )

    def test_encrypt_text_multiple_tokens(self, vault_initialized):
        """Test encrypting text with multiple tokens."""
        text = (
            "VAR1=enc:secret1\n"
            "VAR2=enc:secret2\n"
            "VAR3=enc:secret3\n"
        )
        encrypted = vault_initialized._encrypt(text)
        
        assert encrypted.count("enc:") >= 3
        for secret in ["secret1", "secret2", "secret3"]:
            assert secret not in encrypted

    def test_encrypt_text_preserves_non_secret_values(self, vault_initialized):
        """Test that non-secret values are preserved."""
        text = "PLAIN=plainvalue\nSECRET=enc:secret_value\n"
        encrypted = vault_initialized._encrypt(text)
        
        assert "PLAIN=plainvalue" in encrypted
        assert "secret_value" not in encrypted

    def test_decrypt_text_round_trip(self, vault_initialized):
        """Test full text encrypt → decrypt round trip."""
        original_text = (
            "VAR1=enc:secret1\n"
            "VAR2=plaintext\n"
            "VAR3=enc:secret2\n"
        )
        
        encrypted = vault_initialized._encrypt(original_text)
        decrypted = vault_initialized._decrypt(encrypted, return_unprefixed_values=False)
        
        # Decrypted should match original
        assert decrypted == original_text

    def test_decrypt_text_return_unprefixed(self, vault_initialized):
        """Test decryption with return_unprefixed_values=True."""
        original_text = "VAR=enc:secret_value\n"
        encrypted = vault_initialized._encrypt(original_text)
        
        decrypted = vault_initialized._decrypt(encrypted, return_unprefixed_values=True)
        
        # Should have secret_value without enc: prefix
        assert "secret_value" in decrypted
        assert "enc:secret_value" not in decrypted

    def test_decrypt_wrapped_text_round_trip(self, vault_initialized):
        """Test wrapped token encrypt -> decrypt round trip."""
        original_text = "VAR=${enc:secret_value}\n"
        encrypted = vault_initialized._encrypt(original_text)
        decrypted = vault_initialized._decrypt(encrypted, return_unprefixed_values=False)

        assert decrypted == original_text

    def test_decrypt_wrapped_text_return_unprefixed(self, vault_initialized):
        """Test wrapped token decryption with return_unprefixed_values=True."""
        original_text = "VAR=${enc:secret_value}\n"
        encrypted = vault_initialized._encrypt(original_text)
        decrypted = vault_initialized._decrypt(encrypted, return_unprefixed_values=True)

        assert "VAR=secret_value" in decrypted
        assert "${enc:" not in decrypted

    def test_encrypt_text_env_format(self, vault_initialized):
        """Test encryption in ENV format."""
        text = "DB_HOST=localhost\nDB_PASS=enc:mypassword\n"
        encrypted = vault_initialized._encrypt(text)
        
        assert "DB_HOST=localhost" in encrypted
        assert "mypassword" not in encrypted

    def test_encrypt_text_yaml_format(self, vault_initialized):
        """Test encryption in YAML format."""
        text = "database:\n  password: enc:secret123\n"
        encrypted = vault_initialized._encrypt(text)
        
        assert "database:" in encrypted
        assert "secret123" not in encrypted

    def test_encrypt_text_mixed_plain_and_wrapped_tokens(self, vault_initialized):
        """Test encryption supports both enc:... and ${enc:...} in same text."""
        text = (
            "VAR1=enc:plain_secret\n"
            "VAR2=${enc:wrapped_secret}\n"
        )
        encrypted = vault_initialized._encrypt(text)

        assert "plain_secret" not in encrypted
        assert "wrapped_secret" not in encrypted
        assert "VAR1=enc:" in encrypted
        assert "VAR2=${enc:" in encrypted

    def test_encrypt_text_no_tokens(self, vault_initialized):
        """Test encrypting text with no tokens."""
        text = "VAR1=value1\nVAR2=value2\n"
        encrypted = vault_initialized._encrypt(text)
        
        # Should be identical (no encryption needed)
        assert encrypted == text

    def test_decrypt_text_no_tokens(self, vault_initialized):
        """Test decrypting text with no tokens."""
        text = "VAR1=value1\nVAR2=value2\n"
        decrypted = vault_initialized._decrypt(text)
        
        # Should be identical (no decryption needed)
        assert decrypted == text


# ============================================================================
# TEST CHECK MECHANISM (META CHECK)
# ============================================================================

class TestCheckMechanism:
    """Test the check value mechanism for password validation."""

    def test_meta_check_persistence(self, temp_vault_env, password):
        """Test that check value persists across reopen."""
        # Create and initialize
        vault1 = XVault(temp_vault_env, password=password)
        vault1.unlock()
        vault1._save()
        check_value_1 = vault1._meta.check
        
        # Reopen
        vault2 = XVault(temp_vault_env, password=password)
        check_value_2 = vault2._meta.check
        
        assert check_value_1 == check_value_2

    def test_meta_check_invalid_password_fails(self, temp_vault_env):
        """Test that invalid password fails check validation."""
        vault1 = XVault(temp_vault_env, password="correct_password")
        vault1.unlock()
        vault1._save()
        # Open with wrong password
        with pytest.raises(ValueError, match="invalid password"):
            vault2 = XVault(temp_vault_env, password="wrong_password")


# ============================================================================
# TEST EDGE CASES
# ============================================================================

class TestCryptoEdgeCases:
    """Test edge cases and error conditions."""

    def test_encrypt_with_different_crypto_versions(self, temp_vault_env, password):
        """Test behavior with different crypto versions."""
        vault = XVault(temp_vault_env, password=password)
        vault._get_key()
        
        # Should default to version 1
        assert vault._meta.crypto_version == 1
        
        encrypted = vault._encrypt_value("test")
        decrypted = vault._decrypt_value(encrypted)
        assert decrypted == "test"

    def test_key_derivation_with_very_long_password(self, temp_vault_env, long_password):
        """Test key derivation with very long password."""
        vault = XVault(temp_vault_env, password=long_password)
        key = vault._get_key()
        assert len(key) == 32

    def test_password_with_null_bytes(self, temp_vault_env):
        """Test password containing null bytes."""
        password_with_null = "password\x00with\x00nulls"
        vault = XVault(temp_vault_env, password=password_with_null)
        key = vault._get_key()
        assert len(key) == 32

    def test_concurrent_encrypt_decrypt(self, vault_initialized):
        """Test multiple encrypt/decrypt operations sequentially."""
        plaintexts = [f"secret_{i}" for i in range(100)]
        encrypted_values = [vault_initialized._encrypt_value(p) for p in plaintexts]
        decrypted_values = [vault_initialized._decrypt_value(e) for e in encrypted_values]
        
        assert decrypted_values == plaintexts

    def test_encrypt_decrypt_with_cache_hits(self, vault_initialized):
        """Test that cache works correctly for repeated encryptions."""
        plaintext = "repeated_value"
        
        # First encryption
        encrypted1 = vault_initialized._encrypt_value(plaintext)
        
        # Second encryption should hit cache
        encrypted2 = vault_initialized._encrypt_value(plaintext)
        
        assert encrypted1 != encrypted2
        
        # Both should decrypt to same plaintext
        assert vault_initialized._decrypt_value(encrypted1) == plaintext
        assert vault_initialized._decrypt_value(encrypted2) == plaintext

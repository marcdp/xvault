import base64
import os
from collections.abc import Callable
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..meta import META_CHECK_VALUE, XVaultMeta
from .base import CryptoBase


class CryptoV1(CryptoBase):
    """The original Argon2id and AES-256-GCM vault cryptography."""

    def __init__(
        self,
        meta: XVaultMeta,
        password: Optional[str] = None,
        cached_key_loader: Optional[Callable[[], Optional[str]]] = None,
        key_deriver: Callable[..., bytes] = hash_secret_raw,
    ):
        self._meta = meta
        self._password = password
        self._key: Optional[bytes] = None
        self._cached_key_loader = cached_key_loader
        self._key_deriver = key_deriver

    def get_key(self) -> bytes:
        """Return the cached, keyring-backed, or newly derived version 1 key."""
        if self._password is None and self._key is None and self._cached_key_loader:
            encoded_key = self._cached_key_loader()
            if encoded_key:
                self._key = base64.b64decode(encoded_key)

        if self._meta.crypto_version != 1:
            raise ValueError(
                f"Unable to get key: unsupported crypto version in meta: "
                f"{self._meta.crypto_version}"
            )
        if self._key is not None:
            return self._key
        if not self._password:
            raise ValueError("Unable to get key: store is locked. Password required.")

        if not self._meta.salt:
            self._meta.salt = os.urandom(16).hex()
        self._key = self._key_deriver(
            secret=self._password.encode(),
            salt=bytes.fromhex(self._meta.salt),
            time_cost=5,
            memory_cost=131072,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )
        self._password = None
        return self._key

    def get_cacheable_key(self) -> bytes:
        return self.get_key()

    def validate_password(self) -> None:
        if not self._meta.check:
            return
        try:
            value = self.decrypt(self._meta.check)
        except Exception as error:
            raise ValueError("Unable to validate password: invalid password") from error
        if value != META_CHECK_VALUE:
            raise ValueError("Unable to validate password: invalid password")

    def encrypt(self, value: str) -> str:
        key = self.get_key()
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, value.encode("utf-8"), None)
        encrypted_blob = nonce + ciphertext
        return base64.urlsafe_b64encode(encrypted_blob).decode("utf-8")

    def decrypt(self, encrypted_value: str) -> str:
        key = self.get_key()
        encrypted_blob = base64.urlsafe_b64decode(encrypted_value)
        nonce = encrypted_blob[:12]
        ciphertext = encrypted_blob[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, None).decode("utf-8")

    def replace_password(self, password: str) -> None:
        self._key = None
        self._password = password

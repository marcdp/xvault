import base64
import binascii
import os
from collections.abc import Callable
from dataclasses import dataclass
from typing import Optional

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..meta import XVaultMeta
from .base import CryptoBase


DEK_AAD = b"xvault:v2:dek"


@dataclass(frozen=True)
class PasswordRotation:
    """Opaque candidate state used to commit a v2 password rotation safely."""

    meta: XVaultMeta
    kek: bytes
    dek: bytes


class CryptoV2(CryptoBase):
    """Envelope encryption using a password-derived KEK and random DEK."""

    def __init__(
        self,
        meta: XVaultMeta,
        password: Optional[str] = None,
        cached_key_loader: Optional[Callable[[], Optional[str]]] = None,
        key_deriver: Callable[..., bytes] = hash_secret_raw,
        random_bytes: Callable[[int], bytes] = os.urandom,
    ):
        if meta.crypto_version != 2:
            raise ValueError(f"Unsupported crypto version: {meta.crypto_version}")
        self._meta = meta
        self._password = password
        self._kek: Optional[bytes] = None
        self._dek: Optional[bytes] = None
        self._cached_key_loader = cached_key_loader
        self._key_deriver = key_deriver
        self._random_bytes = random_bytes

    @staticmethod
    def _decode_blob(value: str, description: str) -> bytes:
        try:
            return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
        except (ValueError, UnicodeEncodeError, binascii.Error) as error:
            raise ValueError(f"Invalid {description} encoding") from error

    def _derive(self, password: str, salt: bytes) -> bytes:
        return self._key_deriver(
            secret=password.encode(), salt=salt, time_cost=5, memory_cost=131072,
            parallelism=4, hash_len=32, type=Type.ID,
        )

    def _get_kek(self) -> bytes:
        if self._meta.crypto_version != 2:
            raise ValueError(
                f"Unable to get key: unsupported crypto version in meta: {self._meta.crypto_version}"
            )
        if self._kek is not None:
            return self._kek
        if self._password is None and self._cached_key_loader:
            encoded_key = self._cached_key_loader()
            if encoded_key:
                try:
                    candidate = base64.b64decode(encoded_key, validate=True)
                except (ValueError, binascii.Error) as error:
                    raise ValueError("Unable to validate password: invalid cached key") from error
                if len(candidate) != 32:
                    raise ValueError("Unable to validate password: invalid cached key")
                self._kek = candidate
        if self._kek is not None:
            return self._kek
        if not self._password:
            raise ValueError("Unable to get key: store is locked. Password required.")
        if not self._meta.salt:
            if self._meta.metadata_present:
                raise ValueError("Unable to load vault meta: v2 salt is missing")
            self._meta.salt = self._random_bytes(16).hex()
        try:
            salt = bytes.fromhex(self._meta.salt)
        except ValueError as error:
            raise ValueError("Unable to load vault meta: v2 salt is not hexadecimal") from error
        if len(salt) != 16:
            raise ValueError("Unable to load vault meta: v2 salt must be 16 bytes")
        self._kek = self._derive(self._password, salt)
        self._password = None
        return self._kek

    def _wrap_dek(self, dek: bytes, kek: bytes) -> str:
        nonce = self._random_bytes(12)
        blob = nonce + AESGCM(kek).encrypt(nonce, dek, DEK_AAD)
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def _unwrap_dek(self, encrypted_key: str, kek: bytes) -> bytes:
        blob = self._decode_blob(encrypted_key, "wrapped DEK")
        if len(blob) != 60:
            raise ValueError("Invalid wrapped DEK length")
        try:
            dek = AESGCM(kek).decrypt(blob[:12], blob[12:], DEK_AAD)
        except InvalidTag as error:
            raise ValueError("Unable to validate password: invalid password or encrypted key") from error
        if len(dek) != 32:
            raise ValueError("Invalid unwrapped DEK length")
        return dek

    def _get_dek(self) -> bytes:
        if self._dek is not None:
            return self._dek
        kek = self._get_kek()
        if self._meta.metadata_present:
            if not self._meta.encrypted_key:
                raise ValueError("Unable to load vault meta: v2 encrypted_key is missing")
            self._dek = self._unwrap_dek(self._meta.encrypted_key, kek)
            return self._dek
        self._dek = self._random_bytes(32)
        if len(self._dek) != 32:
            raise ValueError("Unable to generate a 32-byte DEK")
        self._meta.encrypted_key = self._wrap_dek(self._dek, kek)
        return self._dek

    def get_cacheable_key(self) -> bytes:
        if self._meta.metadata_present:
            self.validate_password()
        else:
            self._get_dek()
        return self._get_kek()

    def validate_password(self) -> None:
        if self._meta.metadata_present:
            if not self._meta.encrypted_key:
                raise ValueError("Unable to load vault meta: v2 encrypted_key is missing")
            dek = self._unwrap_dek(self._meta.encrypted_key, self._get_kek())
            if self._dek is not None and self._dek != dek:
                raise ValueError("Unable to validate password: encrypted key changed")
            self._dek = dek

    def encrypt(self, value: str) -> str:
        dek = self._get_dek()
        nonce = self._random_bytes(12)
        blob = nonce + AESGCM(dek).encrypt(nonce, value.encode("utf-8"), None)
        return base64.urlsafe_b64encode(blob).decode("ascii")

    def decrypt(self, encrypted_value: str) -> str:
        dek = self._get_dek()
        blob = self._decode_blob(encrypted_value, "ciphertext")
        if len(blob) < 28:
            raise ValueError("Invalid ciphertext length")
        return AESGCM(dek).decrypt(blob[:12], blob[12:], None).decode("utf-8")

    def prepare_password_rotation(self, password: str) -> PasswordRotation:
        if not password:
            raise ValueError("Unable to rekey: new password cannot be empty")
        dek = self._get_dek()
        salt = self._random_bytes(16)
        kek = self._derive(password, salt)
        meta = XVaultMeta(
            self._meta.schema_version, 2, salt.hex(),
            encrypted_key=self._wrap_dek(dek, kek), metadata_present=True,
        )
        return PasswordRotation(meta=meta, kek=kek, dek=dek)

    def activate_password_rotation(self, rotation: PasswordRotation) -> None:
        self._meta = rotation.meta
        self._kek = rotation.kek
        self._dek = rotation.dek
        self._password = None

    def mark_persisted(self) -> None:
        self._meta.metadata_present = True

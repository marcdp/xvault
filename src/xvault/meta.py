import base64
import binascii
from typing import Optional


DEFAULT_VERSION = "1"
DEFAULT_CRYPTO_VERSION = 2
META_VARIABLE = "_xvault"
META_VARIABLE_PREFIX = "xvault:"
META_VARIABLE_COMMENTS = "xvault metadata. To view/edit secrets in this file use: pip install -e xvault; xvault edit <file>;"
META_CHECK_VALUE = "xvault"
ENC_PREFIX = "enc:"


class XVaultMeta:
    """Version-aware representation of the on-disk xvault metadata."""

    def __init__(
        self,
        schema_version: int,
        crypto_version: int,
        salt: Optional[str],
        check: Optional[str] = None,
        encrypted_key: Optional[str] = None,
        metadata_present: bool = True,
    ):
        self.schema_version = schema_version
        self.crypto_version = crypto_version
        self.salt = salt
        self.check = check
        self.encrypted_key = encrypted_key
        self.metadata_present = metadata_present

    @classmethod
    def new(cls, schema_version: int = 1) -> "XVaultMeta":
        return cls(schema_version, DEFAULT_CRYPTO_VERSION, None, metadata_present=False)

    def to_dict(self) -> dict:
        if self.crypto_version == 1:
            return {"crypto_version": 1, "salt": self.salt, "check": self.check}
        if self.crypto_version == 2:
            return {
                "crypto_version": 2,
                "salt": self.salt,
                "encrypted_key": self.encrypted_key,
            }
        raise ValueError(f"Unsupported crypto version: {self.crypto_version}")

    @staticmethod
    def from_dict(schema_version: int, data: dict) -> "XVaultMeta":
        if not isinstance(data, dict):
            raise ValueError("Unable to load vault meta: expected an object")
        crypto_version = data.get("crypto_version", 1)
        if type(crypto_version) is not int:
            raise ValueError("Unable to load vault meta: crypto_version must be an integer")
        if crypto_version == 1:
            return XVaultMeta(schema_version, 1, data.get("salt"), check=data.get("check"))
        if crypto_version == 2:
            salt = data.get("salt")
            encrypted_key = data.get("encrypted_key")
            if not isinstance(salt, str) or not salt:
                raise ValueError("Unable to load vault meta: v2 salt is missing")
            try:
                salt_raw = bytes.fromhex(salt)
            except ValueError as error:
                raise ValueError("Unable to load vault meta: v2 salt is not hexadecimal") from error
            if len(salt_raw) != 16:
                raise ValueError("Unable to load vault meta: v2 salt must be 16 bytes")
            if not isinstance(encrypted_key, str) or not encrypted_key:
                raise ValueError("Unable to load vault meta: v2 encrypted_key is missing")
            try:
                wrapped = base64.b64decode(
                    encrypted_key.encode("ascii"), altchars=b"-_", validate=True
                )
            except (ValueError, UnicodeEncodeError, binascii.Error) as error:
                raise ValueError("Unable to load vault meta: v2 encrypted_key is invalid") from error
            if len(wrapped) != 60:
                raise ValueError("Unable to load vault meta: v2 encrypted_key must be 60 bytes")
            return XVaultMeta(schema_version, 2, salt, encrypted_key=encrypted_key)
        raise ValueError(f"Unsupported crypto version: {crypto_version}")

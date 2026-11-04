from abc import ABC, abstractmethod


class CryptoBase(ABC):
    """Value-level cryptographic operations used by :class:`xvault.XVault`."""

    @abstractmethod
    def get_key(self) -> bytes:
        """Return the active encryption key, deriving it when necessary."""

    @abstractmethod
    def validate_password(self) -> None:
        """Validate the active password or cached key against vault metadata."""

    @abstractmethod
    def encrypt(self, value: str) -> str:
        """Encrypt one plaintext value."""

    @abstractmethod
    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt one ciphertext value."""

    @abstractmethod
    def replace_password(self, password: str) -> None:
        """Discard the active key and prepare to derive a replacement key."""

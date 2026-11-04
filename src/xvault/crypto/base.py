from abc import ABC, abstractmethod


class CryptoBase(ABC):
    """Small common interface for value-level vault cryptography."""

    @abstractmethod
    def get_cacheable_key(self) -> bytes:
        """Return the authenticated credential suitable for keyring caching."""

    def get_key(self) -> bytes:
        """Compatibility alias for callers of the original v1 interface."""
        return self.get_cacheable_key()

    @abstractmethod
    def validate_password(self) -> None:
        """Validate the active password or cached key against vault metadata."""

    @abstractmethod
    def encrypt(self, value: str) -> str:
        """Encrypt one plaintext value."""

    @abstractmethod
    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt one ciphertext value."""

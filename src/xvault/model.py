from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
import json

# consts
DEFAULT_SCHEMA_VERSION = 1
DEFAULT_CRYPTO_VERSION = 1

# SecretEntry
@dataclass
class SecretEntry:
    key: str
    type: str
    services: List[str]
    value: object
    description: Optional[str] = None
    meta: Optional[Dict[str, Any]] = None

    # Validation
    def validate(self) -> None:
        if not self.type:
            raise ValueError(f"Secret '{self.key}' missing type")

        if not self.services:
            raise ValueError(f"Secret '{self.key}' must define services")

        if self.value == None:
            raise ValueError(f"Secret '{self.key}' value must be something")

    # Serialization
    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "description": self.description,
            "meta": self.meta,
            "services": self.services,
            "value": self.value,
        }

    @staticmethod
    def from_dict(key: str, data: Dict[str, Any]) -> "SecretEntry":
        return SecretEntry(
            key=key,
            type=data["type"],
            services=data["services"],
            description=data.get("description"),
            meta=data.get("meta"),
            value=data["value"]
        )


# SecretsMeta
@dataclass
class SecretsMeta:
    # fields
    schema_version: int = DEFAULT_SCHEMA_VERSION
    crypto_version: int = DEFAULT_CRYPTO_VERSION
    salt: str           = None
    check: str          = None
    # methods
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "schema_version": self.schema_version,
            "crypto_version": self.crypto_version,
            "salt": self.salt,
            "check": self.check,
        }
        return data

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "SecretsMeta":
        return SecretsMeta(
            schema_version=data.get("schema_version", DEFAULT_SCHEMA_VERSION),
            crypto_version=data.get("crypto_version", DEFAULT_CRYPTO_VERSION),
            salt=data.get("salt"),
            check=data.get("check"),
        )


# SecretsStore
@dataclass
class SecretsStore:
    name: str
    meta: SecretsMeta
    secrets: Dict[str, SecretEntry] = field(default_factory=dict)

    # Core Operations
    def add(self, entry: SecretEntry) -> None:
        if entry.key in self.secrets:
            raise ValueError(f"Secret '{entry.key}' already exists")
        self.secrets[entry.key] = entry

    def set(self, entry: SecretEntry) -> None:
        self.secrets[entry.key] = entry

    def remove(self, key: str) -> None:
        if key not in self.secrets:
            raise KeyError(f"Secret '{key}' not found")
        del self.secrets[key]

    def get(self, key: str) -> SecretEntry:
        if key not in self.secrets:
            raise KeyError(f"Secret '{key}' not found")
        return self.secrets[key]
    
    def exists(self, key: str) -> bool:
        return key in self.secrets

    def list_keys(self) -> List[str]:
        return sorted(self.secrets.keys())

    # Validation
    def validate(self) -> None:
        for entry in self.secrets.values():
            entry.validate()

    # Serialization
    def to_dict(self) -> Dict[str, Any]:
        return {
            "meta": self.meta.to_dict(),
            "secrets": {
                key: entry.to_dict()
                for key, entry in sorted(self.secrets.items())
            },
        }

    def to_json(self, pretty: bool = True) -> str:
        if pretty:
            return json.dumps(self.to_dict(), indent=4)
        return json.dumps(self.to_dict(), separators=(",", ":"))

    @staticmethod
    def from_dict(name: str, data: Dict[str, Any]) -> "SecretsStore":
        meta = SecretsMeta.from_dict(data.get("meta", {}))
        secrets_data = data.get("secrets", {})
        secrets = {
            key: SecretEntry.from_dict(key, value)
            for key, value in secrets_data.items()
        }
        return SecretsStore(
            name=name,
            meta=meta,
            secrets=secrets,
        )

    @staticmethod
    def from_json(name: str, raw: str) -> "SecretsStore":
        data = json.loads(raw)
        return SecretsStore.from_dict(name, data)
import base64
import copy
from collections import defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
import os
import re
import tempfile
import warnings
from typing import Optional

from argon2.low_level import hash_secret_raw
from dprojectstools.xeditor import XEditor
import keyring
from keyring.errors import PasswordDeleteError

from .handlers import (
    HandlerBase,
    HandlerEnv,
    HandlerJson,
    HandlerJsonc,
    HandlerMd,
    HandlerOvpn,
    HandlerYaml,
)
from .meta import (
    DEFAULT_VERSION,
    ENC_PREFIX,
    META_CHECK_VALUE,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)
from .crypto import CryptoBase, CryptoV1, CryptoV2


KEYRING_APP_NAME = "xvault"  # keyring app name for storing unlocked keys

CRYPTO_VERSIONS = {1: CryptoV1, 2: CryptoV2}

HANDLERS = {
    ".json": HandlerJson,
    ".jsonc": HandlerJsonc,
    ".yaml": HandlerYaml,
    ".yml": HandlerYaml,
    ".env": HandlerEnv,
    ".md": HandlerMd,
    ".ovpn": HandlerOvpn,
}


@dataclass
class _EditToken:
    marker: str
    plaintext: str
    wrapped: bool
    ciphertext: Optional[str] = None
    context: tuple[str, int] = ("", 0)


@dataclass
class _EditDocument:
    text: str
    marked_text: str
    skeleton: str
    tokens: list[_EditToken]


class HandlerXml(HandlerBase):
    """Compatibility stub for the unsupported XML format."""

    pass


# class
class XVault():

    # ctr
    def __init__(self, path : str, password : Optional[str] = None, no_cache_key: bool = False):
        # get path
        self._path = Path(path)
        # validate
        if not self._path.exists():
            raise ValueError(f"Unable to open: path not found: {path}")
        # no cache key
        self._no_cache_key = no_cache_key
        if self._no_cache_key and password is None:
            raise ValueError("Unable to open: no_cache_key option requires password to be provided")
        # load
        self._text = None
        self._meta = None
        self._crypto: Optional[CryptoBase] = None
        handler_class = HANDLERS.get(self._path.suffix)
        if handler_class is None:
            raise ValueError(f"Unable to open: unsupported file format: only .json, .jsonc, .env, .yml, .yaml, .md, .ovpn are supported: {path}")
        self._handler = handler_class()
        self._load()
        if self._meta is not None:
            self._crypto = self._create_crypto(password)
        # auto unlock
        if not self._no_cache_key and password and self._meta.metadata_present:
            self.unlock()

    # property
    @property
    def path(self):
        return self._path.resolve()

    # methods
    def edit(self):
        # Decrypt and capture ciphertext per occurrence. Preservation remains
        # local to this edit and never becomes cryptographic object state.
        original = self._prepare_edit_document()
        format = self._path.suffix.lstrip(".")
        crypto_version = self._meta.crypto_version
        # edit
        xeditor = XEditor()
        result = xeditor.editText(original.text, format = format, title = f"Editing secrets in {self._path.resolve()} (v{crypto_version})")
        # apply changes
        if result is not None:
            # Prepare the complete candidate on isolated state. This matters for
            # first-time v2 initialization, where encryption creates metadata and
            # a DEK before any bytes are written.
            candidate_meta, candidate_crypto = copy.deepcopy((self._meta, self._crypto))
            candidate_text = self._encrypt_edit_result(
                result, original, candidate_crypto
            )
            self._save_candidate(candidate_meta, candidate_text, candidate_crypto)

    def edit_secret(self, name: str):
        """Edit one addressable secret without rewriting unrelated ciphertext."""
        if isinstance(self._handler, (HandlerJsonc, HandlerMd)) or not isinstance(
            self._handler, (HandlerEnv, HandlerJson, HandlerOvpn, HandlerYaml)
        ):
            raise NotImplementedError(
                f"Single-secret editing is not supported for {self._path.suffix} files"
            )
        value = self.get(name)
        if value is None:
            raise ValueError(f"Unable to edit secret: key '{name}' not found")
        result = XEditor().editText(
            str(value),
            format="text",
            title=f"Editing secret '{name}' in {self._path.resolve()}",
        )
        if result is not None and result != value:
            self.set(name, result)

    def get(self, name: str, resolve: bool = False):
        # get value
        text = self._decrypt(self._text, return_unprefixed_values = True )
        # resolve
        if resolve:
            text = self._resolve(text)
        # get value
        return self._handler.getValue(text, name)

    def set(self, name: str, value: str, encrypt:bool = True):
        candidate_meta, candidate_crypto = copy.deepcopy((self._meta, self._crypto))
        initializing = self.is_unitialized() and encrypt
        if initializing:
            # Add the incoming plaintext marker first, then initialize every
            # marker exactly once with the same newly generated v2 DEK.
            text = self._handler.setValue(self._text, name, value, True)
            text = self._encrypt_with_crypto(text, candidate_crypto)
        else:
            # Initialized vaults must encrypt only the incoming value so existing
            # ciphertext remains byte-for-byte unchanged.
            if encrypt:
                if isinstance(self._handler, HandlerOvpn):
                    value = "\n".join(
                        candidate_crypto.encrypt(line) for line in value.splitlines()
                    )
                else:
                    value = candidate_crypto.encrypt(value)
            text = self._handler.setValue(self._text, name, value, encrypt)
        self._save_candidate(candidate_meta, text, candidate_crypto)

    def export(self, resolve: bool = False) -> str:
        # decrypt
        text = self._decrypt(self._text, return_unprefixed_values = True )
        # resolve
        if resolve:
            text = self._resolve(text)
        # return
        return text
    
    def info(self):
        # info
        info = {
            "File": self._path,
            "Format": self._path.suffix.lstrip("."),
            "Status": f"uninitialized" if self.is_unitialized() else f"locked" if self.is_locked() else "unlocked",
            "Schema version": self._meta.schema_version,
            "Crypto version": self._meta.crypto_version,
            "Encrypted": self._text.count("enc:") 
        }
        return info


    # lock/unlock methods
    def unlock(self):
        # unlocking
        if self.is_unitialized():
            raise ValueError("Unable to unlock: vault is not initialized")
        self._validate_password()
        key = self._get_crypto().get_cacheable_key()
        self._store_cache_key(key)

    def is_unlocked(self):
        # check if unlocked
        try:
            self._validate_password()
        except Exception:
            return False
        return True
    
    def is_locked(self):
        # check if locked
        if self.is_unitialized():
            return False
        if self._no_cache_key:
            return False
        encoded_key = keyring.get_password(self._get_keyring_store_name(), self._get_keyring_store_id())
        return encoded_key is None
    
    def is_unitialized(self):
        # check if uninitialized
        return not self._meta.metadata_present

    def is_uninitialized(self):
        """Correctly-spelled alias retained alongside the historical API."""
        return self.is_unitialized()
    
    def lock(self):
        # lock
        if self._no_cache_key:
            return
        self._delete_cached_credential(
            self._get_keyring_store_name(), self._get_keyring_store_id()
        )
    
    def rekey(self, new_password: str):
        # rekey
        # validate new password
        if not new_password:
            raise ValueError("Unable to rekey: new password cannot be empty")
        if self.is_unitialized():
            raise ValueError("Unable to rekey: vault is not initialized")
        if self._meta.crypto_version == 2:
            crypto = self._get_crypto()
            if not isinstance(crypto, CryptoV2):
                raise ValueError("Unable to rekey: invalid crypto implementation")
            rotation = crypto.prepare_password_rotation(new_password)
            cache_key = rotation.kek if not self._no_cache_key else None
            self._write_vault(rotation.meta, self._text)
            self._meta = rotation.meta
            crypto.activate_password_rotation(rotation)
            if cache_key is not None:
                self._cache_key_after_commit(
                    cache_key, "Vault password was changed"
                )
            return
        # v1: prepare a complete replacement without changing active state.
        active_crypto = self._get_crypto()
        if not isinstance(active_crypto, CryptoV1):
            raise ValueError("Unable to rekey: invalid crypto implementation")
        self._validate_password()
        decrypted_text = self._decrypt_with_crypto(self._text, active_crypto)
        candidate_meta = XVaultMeta(
            self._meta.schema_version,
            1,
            self._meta.salt,
            metadata_present=True,
        )
        candidate_crypto = CryptoV1(
            candidate_meta,
            password=new_password,
            key_deriver=hash_secret_raw,
        )
        encrypted_text = self._encrypt_with_crypto(decrypted_text, candidate_crypto)
        candidate_meta.check = candidate_crypto.encrypt(META_CHECK_VALUE)
        cache_key = (
            candidate_crypto.get_cacheable_key() if not self._no_cache_key else None
        )
        self._write_vault(candidate_meta, encrypted_text)
        self._meta = candidate_meta
        self._text = encrypted_text
        self._crypto = candidate_crypto
        if cache_key is not None:
            self._cache_key_after_commit(cache_key, "Vault was saved")

    def upgrade(self, password: str):
        """Atomically migrate an initialized v1 vault to crypto version 2."""
        if self.is_unitialized():
            raise ValueError("Unable to upgrade: vault is not initialized")
        if self._meta.crypto_version != 1:
            raise ValueError("Unable to upgrade: vault already uses crypto version 2")
        if not password:
            raise ValueError("Unable to upgrade: password is required")
        self._validate_password()
        plaintext_text = self._decrypt(self._text)
        candidate_meta = XVaultMeta.new(schema_version=self._meta.schema_version)
        candidate_crypto = CryptoV2(candidate_meta, password=password, key_deriver=hash_secret_raw)
        encrypted_text = self._encrypt_with_crypto(plaintext_text, candidate_crypto)
        # Verify the complete candidate before replacing the original file.
        if self._decrypt_with_crypto(encrypted_text, candidate_crypto) != plaintext_text:
            raise ValueError("Unable to upgrade: candidate verification failed")
        candidate_meta.metadata_present = True
        cache_key = (
            candidate_crypto.get_cacheable_key() if not self._no_cache_key else None
        )
        self._write_vault(candidate_meta, encrypted_text)
        old_store_name = self._get_keyring_store_name(version=1)
        self._meta = candidate_meta
        self._text = encrypted_text
        self._crypto = candidate_crypto
        candidate_crypto.mark_persisted()
        if cache_key is not None:
            try:
                self._delete_cached_credential(
                    old_store_name, self._get_keyring_store_id()
                )
            except Exception:
                warnings.warn(
                    "Vault upgrade was saved, but the old cached credential "
                    "could not be verified as removed.",
                    RuntimeWarning,
                    stacklevel=2,
                )
            self._cache_key_after_commit(
                cache_key, "Vault upgrade was saved"
            )

    def validate(self, strict: bool = False, verbose: bool = False):
        checks = [{"name": "parse", "severity": "info", "message": f"ok ({self._path.suffix})"}]
        if self.is_unitialized():
            checks.append({"name": "status", "severity": "warning", "message": "uninitialized"})
            checks.append({"name": "password-validation", "severity": "info", "message": "unavailable"})
            checks.append({"name": "decryp", "severity": "info", "message": "unavailable"})
            checks.append({"name": "decryp count", "severity": "info", "message": f"ok ({self._text.count('enc:')})"})
            return self._finalize_validation(checks, strict, verbose)

        if not self._meta.salt:
            checks.append({"name": "salt", "severity": "error", "message": "missing"})
        else:
            try:
                salt_raw = bytes.fromhex(self._meta.salt)
                checks.append({"name": "salt", "severity": "info", "message": "ok"})
                if len(salt_raw) == 16:
                    checks.append({"name": "salt-length", "severity": "info", "message": "ok (16 bytes)"})
                else:
                    checks.append({"name": "salt-length", "severity": "error", "message": f"invalid length ({len(salt_raw)} bytes), expected 16 bytes"})
            except (TypeError, ValueError):
                checks.append({"name": "salt", "severity": "error", "message": "invalid hexadecimal value"})

        if self._meta.crypto_version == 1:
            severity = "info" if self._meta.check else "error"
            checks.append({"name": "check", "severity": severity, "message": "ok" if self._meta.check else "missing"})
        else:
            try:
                wrapped = base64.b64decode(
                    self._meta.encrypted_key.encode("ascii"), altchars=b"-_", validate=True
                )
                if len(wrapped) != 60:
                    raise ValueError(f"invalid length ({len(wrapped)} bytes), expected 60 bytes")
                checks.append({"name": "encrypted-key", "severity": "info", "message": "ok"})
            except Exception as error:
                checks.append({"name": "encrypted-key", "severity": "error", "message": str(error)})

        if self.is_locked():
            checks.append({"name": "status", "severity": "warning", "message": "locked"})
            checks.append({"name": "password-validation", "severity": "info", "message": "unavailable"})
            checks.append({"name": "decryp", "severity": "info", "message": "unavailable"})
        else:
            checks.append({"name": "status", "severity": "info", "message": "ok (unlocked)"})
            try:
                self._validate_password()
            except Exception:
                checks.append({"name": "password-validation", "severity": "error", "message": "invalid password or metadata"})
                checks.append({"name": "decryp", "severity": "info", "message": "unavailable"})
            else:
                checks.append({"name": "password-validation", "severity": "info", "message": "ok"})
                try:
                    self._decrypt(self._text)
                except Exception as error:
                    checks.append({"name": "decryp", "severity": "error", "message": f"error: {error}"})
                else:
                    checks.append({"name": "decryp", "severity": "info", "message": "ok"})
        checks.append({"name": "decryp count", "severity": "info", "message": f"ok ({self._text.count('enc:')})"})
        return self._finalize_validation(checks, strict, verbose)

    def _finalize_validation(self, checks, strict: bool, verbose: bool):
        if strict:
            authenticated = any(
                check["name"] == "password-validation"
                and check["severity"] == "info"
                and check["message"] == "ok"
                for check in checks
            )
            decrypted = any(
                check["name"] == "decryp"
                and check["severity"] == "info"
                and check["message"] == "ok"
                for check in checks
            )
            checks.append(
                {
                    "name": "strict",
                    "severity": "info" if authenticated and decrypted else "error",
                    "message": (
                        "authenticated verification complete"
                        if authenticated and decrypted
                        else "authenticated verification incomplete"
                    ),
                }
            )
        if verbose:
            credential = next(
                (c["message"] for c in checks if c["name"] == "password-validation"),
                "unavailable",
            )
            secret_check = next(
                (c["message"] for c in checks if c["name"] == "decryp"),
                "unavailable",
            )
            metadata_errors = any(
                c["severity"] == "error"
                and c["name"] in {"salt", "salt-length", "check", "encrypted-key"}
                for c in checks
            )
            metadata_message = (
                "absent"
                if self.is_unitialized()
                else "invalid" if metadata_errors else "valid"
            )
            checks.extend(
                [
                    {
                        "name": "crypto-version",
                        "severity": "info",
                        "message": str(self._meta.crypto_version),
                    },
                    {
                        "name": "metadata",
                        "severity": "info" if not metadata_errors else "error",
                        "message": metadata_message,
                    },
                    {"name": "credentials", "severity": "info", "message": credential},
                    {"name": "secrets", "severity": "info", "message": secret_check},
                    {
                        "name": "marked-secrets",
                        "severity": "info",
                        "message": str(self._text.count("enc:")),
                    },
                ]
            )
        severities = {check["severity"] for check in checks}
        status = "error" if "error" in severities else "warning" if "warning" in severities else "ok"
        return {"status": status, "checks": checks}


    # static lock/unlock methods
    @staticmethod
    def is_locked_file(path: str) -> bool:
        xvault = XVault(path)
        return xvault.is_locked()
    @staticmethod
    def is_uninitialized_file(path: str) -> bool:
        xvault = XVault(path)
        return xvault.is_unitialized()
    

    # read/write utils
    def _get_keyring_store_name(self, version: Optional[int] = None):
        version = self._meta.crypto_version if version is None else version
        prefix = KEYRING_APP_NAME if version == 1 else f"{KEYRING_APP_NAME}:v{version}"
        return prefix + ":" + str(self._path.resolve().as_uri())
    def _get_keyring_store_id(self):
        return "username"

    def _delete_cached_credential(self, store_name: str, store_id: str):
        try:
            keyring.delete_password(store_name, store_id)
        except PasswordDeleteError as error:
            if keyring.get_password(store_name, store_id) is not None:
                raise PasswordDeleteError(
                    "Cached credential is still present after deletion failed"
                ) from error

    def _store_cache_key(self, key: bytes):
        encoded_key = base64.b64encode(key).decode()
        store_name = self._get_keyring_store_name()
        store_id = self._get_keyring_store_id()
        try:
            keyring.set_password(store_name, store_id, encoded_key)
        except Exception as store_error:
            # A failed refresh must not leave a now-incompatible old credential.
            try:
                self._delete_cached_credential(store_name, store_id)
            except Exception as delete_error:
                warnings.warn(
                    "Key caching failed, and a stale cached credential could "
                    "not be removed or verified absent; automatic unlocking may "
                    "not work.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                store_error.add_note(
                    "A stale cached credential could not be removed or verified "
                    "absent after the keyring update failed."
                )
                raise store_error from delete_error
            raise

    def _cache_key_after_commit(self, key: bytes, operation: str):
        try:
            self._store_cache_key(key)
        except Exception:
            warnings.warn(
                f"{operation}, but key caching failed; automatic unlocking "
                "may not work.",
                RuntimeWarning,
                stacklevel=2,
            )

    def _create_crypto(self, password: Optional[str]) -> Optional[CryptoBase]:
        loader = None
        if not self._no_cache_key:
            loader = lambda: keyring.get_password(
                self._get_keyring_store_name(), self._get_keyring_store_id()
            )
        if self._meta.crypto_version == 1:
            # Passing the module binding preserves compatibility with callers that
            # monkeypatch xvault.xvault.hash_secret_raw.
            return CryptoV1(
                self._meta,
                password=password,
                cached_key_loader=loader,
                key_deriver=hash_secret_raw,
            )
        if self._meta.crypto_version == 2:
            return CryptoV2(
                self._meta,
                password=password,
                cached_key_loader=loader,
                key_deriver=hash_secret_raw,
            )
        raise ValueError(
            f"Unable to get key: unsupported crypto version in meta: "
            f"{self._meta.crypto_version}"
        )

    def _get_crypto(self) -> CryptoBase:
        if self._crypto is None:
            raise ValueError(
                f"Unable to get key: unsupported crypto version in meta: "
                f"{self._meta.crypto_version}"
            )
        return self._crypto
    
    def _load(self):        
        # text
        with open(self._path, "r", encoding="utf-8-sig", newline="") as file:
            text = file.read()
         # parse 
        (self._meta, self._text) = self._handler.parse(text)
        # Merely loading an uninitialized file must not touch keyring state.

    def _save(self):
        if self._meta.crypto_version == 1 and self._meta.check is None:
            self._meta.check = self._encrypt_value(META_CHECK_VALUE)
        if self.is_unitialized() and not self._meta.encrypted_key:
            self._write_result(self._text)
            return
        cache_key = (
            self._get_crypto().get_cacheable_key() if not self._no_cache_key else None
        )
        self._write_vault(self._meta, self._text)
        self._meta.metadata_present = True
        if isinstance(self._crypto, CryptoV2):
            self._crypto.mark_persisted()
        if cache_key is not None:
            self._cache_key_after_commit(cache_key, "Vault was saved")

    def _save_candidate(self, meta: XVaultMeta, text: str, crypto: CryptoBase):
        """Persist candidate edit state, then make it active."""
        if meta.crypto_version == 1 and meta.check is None:
            meta.check = crypto.encrypt(META_CHECK_VALUE)
        if not meta.metadata_present and not meta.encrypted_key:
            self._write_result(text)
            self._meta = meta
            self._text = text
            self._crypto = crypto
            return
        cache_key = crypto.get_cacheable_key() if not self._no_cache_key else None
        self._write_vault(meta, text)
        meta.metadata_present = True
        if isinstance(crypto, CryptoV2):
            crypto.mark_persisted()
        self._meta = meta
        self._text = text
        self._crypto = crypto
        if cache_key is not None:
            self._cache_key_after_commit(cache_key, "Vault was saved")

    def _write_vault(self, meta: XVaultMeta, text: str):
        self._write_result(self._handler.stringify(meta, text))

    def _write_result(self, result: str):
        if not result.endswith("\n"):
            result += "\n"
        # write atomically so an interrupted save cannot truncate the vault
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                newline="",
                dir=self._path.parent,
                prefix=f".{self._path.name}.",
                suffix=".tmp",
                delete=False,
            ) as file:
                temp_path = Path(file.name)
                file.write(result)
            os.chmod(temp_path, self._path.stat().st_mode)
            os.replace(temp_path, self._path)
        except Exception:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
            raise

    # resolve
    def _resolve(self, text: str) -> str:
        # resolve all values in text
        pattern = re.compile(r"\$\{var:([A-Za-z_][A-Za-z0-9_]*)\}")
        def replacer(match):
            name = match.group(1)
            value = self._handler.getValue(text, name)
            if value is None:
                raise ValueError(f"Unable to resolve: variable '{name}' not found")
            return str(value)
        text = re.sub(pattern, replacer, text)
        return text

    # decrypt
    def _validate_password(self):
        if self.is_unitialized():
            return
        self._get_crypto().validate_password()
   
    def _get_key(self):
        return self._get_crypto().get_key()
    
    def _decrypt(self, text: str, return_unprefixed_values: bool = False) -> str:
        if self.is_unitialized() and not self._meta.encrypted_key:
            def reveal_uninitialized(value):
                if not return_unprefixed_values:
                    return value
                is_wrapped = value.startswith("${") and value.endswith("}")
                token = value[2:-1] if is_wrapped else value
                return token[len(ENC_PREFIX):]
            return self._handler.replace_enc_tokens(text, reveal_uninitialized)
        return self._decrypt_with_crypto(text, self._get_crypto(), return_unprefixed_values)

    def _decrypt_with_crypto(
        self, text: str, crypto: CryptoBase, return_unprefixed_values: bool = False
    ) -> str:
        # decrypt all values in text
        def decrypt_value(value):
            is_wrapped = value.startswith("${") and value.endswith("}")
            token = value[2:-1] if is_wrapped else value
            token = token[len(ENC_PREFIX):]
            decrypted = crypto.decrypt(token)
            if return_unprefixed_values:
                return decrypted
            result = ENC_PREFIX + decrypted
            return "${" + result + "}" if is_wrapped else result
        return self._handler.replace_enc_tokens(text, decrypt_value)
    
    def _encrypt(self, text: str) -> str:
        return self._encrypt_with_crypto(text, self._get_crypto())

    def _encrypt_with_crypto(self, text: str, crypto: CryptoBase) -> str:
        # encrypt all values in text
        def encrypt_value(value):
            is_wrapped = value.startswith("${") and value.endswith("}")
            token = value[2:-1] if is_wrapped else value
            token = token[len(ENC_PREFIX):]
            encrypted = crypto.encrypt(token)
            result = ENC_PREFIX + encrypted
            return "${" + result + "}" if is_wrapped else result
        return self._handler.replace_enc_tokens(text, encrypt_value)

    def _prepare_edit_document(self) -> _EditDocument:
        if self.is_unitialized() and not self._meta.encrypted_key:
            return self._mark_edit_tokens(self._text, lambda value: (value, None))
        crypto = self._get_crypto()
        return self._mark_edit_tokens(
            self._text, lambda value: (crypto.decrypt(value), value)
        )

    def _mark_edit_tokens(self, text: str, loader) -> _EditDocument:
        """Replace token occurrences with private markers and describe context.

        Handler callbacks are not assumed to run in source order. The returned
        records are sorted by marker position after replacement instead.
        """
        marker_prefix = "\x00xvault-edit-token-"
        while marker_prefix in text:
            marker_prefix += "x"
        tokens = []

        def mark(value):
            wrapped = value.startswith("${") and value.endswith("}")
            token = value[2:-1] if wrapped else value
            plaintext, ciphertext = loader(token[len(ENC_PREFIX):])
            marker = f"{marker_prefix}{len(tokens)}\x00"
            tokens.append(_EditToken(marker, plaintext, wrapped, ciphertext))
            return marker

        marked_text = self._handler.replace_enc_tokens(text, mark)
        tokens.sort(key=lambda token: marked_text.index(token.marker))

        skeleton = marked_text
        rendered = marked_text
        for token in tokens:
            skeleton = skeleton.replace(token.marker, "<xvault-token>")
            value = ENC_PREFIX + token.plaintext
            if token.wrapped:
                value = "${" + value + "}"
            rendered = rendered.replace(token.marker, value)

        lines = marked_text.splitlines(keepends=True)
        for line in lines:
            line_tokens = [token for token in tokens if token.marker in line]
            if not line_tokens:
                continue
            normalized = line
            for token in line_tokens:
                normalized = normalized.replace(token.marker, "<xvault-token>")
            normalized = normalized.rstrip("\r\n")
            for ordinal, token in enumerate(
                sorted(line_tokens, key=lambda item: line.index(item.marker))
            ):
                token.context = (normalized, ordinal)

        return _EditDocument(rendered, marked_text, skeleton, tokens)

    def _encrypt_edit_result(
        self, result: str, original: _EditDocument, crypto: CryptoBase
    ) -> str:
        edited = self._mark_edit_tokens(result, lambda value: (value, None))
        preserved: dict[str, str] = {}

        # With an unchanged token skeleton, textual occurrence is a safe logical
        # identity. This covers no-op edits and value-only changes in every format.
        if (
            original.skeleton == edited.skeleton
            and len(original.tokens) == len(edited.tokens)
        ):
            pairs = zip(original.tokens, edited.tokens)
        else:
            # Structural edits are matched only through contexts unique on both
            # sides. Ambiguous occurrences deliberately receive fresh ciphertext.
            original_by_context = defaultdict(list)
            edited_by_context = defaultdict(list)
            for token in original.tokens:
                original_by_context[token.context].append(token)
            for token in edited.tokens:
                edited_by_context[token.context].append(token)
            pairs = (
                (original_by_context[context][0], edited_by_context[context][0])
                for context in original_by_context.keys() & edited_by_context.keys()
                if len(original_by_context[context]) == 1
                and len(edited_by_context[context]) == 1
            )

        for old, new in pairs:
            if old.ciphertext is not None and old.plaintext == new.plaintext:
                preserved[new.marker] = old.ciphertext

        encrypted_text = edited.marked_text
        for token in edited.tokens:
            ciphertext = preserved.get(token.marker)
            if ciphertext is None:
                ciphertext = crypto.encrypt(token.plaintext)
            value = ENC_PREFIX + ciphertext
            if token.wrapped:
                value = "${" + value + "}"
            encrypted_text = encrypted_text.replace(token.marker, value)
        return encrypted_text

    def _decrypt_value(self, encrypted_value: str) -> str:
        return self._get_crypto().decrypt(encrypted_value)
    
    def _encrypt_value(self, value: str) -> str:
        return self._get_crypto().encrypt(value)


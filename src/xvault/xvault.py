import base64
from hashlib import sha256
from pathlib import Path
import os
import re
import tempfile
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
from .crypto import CryptoBase, CryptoV1


KEYRING_APP_NAME = "xvault"  # keyring app name for storing unlocked keys

HANDLERS = {
    ".json": HandlerJson,
    ".jsonc": HandlerJsonc,
    ".yaml": HandlerYaml,
    ".yml": HandlerYaml,
    ".env": HandlerEnv,
    ".md": HandlerMd,
    ".ovpn": HandlerOvpn,
}


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
        if not self._no_cache_key and self._password:
            self.unlock()

    @property
    def _key(self):
        return self._crypto._key if self._crypto is not None else None

    @_key.setter
    def _key(self, value):
        self._get_crypto()._key = value

    @property
    def _password(self):
        return self._crypto._password if self._crypto is not None else None

    @_password.setter
    def _password(self, value):
        self._get_crypto()._password = value

    @property
    def _cache(self):
        return self._crypto._cache if self._crypto is not None else {}

    @_cache.setter
    def _cache(self, value):
        self._get_crypto()._cache = value

    # property
    @property
    def path(self):
        return self._path.resolve()

    # methods
    def edit(self):
        # decrypt
        text = self._decrypt(self._text)
        format = self._path.suffix.lstrip(".")
        # edit
        xeditor = XEditor()
        result = xeditor.editText(text, format = format, title = f"Editing secrets in {self._path.resolve()}")
        # apply changes
        if result != None:
            # encrypt
            self._text = self._encrypt(result)
            # save
            self._save()

    def get(self, name: str, resolve: bool = False):
        # get value
        text = self._decrypt(self._text, return_unprefixed_values = True )
        # resolve
        if resolve:
            text = self._resolve(text)
        # get value
        return self._handler.getValue(text, name)

    def set(self, name: str, value: str, encrypt:bool = True):
        # Encrypt only the incoming value. Encrypting the complete document here
        # would encrypt ciphertext already present in other fields a second time.
        if encrypt:
            if isinstance(self._handler, HandlerOvpn):
                value = "\n".join(self._encrypt_value(line) for line in value.splitlines())
            else:
                value = self._encrypt_value(value)
        # set value
        text = self._handler.setValue(self._text, name, value, encrypt)
        # save
        self._text = text
        self._save()

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
        self._validate_password()
        key = self._get_key()
        encoded_key = base64.b64encode(key).decode()
        keyring.set_password(self._get_keyring_store_name(), self._get_keyring_store_id(), encoded_key)

    def is_unlocked(self):
        # check if unlocked
        try:
            self._validate_password()
        except Exception:
            return False
        return True
    
    def is_locked(self):
        # check if locked
        if self._meta.check is None:
            return False  # no check value in meta, consider it as unlocked (e.g. first time setup)
        encoded_key = keyring.get_password(self._get_keyring_store_name(), self._get_keyring_store_id())
        return encoded_key is None
    
    def is_unitialized(self):
        # check if uninitialized
        return self._meta.check is None
    
    def lock(self):
        # lock
        password = keyring.get_password(self._get_keyring_store_name(), self._get_keyring_store_id())
        if not password is None:
            try:
                keyring.delete_password(self._get_keyring_store_name(), self._get_keyring_store_id())
            except PasswordDeleteError:
                pass
    
    def rekey(self, new_password: str):
        # rekey
        # validate new password
        if not new_password:
            raise ValueError("Unable to rekey: new password cannot be empty")
        # decrypt with old key
        decrypted_text = self._decrypt(self._text)
        # clear old key from memory and keyring
        self._meta.check = None
        self._meta.check = None
        if not self._no_cache_key:
            self.lock()
        # set new password and derive new key
        self._get_crypto().replace_password(new_password)
        key = self._get_key()
        # encrypt with new key
        self._text = self._encrypt(decrypted_text)
        # save
        self._save()
        # unlock
        if not self._no_cache_key:
            self.unlock()

    def validate(self):
        # format
        checks = []
        # check file format
        checks.append({"name": "parse", "severity": "info","message": f"ok ({self._path.suffix})"})
        # check salt
        if not self._meta.salt:
            checks.append({"name": "salt", "severity": "error", "message": f"missing"})
        else:
            try:
                salt_raw = bytes.fromhex(self._meta.salt)
                checks.append({"name": "salt", "severity": "info", "message": f"ok"})
                if len(salt_raw) != 16:
                    checks.append({"name": "salt-length", "severity": "error", "message": f"invalid length ({len(salt_raw)} bytes), expected 16 bytes"})
                else:
                    checks.append({"name": "salt-length", "severity": "info", "message": f"ok ({len(salt_raw)} bytes)"})
            except (TypeError, ValueError):
                checks.append({"name": "salt", "severity": "error", "message": "invalid hexadecimal value"})
        # check check
        if not self._meta.check:
            checks.append({"name": "check", "severity": "error", "message": f"missing"})
        else:   
            checks.append({"name": "check", "severity": "info", "message": f"ok"})            
        # check status
        if self.is_unitialized():
            checks.append({"name": "status", "severity": "warning", "message": f"uninitialized"})
        elif self.is_locked():
            checks.append({"name": "status", "severity": "warning", "message": f"locked"})
        else:
            checks.append({"name": "status", "severity": "info", "message": f"ok (unlocked)"})
        # validate password
        if not self._no_cache_key and self.is_locked():
            checks.append({"name": "password-validation", "severity": "info", "message": f"unknown"})
        else:
            try:
                self._validate_password()
                checks.append({"name": "password-validation", "severity": "info", "message": f"ok"})
            except Exception:
                checks.append({"name": "password-validation", "severity": "error", "message": "invalid password"})
        # decrypt
        try:
            self._decrypt(self._text)
            checks.append({"name": "decryp", "severity": "info", "message": f"ok"})
        except Exception as e:
            checks.append({"name": "decryp", "severity": "error", "message": f"error: {str(e)}"})
        # decrypt values
        checks.append({"name": "decryp count", "severity": "info", "message": f"ok ({self._text.count('enc:')})"})
        severities = {check["severity"] for check in checks}
        status = "error" if "error" in severities else "warning" if "warning" in severities else "ok"
        # return
        return {
            "status": status,
            "checks": checks
        }


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
    def _get_keyring_store_name(self):
        return KEYRING_APP_NAME + ":" + str(self._path.resolve().as_uri())
    def _get_keyring_store_id(self):
        return "username"

    def _create_crypto(self, password: Optional[str]) -> Optional[CryptoBase]:
        if self._meta.crypto_version == 1:
            # Passing the module binding preserves compatibility with callers that
            # monkeypatch xvault.xvault.hash_secret_raw.
            return CryptoV1(
                self._meta,
                password=password,
                cached_key_loader=lambda: keyring.get_password(
                    self._get_keyring_store_name(), self._get_keyring_store_id()
                ),
                key_deriver=hash_secret_raw,
            )
        return None

    def _get_crypto(self) -> CryptoBase:
        if self._crypto is None:
            raise ValueError(
                f"Unable to get key: unsupported crypto version in meta: "
                f"{self._meta.crypto_version}"
            )
        return self._crypto
    
    def _load(self):        
        # text
        with open(self._path, "r", encoding="utf-8-sig") as file:
            text = file.read()
         # parse 
        (self._meta, self._text) = self._handler.parse(text)
        # ensure no cached key for this file in keyring (if new)
        if not self._no_cache_key and self._meta.check is None:            
            self.lock()

    def _save(self):
        # save
        # forces generation of check value in meta if not exists (e.g. first time setup) by encrypting known value and storing in meta.check
        if self._meta.check is None:
            self._meta.check = self._encrypt_value(META_CHECK_VALUE)
        # encode
        result = self._handler.stringify(self._meta, self._text)
        if not result.endswith("\n"):
            result += "\n"
        # write atomically so an interrupted save cannot truncate the vault
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
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
        # Preserve the uninitialized-vault shortcut before selecting crypto.
        if not self._meta.check:
            return
        self._get_crypto().validate_password()
   
    def _get_key(self):
        return self._get_crypto().get_key()
    
    def _decrypt(self, text: str, return_unprefixed_values: bool = False) -> str:
        # decrypt all values in text
        def decrypt_value(value):
            is_wrapped = value.startswith("${") and value.endswith("}")
            token = value[2:-1] if is_wrapped else value
            token = token[len(ENC_PREFIX):]
            decrypted = self._decrypt_value(token)
            if return_unprefixed_values:
                return decrypted
            result = ENC_PREFIX + decrypted
            return "${" + result + "}" if is_wrapped else result
        return self._handler.replace_enc_tokens(text, decrypt_value)
    
    def _encrypt(self, text: str) -> str:
        # encrypt all values in text
        def encrypt_value(value):
            is_wrapped = value.startswith("${") and value.endswith("}")
            token = value[2:-1] if is_wrapped else value
            token = token[len(ENC_PREFIX):]
            encrypted = self._encrypt_value(token)
            result = ENC_PREFIX + encrypted
            return "${" + result + "}" if is_wrapped else result
        return self._handler.replace_enc_tokens(text, encrypt_value)

    def _decrypt_value(self, encrypted_value: str) -> str:
        return self._get_crypto().decrypt(encrypted_value)
    
    def _encrypt_value(self, value: str) -> str:
        return self._get_crypto().encrypt(value)


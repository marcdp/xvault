from ast import pattern
import base64
import json
from io import StringIO
from pydoc import resolve
import json5
from dotenv import dotenv_values
from hashlib import sha256
from pathlib import Path
import os
from keyring.errors import PasswordDeleteError
import yaml
import re
from unittest import result
from argon2.low_level import hash_secret_raw, Type
from typing import Optional
import keyring
from dprojectstools.xeditor import XEditor
from sqlalchemy import text
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from abc import abstractmethod

# consts
META_VARIABLE = "_xvault"  # variable name in JSON/YAML/ENV for storing meta info
META_VARIABLE_PREFIX = "xvault:"  # prefix for the value of META_VARIABLE, followed by base64-encoded meta JSON, e.g. "xvault:eyJjcnlwdG9fdmVyc2lvbiI6IDEsICJzYWx0IjogIjIxYWYyY2ExZGViMmRhZDgxYTAwZGJiNGQ2MDcwMWYzIiwgImNoZWNrIjogImVuYzp2MTovRUF3R0RRWHdVcXJNRUlFN1dMdFV3dEowMnpHWlczQkpMTS9BeGJBd3YvOSt3PT0ifQ=="
META_VARIABLE_COMMENTS = "xvault meta variable (do not modify)"
META_CHECK_VALUE = "xvault"  # known value used to validate password by trying to decrypt it, stored in "_xvault.check"
KEYRING_APP_NAME = "xvault"  # keyring app name for storing unlocked keys
ENC_PREFIX = "enc:"     # prefix used to identify encrypted values in the store, followed by version info, e.g. "enc:...."


# XVault meta
class XVaultMeta():
    def __init__(self, schema_version: int, crypto_version: int, salt: str, check: Optional[str]):
        self.schema_version = schema_version
        self.crypto_version = crypto_version
        self.salt = salt
        self.check = check
    def to_dict(self):
        return {
            "crypto_version": self.crypto_version,
            "salt": self.salt,
            "check": self.check
        }
    def from_dict(schema_version:int, data: dict):
        return XVaultMeta(
            schema_version,
            crypto_version = data.get("crypto_version", 1),
            salt = data.get("salt"),
            check = data.get("check")
        )   


# handlers
class HandlerBase:
    @abstractmethod
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        pass
class HandlerJson(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        # extract meta
        _xvault_match = re.search(r'"' + META_VARIABLE + r'"\s*:\s*"([^"]+)"', text)
        _xvault_value = _xvault_match.group(1) if _xvault_match else None
        if _xvault_value is None:
            # default meta
            meta = XVaultMeta(schema_version = 1, crypto_version  = 1, salt = None, check = None)
        else:
            # constants
            indent = " " * self.detect_json_indentation(text)
            # decode meta
            if _xvault_value.startswith(META_VARIABLE_PREFIX):
                decoded = base64.urlsafe_b64decode(_xvault_value[len(META_VARIABLE_PREFIX):])
                meta_json = decoded.decode()
                meta_dict = json.loads(meta_json)
                meta = XVaultMeta.from_dict(schema_version=1, data= meta_dict)
            else:
                raise ValueError("Unable to load vault meta: invalid _xvault format")
            # remove meta variable from text
            text = re.sub(r'"' + META_VARIABLE + r'"\s*:\s*"([^"]+)"\s*,?', '', text, count=1)
            # remove meta comments if exists
            text = text.replace(f"// {META_VARIABLE_COMMENTS}\n", "")
            # remove leading empty lines if exists
            text = f"{{\n{indent}\n{indent}" + text.lstrip("{").lstrip()    
        # return
        return (meta, text)
    def replace_enc_tokens(self, text: str, replacer):
        pattern = r'' + ENC_PREFIX + '[^"\r\n]+'
        return re.sub(pattern, lambda m: replacer(m.group(0)), text)
    def detect_json_indentation(self, text: str) -> int | None:
        for line in text.splitlines():
            if not line.strip():
                continue
            spaces = len(line) - len(line.lstrip(" "))
            if spaces > 0:
                return spaces
        return 2  # default indentation
    def stringify(self, meta: XVaultMeta, text: str) -> str:
        # encode
        _xvault = base64.urlsafe_b64encode(json.dumps(meta.to_dict()).encode()).decode()
        indent = " " * self.detect_json_indentation(text)
        result = "{\n"
        result += f"{indent}\"{META_VARIABLE}\": \"{META_VARIABLE_PREFIX}{_xvault}\""
        if '"' in text:
            result += ","
        result += f"\n{indent}"
        result += f"\n{indent}"
        result += text.lstrip('{').strip()
        return result
    def getValue(self, text: str, path: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        data = json5.loads(text)
        value = data
        for key in path.split("."):
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value
class HandlerJsonc(HandlerJson):
    def stringify(self, meta: XVaultMeta, text: str) -> str:
        # encode
        _xvault = base64.urlsafe_b64encode(json.dumps(meta.to_dict()).encode()).decode()
        indent = " " * self.detect_json_indentation(text)
        result = "{\n"
        result += f"{indent}// {META_VARIABLE_COMMENTS}\n"
        result += f"{indent}\"{META_VARIABLE}\": \"{META_VARIABLE_PREFIX}{_xvault}\""
        if '"' in text:
            result += ","
        result += f"\n{indent}"
        result += f"\n{indent}"
        result += text.lstrip('{').strip()
        return result
    def getValue(self, text: str, path: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        data = json5.loads(text)
        value = data
        for key in path.split("."):
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value

class HandlerEnv(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        _xvault_match = re.search(r'^' + META_VARIABLE + r'\s*=\s*(.+)$', text, re.MULTILINE)
        _xvault_value = _xvault_match.group(1) if _xvault_match else None
        if _xvault_value is None:
            # default meta
            meta = XVaultMeta(schema_version = 1, crypto_version  = 1, salt = None, check = None)
        elif _xvault_value.startswith(META_VARIABLE_PREFIX):
            # decode meta
            decoded = base64.urlsafe_b64decode(_xvault_value[len(META_VARIABLE_PREFIX):])
            meta_json = decoded.decode()
            meta_dict = json.loads(meta_json)
            meta = XVaultMeta.from_dict(schema_version=1, data= meta_dict)
            # replace meta variable with empty line in text
            text = text.replace(f"# {META_VARIABLE_COMMENTS}\n", "")
            text = re.sub(r'^' + META_VARIABLE + r'\s*=\s*.+$', "", text, count=1, flags=re.MULTILINE)    
            text = text.lstrip("\n")  # remove leading empty lines if exists
        else:
            raise ValueError("Unable to load vault meta: invalid _xvault format")
        # return
        return (meta, text)
    def replace_enc_tokens(self, text: str, replacer):
        # pattern to match lines like: SECRET_KEY=enc:.... (value starts with enc: and continues until end of line or comment)        
        pattern = r'' + ENC_PREFIX + '[^\r\n#"\']+'
        return re.sub(pattern, lambda m: replacer(m.group(0)), text)
    def stringify(self, meta: XVaultMeta, text: str) -> str:
        # encode
        _xvault = base64.urlsafe_b64encode(json.dumps(meta.to_dict()).encode()).decode()
        result = f"# {META_VARIABLE_COMMENTS}\n"
        result += f"{META_VARIABLE}={META_VARIABLE_PREFIX}{_xvault}\n"
        result += "\n"
        result += text
        return result
    def getValue(self, text: str, name: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        data = dotenv_values(stream=StringIO(text))
        if name not in data:
            return None
        return data[name]

class HandlerYaml(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        # extract meta from YAML (_xvault: enc:....\n")
        _xvault_match = re.search(r'' + META_VARIABLE + r'\s*:\s*([^"\r\n]+)', text)
        _xvault_value = _xvault_match.group(1) if _xvault_match else None
        if _xvault_value is None:
            # default meta
            meta = XVaultMeta(schema_version = 1, crypto_version  = 1, salt = None, check = None)
        else:
            # decode meta
            if _xvault_value.startswith(META_VARIABLE_PREFIX):
                decoded = base64.urlsafe_b64decode(_xvault_value[len(META_VARIABLE_PREFIX):])
                meta_json = decoded.decode()
                meta_dict = json.loads(meta_json)
                meta = XVaultMeta.from_dict(schema_version=1, data= meta_dict)
            else:
                raise ValueError("Unable to load vault meta: invalid _xvault format")
            # remove meta variable from text
            text = re.sub(r'' + META_VARIABLE + r'\s*:\s*([^"\r\n]+)', '', text, count=1)
            # remove meta comments if exists
            text = text.replace(f"# {META_VARIABLE_COMMENTS}\n", "")
            # remove leading empty lines if exists
            text = text.lstrip()
        # return
        return (meta, text)
    def replace_enc_tokens(self, text: str, replacer):
        # pattern enc:....
        pattern = r'' + ENC_PREFIX + '[^"\r\n]+'
        return re.sub(pattern, lambda m: replacer(m.group(0)), text)
    def stringify(self, meta: XVaultMeta, text: str) -> str:
        # encode
        _xvault = base64.urlsafe_b64encode(json.dumps(meta.to_dict()).encode()).decode()
        result = f"# {META_VARIABLE_COMMENTS}\n{META_VARIABLE}: {META_VARIABLE_PREFIX}{_xvault}\n\n" + text
        return result
    def getValue(self, text: str, path: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        data = yaml.safe_load(text)
        value = data
        for key in path.split("."):
            if not isinstance(value, dict) or key not in value:
                return None
            value = value[key]
        return value
    
class HandlerMd(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        # extract meta from Markdown (---\n_xvault: enc:....\n---\n")
        front_matter_match = m = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n?', text, re.DOTALL)
        front_matter_value = front_matter_match.group(1) if m else None
        _xvault_value = None
        if front_matter_value:
            # decode xvault meta from front matter
            _xvault_match = re.search(r'' + META_VARIABLE + r'\s*:\s*([^"\r\n]+)', front_matter_value)
            _xvault_value = _xvault_match.group(1) if _xvault_match else None
            # extract meta from front matter
            text = text[front_matter_match.end():]  # remove front matter from text
            text = text.lstrip()  # remove leading empty lines if exists
        if _xvault_value is None:
            # default meta
            meta = XVaultMeta(schema_version = 1, crypto_version  = 1, salt = None, check = None)
        else:
            # decode meta
            if _xvault_value.startswith(META_VARIABLE_PREFIX):
                decoded = base64.urlsafe_b64decode(_xvault_value[len(META_VARIABLE_PREFIX):])
                meta_json = decoded.decode()
                meta_dict = json.loads(meta_json)
                meta = XVaultMeta.from_dict(schema_version=1, data= meta_dict)
            else:
                raise ValueError("Unable to load vault meta: invalid _xvault format")
            # remove leading empty lines if exists
            text = text.lstrip()
        # return
        return (meta, text)
    def replace_enc_tokens(self, text: str, replacer):
        # pattern enc:....
        pattern = r'' + ENC_PREFIX + '[^"\r\n]+'
        return re.sub(pattern, lambda m: replacer(m.group(0)), text)
    def stringify(self, meta: XVaultMeta, text: str) -> str:
        # encode
        _xvault = base64.urlsafe_b64encode(json.dumps(meta.to_dict()).encode()).decode()
        result = f"---\n"
        result += f"# {META_VARIABLE_COMMENTS}\n"
        result += f"{META_VARIABLE}: {META_VARIABLE_PREFIX}{_xvault}\n"
        result += f"---\n\n"
        result += text
        return result
    def getValue(self, text: str, path: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        raise NotImplementedError("getValue is not implemented for Markdown format")
    
class HandlerXml(HandlerBase):
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
        # password
        self._password = password
        # key
        self._key = None
        # no cache key
        self._no_cache_key = no_cache_key
        if self._no_cache_key and self._password is None:
            raise ValueError("Unable to open: no_cache_key option requires password to be provided")
        # load
        self._text = None
        self._meta = None
        self._cache = {}
        if path.endswith(".json"):
            self._handler = HandlerJson()
        elif path.endswith(".jsonc"):
            self._handler = HandlerJsonc()
        elif path.endswith(".env"):
             self._handler = HandlerEnv()
        elif path.endswith(".yml") or path.endswith(".yaml"):
             self._handler = HandlerYaml()
        elif path.endswith(".md"):
             self._handler = HandlerMd()
        elif path.endswith(".xml"):
             self._handler = HandlerXml()
        else:
            raise ValueError(f"Unable to open: unsupported file format: only .json, .jsonc, .env, .yml, .yaml, .md, .xml are supported: {path}")
        self._handler
        self._load()
        # auto unlock
        if not self._no_cache_key and self._password:
            self.unlock()

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
        canonical_path = str(self._path.resolve())
        store_id = sha256(canonical_path.encode()).hexdigest()
        keyring.set_password(KEYRING_APP_NAME, store_id, encoded_key)

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
        canonical_path = str(self._path.resolve())
        store_id = sha256(canonical_path.encode()).hexdigest()
        encoded_key = keyring.get_password(KEYRING_APP_NAME, store_id)
        return encoded_key is None
    
    def is_unitialized(self):
        # check if uninitialized
        return self._meta.check is None
    
    def lock(self):
        # lock
        canonical_path = str(self._path.resolve())
        store_id = sha256(canonical_path.encode()).hexdigest()
        password = keyring.get_password(KEYRING_APP_NAME, store_id)
        if not password is None:
            try:
                keyring.delete_password(KEYRING_APP_NAME, store_id)
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
        self._key = None
        self._meta.check = None
        self._meta.check = None
        if not self._no_cache_key:
            self.lock()
        # set new password and derive new key
        self._password = new_password
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
        status = "ok"
        # check file format
        checks.append({"name": "parse", "severity": "info","message": f"ok ({self._path.suffix})"})
        # check salt
        if not self._meta.salt:
            checks.append({"name": "salt", "severity": "error", "message": f"missing"})
        else:   
            checks.append({"name": "salt", "severity": "info", "message": f"ok"})
            salt_raw = bytes.fromhex(self._meta.salt)
            if len(salt_raw) != 16:
                checks.append({"name": "salt-length", "severity": "error", "message": f"invalid length ({len(salt_raw)} bytes), expected 16 bytes"})
            else:
                checks.append({"name": "salt-length", "severity": "info", "message": f"ok ({len(salt_raw)} bytes)"})
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
        if not self._no_cache_key:
            checks.append({"name": "password-validation", "severity": "info", "message": f"unknown"})
        elif self.is_unlocked():
            try:
                self._validate_password()
                checks.append({"name": "password-validation", "severity": "info", "message": f"ok"})
            except Exception as e:
                checks.append({"name": "password-validation", "severity": "error", "message": f"invalid password: {str(e)}"})
        # decrypt
        try:
            self._decrypt(self._text)
            checks.append({"name": "decryp", "severity": "info", "message": f"ok"})
        except Exception as e:
            checks.append({"name": "decryp", "severity": "error", "message": f"error: {str(e)}"})
        # decrypt values
        checks.append({"name": "decryp count", "severity": "info", "message": f"ok ({self._text.count("enc:")})"})
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
        # write
        with open(self._path, "w", encoding="utf-8") as file:
            file.write(result)

    # resolve
    def _resolve(self, text: str) -> str:
        # resolve all values in text
        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
        def replacer(match):
            name = match[2:-1]
            value = self._handler.getValue(text, name)
            if value is None:
                raise ValueError(f"Unable to resolve: variable '{name}' not found")
            return str(value)
        text = re.sub(pattern, lambda m: replacer(m.group(0)), text)
        return text

    # decrypt
    def _validate_password(self):
        # try to decrypt meta.check to validate password
        if not self._meta.check:
            return  # no check value, skip validation (e.g. first time setup)
        try:
            value = self._decrypt_value(self._meta.check)
        except Exception as e:
            raise ValueError("Unable to validate password: invalid password") from e
        if value != META_CHECK_VALUE:
            raise ValueError("Unable to validate password: invalid password")
   
    def _get_key(self):
        # get key, derive if not exists, or return cached
        if self._password is None and self._key is None:
            # try to get from keyring
            canonical_path = str(self._path.resolve())
            store_id = sha256(canonical_path.encode()).hexdigest()
            encoded_key = keyring.get_password(KEYRING_APP_NAME, store_id)
            if encoded_key:
                self._key = base64.b64decode(encoded_key)
        if self._meta.crypto_version not in [1]:
            raise ValueError(f"Unable to get key: unsupported crypto version in meta: {self._meta.crypto_version}")
        if self._key is not None:
            return self._key
        if not self._password:
            raise ValueError("Unable to get key: store is locked. Password required.")
        if self._key is None:
            # derive the key
            if not self._meta.salt:
                self._meta.salt = os.urandom(16).hex()        
            if self._meta.crypto_version == 1:
                # v1: argon2id + AES-256
                self._key = hash_secret_raw(
                    secret      = self._password.encode(),
                    salt        = bytes.fromhex(self._meta.salt),
                    time_cost   = 5,
                    memory_cost = 131072,  # 128Mb
                    parallelism = 4,
                    hash_len    = 32,
                    type        = Type.ID
                )
            else:
                raise ValueError(f"Unable to derive key: unsupported crypto version in meta: {self._meta.crypto_version}")            
            
        # clear password from memory
        self._password = None
        # clear cache from memory
        self._cache = {}
        # return
        return self._key
    
    def _decrypt(self, text: str, return_unprefixed_values: bool = False) -> str:
        # decrypt all values in text
        def decrypt_value(value):
            value = value[len(ENC_PREFIX):]
            return (ENC_PREFIX if not return_unprefixed_values else "") + self._decrypt_value(value)
        return self._handler.replace_enc_tokens(text, decrypt_value)
    
    def _encrypt(self, text: str) -> str:
        # encrypt all values in text
        def encrypt_value(value):
            value = value[len(ENC_PREFIX):]
            return ENC_PREFIX + self._encrypt_value(value)
        return self._handler.replace_enc_tokens(text, encrypt_value)

    def _decrypt_value(self, encrypted_value: str) -> str:
        # decrypt text value
        key = self._get_key()
        if self._meta.crypto_version == 1:
            # schema 1: AES-GCM with random nonce
            encrypted_blob = base64.urlsafe_b64decode(encrypted_value)
            nonce = encrypted_blob[:12]
            ciphertext = encrypted_blob[12:]
            aesgcm = AESGCM(key)
            plaintext_bytes = aesgcm.decrypt(
                nonce,
                ciphertext,
                None
            )
            result = plaintext_bytes.decode("utf-8")            
            self._cache[result] = encrypted_value
            return result
        # error
        raise ValueError("Unable to decrypt: invalid crypto version")
    
    def _encrypt_value(self, value: str) -> str:
        # encrypt value
        key = self._get_key()
        if value in self._cache:
            return self._cache[value]
        if self._meta.crypto_version == 1:
            # scheme 1: AES-GCM with random nonce
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)  # 96-bit nonce (recommended for GCM)
            plaintext_bytes = value.encode("utf-8")
            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext_bytes,
                None  # optional associated data
            )
            # Store nonce + ciphertext together
            encrypted_blob = nonce + ciphertext
            # Encode to base64 so it fits in JSON
            return base64.urlsafe_b64encode(encrypted_blob).decode("utf-8")
        # error
        raise ValueError("Unable to encrypt: invalid crypto version")


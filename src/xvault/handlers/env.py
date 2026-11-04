import base64
import json
import re
from io import StringIO
from typing import Optional

from dotenv import dotenv_values

from .base import HandlerBase
from ..meta import (
    ENC_PREFIX,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


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
        # first replace ${enc:...} to avoid replacing enc:... inside ${...}
        pattern = r"\$\{enc:[^}\r\n]+\}+"
        text = re.sub(pattern, lambda m: replacer(m.group(0)), text)
        # then replace enc:... that are not inside ${...}
        pattern = r"(?<!\$\{)enc:[^\r\n#\"']+"
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
    def setValue(self, text: str, path: str, value: str, encrypt: bool = True) -> str:
        # set value
        actual_value = f"{ENC_PREFIX}{value}" if encrypt else value
        pattern = r'^' + re.escape(path) + r'\s*=.*$'
        if re.search(pattern, text, re.MULTILINE):
            return re.sub(pattern, lambda _: f'{path}={actual_value}', text, count=1, flags=re.MULTILINE)
        if not text.endswith('\n'):
            text += '\n'
        return text + f'{path}={actual_value}\n'

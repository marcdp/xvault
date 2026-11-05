import base64
import json
import re
from io import StringIO
from typing import Optional

from dotenv import dotenv_values

from .base import HandlerBase, decode_meta
from ..meta import (
    ENC_PREFIX,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


class HandlerEnv(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        matches = list(re.finditer(
            r'^[ \t]*' + META_VARIABLE + r'[ \t]*=[ \t]*([^\r\n]*)\r?$',
            text,
            re.MULTILINE,
        ))
        if len(matches) > 1:
            raise ValueError("Unable to load vault meta: duplicate _xvault entries")
        if not matches:
            # default meta
            meta = XVaultMeta.new(schema_version=1)
        else:
            meta = decode_meta(matches[0].group(1).strip())
            # replace meta variable with empty line in text
            text = text[:matches[0].start()] + text[matches[0].end():]
            text = text.replace(f"# {META_VARIABLE_COMMENTS}\n", "")
            text = text.lstrip("\n")  # remove leading empty lines if exists
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

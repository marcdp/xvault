import base64
import json
import re
from typing import Optional

import yaml

from .base import HandlerBase
from ..meta import (
    ENC_PREFIX,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


class HandlerYaml(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        # extract meta from YAML (_xvault: enc:....\n")
        _xvault_match = re.search(r'' + META_VARIABLE + r'\s*:\s*([^"\r\n]+)', text)
        _xvault_value = _xvault_match.group(1) if _xvault_match else None
        if _xvault_value is None:
            # default meta
            meta = XVaultMeta.new(schema_version=1)
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
        # first replace ${enc:...} to avoid replacing enc:... inside ${...}
        pattern = r"\$\{enc:[^}\r\n]+\}+"
        text = re.sub(pattern, lambda m: replacer(m.group(0)), text)
        # then replace enc:... that are not inside ${...}
        pattern = r"(?<!\$\{)enc:[^\"\r\n]+"
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

    def setValue(self, text: str, path: str, value: str, encrypt: bool = True) -> str:
        actual_value = f"{ENC_PREFIX}{value}" if encrypt else value
        data = yaml.safe_load(text) or {}
        keys = path.split(".")
        target = data
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        target[keys[-1]] = actual_value
        return yaml.dump(data, default_flow_style=False, allow_unicode=True)

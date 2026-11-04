import base64
import json
from typing import Optional

import json5

from .json import HandlerJson
from ..meta import META_VARIABLE, META_VARIABLE_COMMENTS, META_VARIABLE_PREFIX, XVaultMeta


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
    def setValue(self, text: str, path: str, value: str, encrypt: bool = True) -> str:
        # set value
        raise NotImplementedError("setValue is not implemented for Jsonc format")

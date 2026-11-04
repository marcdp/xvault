import base64
import json
import re
from typing import Optional

from .base import HandlerBase
from ..meta import (
    ENC_PREFIX,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


class HandlerOvpn(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        _xvault_match = re.search(r'^#\s*' + META_VARIABLE + r'\s*=\s*(.+)$', text, re.MULTILINE)
        _xvault_value = _xvault_match.group(1).strip() if _xvault_match else None
        if _xvault_value is None:
            meta = XVaultMeta.new(schema_version=1)
        elif _xvault_value.startswith(META_VARIABLE_PREFIX):
            decoded = base64.urlsafe_b64decode(_xvault_value[len(META_VARIABLE_PREFIX):])
            meta_json = decoded.decode()
            meta_dict = json.loads(meta_json)
            meta = XVaultMeta.from_dict(schema_version=1, data=meta_dict)
            text = text.replace(f"# {META_VARIABLE_COMMENTS}\n", "")
            text = re.sub(r'^#\s*' + META_VARIABLE + r'\s*=\s*.+\n?', "", text, count=1, flags=re.MULTILINE)
            text = text.lstrip("\n")
        else:
            raise ValueError("Unable to load vault meta: invalid _xvault format")
        return (meta, text)

    def replace_enc_tokens(self, text: str, replacer):
        # first replace ${enc:...} to avoid replacing enc:... inside ${...}
        pattern = r"\$\{enc:[^}\r\n]+\}+"
        text = re.sub(pattern, lambda m: replacer(m.group(0)), text)
        # then replace enc:... at the start of a line
        pattern = r"(?m)^enc:[^\r\n]+"
        return re.sub(pattern, lambda m: replacer(m.group(0)), text)

    def stringify(self, meta: XVaultMeta, text: str) -> str:
        _xvault = base64.urlsafe_b64encode(json.dumps(meta.to_dict()).encode()).decode()
        result = f"# {META_VARIABLE_COMMENTS}\n"
        result += f"# {META_VARIABLE}={META_VARIABLE_PREFIX}{_xvault}\n"
        result += "\n"
        result += text
        return result

    def getValue(self, text: str, path: str) -> Optional[str]:
        # XML-like block section: <path>\ncontent\n</path>
        block_match = re.search(r'<' + re.escape(path) + r'>\r?\n(.*?)\r?\n</' + re.escape(path) + r'>', text, re.DOTALL)
        if block_match:
            return block_match.group(1).strip()
        # inline directive: path [value]
        line_match = re.search(r'^' + re.escape(path) + r'(?:[ \t]+([^\r\n#;]+))?[ \t]*$', text, re.MULTILINE)
        if line_match:
            value = line_match.group(1)
            return value.strip() if value else ""
        return None

    def setValue(self, text: str, path: str, value: str, encrypt: bool = True) -> str:
        if encrypt:
            # prefix each line with enc: to mark for encryption, preserving line breaks
            value = "\n".join(f"{ENC_PREFIX}{line}" for line in value.splitlines())
        # XML-like block section: <path>\ncontent\n</path>
        block_pattern = r'<' + re.escape(path) + r'>\r?\n.*?\r?\n</' + re.escape(path) + r'>'
        if re.search(block_pattern, text, re.DOTALL):
            replacement = f'<{path}>\n{value}\n</{path}>'
            return re.sub(block_pattern, lambda _: replacement, text, count=1, flags=re.DOTALL)
        # inline directive: path [value]
        line_pattern = r'^' + re.escape(path) + r'(?:[ \t]+[^\r\n#;]*)?[ \t]*$'
        if "\n" in value:
            replacement = f'<{path}>\n{value}\n</{path}>'
            if re.search(line_pattern, text, re.MULTILINE):
                return re.sub(line_pattern, lambda _: replacement, text, count=1, flags=re.MULTILINE)
            if not text.endswith('\n'):
                text += '\n'
            return text + replacement + '\n'
        if encrypt and value:
            value = "${" + value + "}"
        if re.search(line_pattern, text, re.MULTILINE):
            replacement = f'{path} {value}' if value else path
            return re.sub(line_pattern, lambda _: replacement, text, count=1, flags=re.MULTILINE)
        # not found: append
        if not text.endswith('\n'):
            text += '\n'
        text += (f'{path} {value}' if value else path) + '\n'
        return text

import base64
import json
import re
from typing import Optional

from .base import HandlerBase, decode_meta
from .yaml import find_top_level_meta, yaml_meta_value
from ..meta import (
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


class HandlerMd(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        # Only xvault-owned metadata is removed. The remaining front matter is
        # part of the editable document and must round-trip unchanged.
        front_matter_match = m = re.match(r'^---\r?\n(.*?)\r?\n---(?=\r?\n|$)', text, re.DOTALL)
        front_matter_value = front_matter_match.group(1) if m else None
        entries = []
        if front_matter_value is not None:
            entries = find_top_level_meta(front_matter_value)
            if len(entries) > 1:
                raise ValueError("Unable to load vault meta: duplicate _xvault entries")
        if not entries:
            # default meta
            meta = XVaultMeta.new(schema_version=1)
        else:
            key_node, value_node = entries[0]
            meta = decode_meta(yaml_meta_value(value_node))
            start = key_node.start_mark.index
            end = front_matter_value.find("\n", value_node.end_mark.index)
            end = len(front_matter_value) if end < 0 else end + 1
            cleaned = front_matter_value[:start] + front_matter_value[end:]
            comment = f"# {META_VARIABLE_COMMENTS}"
            cleaned = re.sub(
                rf"(?m)^{re.escape(comment)}\r?\n?", "", cleaned, count=1
            )
            opening_end = text.find("\n") + 1
            closing_start = front_matter_match.end() - 3
            text = text[:opening_end] + cleaned + text[closing_start:]
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
        newline = "\r\n" if text.startswith("---\r\n") else "\n"
        metadata = (
            f"# {META_VARIABLE_COMMENTS}{newline}"
            f"{META_VARIABLE}: {META_VARIABLE_PREFIX}{_xvault}{newline}"
        )
        match = re.match(r'^---\r?\n(.*?)\r?\n---(?=\r?\n|$)', text, re.DOTALL)
        if not match:
            return f"---\n{metadata}---\n\n{text}"
        entries = find_top_level_meta(match.group(1))
        if entries:
            raise ValueError("Unable to save vault meta: duplicate _xvault entry")
        closing_start = match.end() - 3
        prefix = text[:closing_start]
        if not prefix.endswith(("\n", "\r")):
            prefix += newline
        return prefix + metadata + text[closing_start:]
    def getValue(self, text: str, path: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        raise NotImplementedError("getValue is not implemented for Markdown format")

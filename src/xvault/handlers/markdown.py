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
        # extract meta from Markdown (---\n_xvault: enc:....\n---\n")
        front_matter_match = m = re.match(r'^---\r?\n(.*?)\r?\n---\r?\n?', text, re.DOTALL)
        front_matter_value = front_matter_match.group(1) if m else None
        entries = []
        if front_matter_value is not None:
            entries = find_top_level_meta(front_matter_value)
            if len(entries) > 1:
                raise ValueError("Unable to load vault meta: duplicate _xvault entries")
            # extract meta from front matter
            text = text[front_matter_match.end():]  # remove front matter from text
            text = text.lstrip()  # remove leading empty lines if exists
        if not entries:
            # default meta
            meta = XVaultMeta.new(schema_version=1)
        else:
            meta = decode_meta(yaml_meta_value(entries[0][1]))
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
        result = f"---\n"
        result += f"# {META_VARIABLE_COMMENTS}\n"
        result += f"{META_VARIABLE}: {META_VARIABLE_PREFIX}{_xvault}\n"
        result += f"---\n\n"
        result += text
        return result
    def getValue(self, text: str, path: str) -> Optional[str]:
        # pattern to match lines like: SECRET
        raise NotImplementedError("getValue is not implemented for Markdown format")

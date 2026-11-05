import base64
import json
import re
from typing import Optional

import yaml
from yaml.nodes import MappingNode, ScalarNode

from .base import HandlerBase, decode_meta
from ..meta import (
    ENC_PREFIX,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


def find_top_level_meta(text: str):
    try:
        root = yaml.compose(text)
    except yaml.YAMLError as error:
        raise ValueError("Unable to load vault meta: invalid YAML document") from error
    if not isinstance(root, MappingNode):
        return []
    return [
        (key, value)
        for key, value in root.value
        if isinstance(key, ScalarNode) and key.value == META_VARIABLE
    ]


def yaml_meta_value(node) -> str:
    if not isinstance(node, ScalarNode) or node.tag != "tag:yaml.org,2002:str":
        raise ValueError("Unable to load vault meta: _xvault must be a string")
    return node.value


class HandlerYaml(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        entries = find_top_level_meta(text)
        if len(entries) > 1:
            raise ValueError("Unable to load vault meta: duplicate _xvault entries")
        if not entries:
            # default meta
            meta = XVaultMeta.new(schema_version=1)
        else:
            key_node, value_node = entries[0]
            meta = decode_meta(yaml_meta_value(value_node))
            # remove the complete top-level metadata entry
            start = key_node.start_mark.index
            end = text.find("\n", value_node.end_mark.index)
            end = len(text) if end < 0 else end + 1
            text = text[:start] + text[end:]
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

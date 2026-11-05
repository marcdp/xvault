import base64
import json
import re
from typing import Optional

import json5

from .base import HandlerBase, decode_meta
from ..meta import (
    ENC_PREFIX,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


def _skip_json5_space(text: str, index: int) -> int:
    while index < len(text):
        if text[index].isspace():
            index += 1
        elif text.startswith("//", index):
            newline = text.find("\n", index + 2)
            index = len(text) if newline < 0 else newline + 1
        elif text.startswith("/*", index):
            end = text.find("*/", index + 2)
            index = len(text) if end < 0 else end + 2
        else:
            break
    return index


def _scan_json5_string(text: str, index: int) -> int:
    quote = text[index]
    index += 1
    while index < len(text):
        if text[index] == "\\":
            index += 2
        elif text[index] == quote:
            return index + 1
        else:
            index += 1
    return index


def _top_level_property_spans(text: str, name: str) -> list[tuple[int, int]]:
    """Locate a JSON5 top-level property without matching nested occurrences."""
    spans = []
    index = _skip_json5_space(text, 0)
    if index >= len(text) or text[index] != "{":
        return spans
    index += 1
    previous_comma = None
    while index < len(text):
        entry_start = index
        index = _skip_json5_space(text, index)
        if index >= len(text) or text[index] == "}":
            break
        if text[index] in "\"'":
            key_end = _scan_json5_string(text, index)
            try:
                key = json5.loads(text[index:key_end])
            except ValueError:
                return spans
            index = key_end
        else:
            key_match = re.match(r"[A-Za-z_$][A-Za-z0-9_$]*", text[index:])
            if not key_match:
                return spans
            key = key_match.group(0)
            index += len(key)
        index = _skip_json5_space(text, index)
        if index >= len(text) or text[index] != ":":
            return spans
        index += 1
        depth = 0
        while index < len(text):
            char = text[index]
            if char in "\"'":
                index = _scan_json5_string(text, index)
                continue
            if text.startswith("//", index) or text.startswith("/*", index):
                index = _skip_json5_space(text, index)
                continue
            if char in "[{(":
                depth += 1
            elif char in "]})":
                if depth == 0:
                    break
                depth -= 1
            elif char == "," and depth == 0:
                break
            index += 1
        has_trailing_comma = index < len(text) and text[index] == ","
        if key == name:
            start = entry_start
            end = index + 1 if has_trailing_comma else index
            if not has_trailing_comma and previous_comma is not None:
                start = previous_comma
            spans.append((start, end))
        if has_trailing_comma:
            previous_comma = index
            index += 1
        else:
            break
    return spans


class HandlerJson(HandlerBase):
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        spans = _top_level_property_spans(text, META_VARIABLE)
        if len(spans) > 1:
            raise ValueError("Unable to load vault meta: duplicate _xvault entries")
        if not spans:
            # default meta
            meta = XVaultMeta.new(schema_version=1)
        else:
            try:
                data = json5.loads(text)
            except ValueError as error:
                raise ValueError("Unable to load vault meta: invalid JSON document") from error
            if not isinstance(data, dict) or META_VARIABLE not in data:
                raise ValueError("Unable to load vault meta: invalid _xvault property")
            meta = decode_meta(data[META_VARIABLE])
            # remove meta variable from text
            start, end = spans[0]
            text = text[:start] + text[end:]
            # remove meta comments if exists
            text = text.replace(f"// {META_VARIABLE_COMMENTS}\n", "")
        # return
        return (meta, text)
    def replace_enc_tokens(self, text: str, replacer):
        # first replace ${enc:...} to avoid replacing enc:... inside ${...}
        pattern = r"\$\{enc:[^}\r\n]+\}+"
        text = re.sub(pattern, lambda m: replacer(m.group(0)), text)
        # then replace enc:... that are not inside ${...}
        pattern = r"(?<!\$\{)enc:[^\"\r\n]+"
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
    def setValue(self, text: str, path: str, value: str, encrypt: bool = True) -> str:
        # set value
        actual_value = f"{ENC_PREFIX}{value}" if encrypt else value
        data = json5.loads(text)
        keys = path.split(".")
        target = data
        for key in keys[:-1]:
            if key not in target:
                target[key] = {}
            target = target[key]
        target[keys[-1]] = actual_value
        return json.dumps(data, indent=self.detect_json_indentation(text))

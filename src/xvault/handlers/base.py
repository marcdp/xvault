from abc import abstractmethod
import base64
import binascii
import json
import re

from ..meta import META_VARIABLE_PREFIX, XVaultMeta


def decode_meta(value: object, schema_version: int = 1) -> XVaultMeta:
    """Decode a metadata value that is known to be present."""
    if not isinstance(value, str) or not value.startswith(META_VARIABLE_PREFIX):
        raise ValueError("Unable to load vault meta: invalid _xvault format")
    payload = value[len(META_VARIABLE_PREFIX):]
    if not re.fullmatch(r"[A-Za-z0-9_-]*={0,2}", payload):
        raise ValueError("Unable to load vault meta: invalid base64 payload")
    try:
        decoded = base64.b64decode(
            payload.encode("ascii"),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise ValueError("Unable to load vault meta: invalid base64 payload") from error
    try:
        data = json.loads(decoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Unable to load vault meta: invalid JSON payload") from error
    try:
        return XVaultMeta.from_dict(schema_version=schema_version, data=data)
    except ValueError as error:
        message = str(error)
        if message.startswith("Unable to load vault meta:"):
            raise
        raise ValueError(f"Unable to load vault meta: {message}") from error


class HandlerBase:
    @abstractmethod
    def parse(self, text: str) -> tuple[XVaultMeta, str]:
        pass

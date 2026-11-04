from typing import Optional


DEFAULT_VERSION = "1"
META_VARIABLE = "_xvault"  # variable name in JSON/YAML/ENV for storing meta info
META_VARIABLE_PREFIX = "xvault:"  # prefix for the value of META_VARIABLE, followed by base64-encoded meta JSON, e.g. "xvault:eyJjcnlwdG9fdmVyc2lvbiI6IDEsICJzYWx0IjogIjIxYWYyY2ExZGViMmRhZDgxYTAwZGJiNGQ2MDcwMWYzIiwgImNoZWNrIjogImVuYzp2MTovRUF3R0RRWHdVcXJNRUlFN1dMdFV3dEowMnpHWlczQkpMTS9BeGJBd3YvOSt3PT0ifQ=="
META_VARIABLE_COMMENTS = "xvault metadata. To view/edit secrets in this file use: pip install -e xvault; xvault edit <file>;"  # comments to indicate the purpose of META_VARIABLE, used in JSON/YAML/ENV
META_CHECK_VALUE = "xvault"  # known value used to validate password by trying to decrypt it, stored in "_xvault.check"
ENC_PREFIX = "enc:"     # prefix used to identify encrypted values in the store, followed by version info, e.g. "enc:...."


class XVaultMeta():
    def __init__(self, schema_version: int, crypto_version: int, salt: str, check: Optional[str]):
        self.schema_version = schema_version
        self.crypto_version = crypto_version
        self.salt = salt
        self.check = check
    def to_dict(self):
        return {
            "crypto_version": self.crypto_version,
            "salt": self.salt,
            "check": self.check
        }
    def from_dict(schema_version:int, data: dict):
        return XVaultMeta(
            schema_version,
            crypto_version = data.get("crypto_version", 1),
            salt = data.get("salt"),
            check = data.get("check")
        )

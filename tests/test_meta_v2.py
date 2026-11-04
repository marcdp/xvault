import base64

import pytest

from xvault.meta import XVaultMeta


def test_metadata_serializes_exact_version_specific_fields():
    v1 = XVaultMeta(1, 1, "00" * 16, check="check")
    v2 = XVaultMeta(1, 2, "11" * 16, encrypted_key=base64.urlsafe_b64encode(b"x" * 60).decode())

    assert v1.to_dict() == {"crypto_version": 1, "salt": "00" * 16, "check": "check"}
    assert v2.to_dict() == {"crypto_version": 2, "salt": "11" * 16, "encrypted_key": v2.encrypted_key}


def test_metadata_treats_missing_version_as_v1():
    assert XVaultMeta.from_dict(1, {"salt": "00" * 16, "check": "check"}).crypto_version == 1


@pytest.mark.parametrize("data", [
    {"crypto_version": 3, "salt": "00" * 16},
    {"crypto_version": 2, "salt": "00" * 16},
    {"crypto_version": 2, "salt": "bad", "encrypted_key": "x"},
    {"crypto_version": 2, "salt": "00" * 16, "encrypted_key": "bad"},
])
def test_metadata_rejects_unsupported_or_malformed_v2(data):
    with pytest.raises(ValueError):
        XVaultMeta.from_dict(1, data)

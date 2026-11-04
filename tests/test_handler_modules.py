import pytest

from xvault.handlers.base import HandlerBase
from xvault.handlers.env import HandlerEnv
from xvault.handlers.json import HandlerJson
from xvault.handlers.jsonc import HandlerJsonc
from xvault.handlers.markdown import HandlerMd
from xvault.handlers.ovpn import HandlerOvpn
from xvault.handlers.yaml import HandlerYaml
from xvault.meta import (
    DEFAULT_VERSION,
    ENC_PREFIX,
    META_CHECK_VALUE,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)
from xvault.xvault import (
    HANDLERS,
    DEFAULT_VERSION as COMPAT_DEFAULT_VERSION,
    ENC_PREFIX as COMPAT_ENC_PREFIX,
    META_CHECK_VALUE as COMPAT_META_CHECK_VALUE,
    META_VARIABLE as COMPAT_META_VARIABLE,
    META_VARIABLE_COMMENTS as COMPAT_META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX as COMPAT_META_VARIABLE_PREFIX,
    HandlerBase as CompatHandlerBase,
    HandlerEnv as CompatHandlerEnv,
    HandlerJson as CompatHandlerJson,
    HandlerJsonc as CompatHandlerJsonc,
    HandlerMd as CompatHandlerMd,
    HandlerOvpn as CompatHandlerOvpn,
    HandlerXml,
    HandlerYaml as CompatHandlerYaml,
    XVault,
    XVaultMeta as CompatXVaultMeta,
)


@pytest.mark.parametrize(
    ("suffix", "handler_type"),
    [
        (".json", HandlerJson),
        (".jsonc", HandlerJsonc),
        (".yaml", HandlerYaml),
        (".yml", HandlerYaml),
        (".env", HandlerEnv),
        (".md", HandlerMd),
        (".ovpn", HandlerOvpn),
    ],
)
def test_xvault_selects_handler_from_extension(tmp_path, monkeypatch, suffix, handler_type):
    path = tmp_path / f"vault{suffix}"
    path.write_text("", encoding="utf-8")
    monkeypatch.setattr(XVault, "_load", lambda self: None)

    vault = XVault(str(path))

    assert isinstance(vault._handler, handler_type)
    assert HANDLERS[suffix] is handler_type


def test_handler_and_metadata_compatibility_imports():
    assert CompatHandlerBase is HandlerBase
    assert CompatHandlerJson is HandlerJson
    assert CompatHandlerJsonc is HandlerJsonc
    assert CompatHandlerYaml is HandlerYaml
    assert CompatHandlerEnv is HandlerEnv
    assert CompatHandlerMd is HandlerMd
    assert CompatHandlerOvpn is HandlerOvpn
    assert CompatXVaultMeta is XVaultMeta
    assert COMPAT_DEFAULT_VERSION == DEFAULT_VERSION
    assert COMPAT_ENC_PREFIX == ENC_PREFIX
    assert COMPAT_META_CHECK_VALUE == META_CHECK_VALUE
    assert COMPAT_META_VARIABLE == META_VARIABLE
    assert COMPAT_META_VARIABLE_COMMENTS == META_VARIABLE_COMMENTS
    assert COMPAT_META_VARIABLE_PREFIX == META_VARIABLE_PREFIX
    assert issubclass(HandlerXml, HandlerBase)


def test_xml_is_not_in_supported_handler_mapping(tmp_path):
    path = tmp_path / "vault.xml"
    path.write_text("<vault />", encoding="utf-8")

    assert ".xml" not in HANDLERS
    with pytest.raises(ValueError, match="unsupported file format"):
        XVault(str(path))

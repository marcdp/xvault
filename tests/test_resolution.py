import pytest

from xvault.xvault import HandlerEnv, HandlerYaml, XVault


class StubVault(XVault):
    def __init__(self):
        pass


def make_vault(handler):
    vault = StubVault.__new__(StubVault)
    vault._handler = handler
    return vault


def test_resolve_replaces_multiple_placeholders_from_same_text():
    vault = make_vault(HandlerEnv())
    text = (
        "DB_HOST=localhost\n"
        "DB_PORT=5432\n"
        "DATABASE_URL=postgres://${var:DB_HOST}:${var:DB_PORT}/app\n"
    )

    resolved = vault._resolve(text)

    assert "DATABASE_URL=postgres://localhost:5432/app" in resolved


def test_resolve_uses_handler_path_lookup_for_yaml():
    vault = make_vault(HandlerYaml())
    text = (
        "DB_HOST: localhost\n"
        "DB_PORT: 5432\n"
        "url: postgres://${var:DB_HOST}:${var:DB_PORT}/app\n"
    )

    resolved = vault._resolve(text)

    assert "url: postgres://localhost:5432/app" in resolved


def test_resolve_raises_for_missing_variable():
    vault = make_vault(HandlerEnv())

    with pytest.raises(ValueError, match="variable 'MISSING' not found"):
        vault._resolve("VALUE=${var:MISSING}\n")


def test_resolve_does_not_replace_variables_without_var_prefix():
    vault = make_vault(HandlerEnv())
    text = (
        "DB_HOST=localhost\n"
        "DATABASE_URL=postgres://${DB_HOST}/app\n"
    )

    resolved = vault._resolve(text)

    assert "DATABASE_URL=postgres://${DB_HOST}/app" in resolved

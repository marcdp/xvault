import base64
import json
import pytest

from xvault.xvault import (
    ENC_PREFIX,
    HandlerEnv,
    HandlerJson,
    HandlerJsonc,
    HandlerMd,
    HandlerOvpn,
    HandlerYaml,
    META_VARIABLE,
    META_VARIABLE_COMMENTS,
    META_VARIABLE_PREFIX,
    XVaultMeta,
)


def encode_meta(meta_dict):
    return META_VARIABLE_PREFIX + base64.urlsafe_b64encode(json.dumps(meta_dict).encode()).decode()


def test_handler_json_parse_removes_meta_and_loads_it():
    handler = HandlerJson()
    text = '{\n  "_xvault": "' + encode_meta({
        "crypto_version": 2,
        "salt": "00" * 16,
        "encrypted_key": base64.urlsafe_b64encode(b"x" * 60).decode(),
    }) + '",\n  "name": "value"\n}'

    meta, parsed = handler.parse(text)

    assert meta.crypto_version == 2
    assert meta.salt == "00" * 16
    assert meta.encrypted_key == base64.urlsafe_b64encode(b"x" * 60).decode()
    assert META_VARIABLE not in parsed
    assert '"name": "value"' in parsed


def test_handler_env_get_value_reads_plain_values():
    handler = HandlerEnv()
    text = "VAR1=value\nVAR2=other\n"

    assert handler.getValue(text, "VAR1") == "value"
    assert handler.getValue(text, "MISSING") is None


def test_handler_yaml_get_value_reads_nested_paths():
    handler = HandlerYaml()
    text = "db:\n  host: localhost\n  port: 5432\n"

    assert handler.getValue(text, "db.host") == "localhost"
    assert handler.getValue(text, "db.user") is None


def test_handler_yaml_replace_enc_tokens_replaces_plain_token():
    handler = HandlerYaml()

    result = handler.replace_enc_tokens("secret: enc:abc123\n", lambda value: f"<{value}>")

    assert result == "secret: <enc:abc123>\n"


def test_handler_yaml_replace_enc_tokens_replaces_wrapped_token():
    handler = HandlerYaml()

    result = handler.replace_enc_tokens("secret: ${enc:abc123}\n", lambda value: f"<{value}>")

    assert result == "secret: <${enc:abc123}>\n"


def test_handler_json_replace_enc_tokens_replaces_wrapped_and_plain_tokens():
    handler = HandlerJson()
    text = '{"a": "${enc:abc123}", "b": "enc:def456"}\n'

    result = handler.replace_enc_tokens(text, lambda value: f"<{value}>")

    assert result == '{"a": "<${enc:abc123}>", "b": "<enc:def456>"}\n'


def test_handler_jsonc_replace_enc_tokens_replaces_wrapped_token():
    handler = HandlerJsonc()
    text = '{"a": "${enc:abc123}"}\n'

    result = handler.replace_enc_tokens(text, lambda value: f"<{value}>")

    assert result == '{"a": "<${enc:abc123}>"}\n'


def test_handler_env_replace_enc_tokens_replaces_wrapped_and_plain_tokens():
    handler = HandlerEnv()
    text = "VAR1=${enc:abc123}\nVAR2=enc:def456\n"

    result = handler.replace_enc_tokens(text, lambda value: f"<{value}>")

    assert result == "VAR1=<${enc:abc123}>\nVAR2=<enc:def456>\n"


def test_handler_md_replace_enc_tokens_replaces_wrapped_token():
    handler = HandlerMd()
    text = "secret is ${enc:abc123}\n"

    result = handler.replace_enc_tokens(text, lambda value: f"<{value}>")

    assert result == "secret is <${enc:abc123}>\n"


def test_handler_md_parse_extracts_front_matter_meta():
    handler = HandlerMd()
    text = "---\n_xvault: " + encode_meta({"crypto_version": 1, "salt": "abcd", "check": None}) + "\n---\n\n# Title\n"

    meta, parsed = handler.parse(text)

    assert isinstance(meta, XVaultMeta)
    assert meta.salt == "abcd"
    assert parsed == "# Title\n"


def test_handler_ovpn_parse_extracts_meta_and_removes_meta_lines():
    handler = HandlerOvpn()
    text = (
        "# " + META_VARIABLE_COMMENTS + "\n"
        + "# _xvault=" + encode_meta({"crypto_version": 1, "salt": "abcd", "check": "enc:test"}) + "\n\n"
        + "client\n"
    )

    meta, parsed = handler.parse(text)

    assert isinstance(meta, XVaultMeta)
    assert meta.salt == "abcd"
    assert "_xvault" not in parsed
    assert parsed == "client\n"


def test_handler_ovpn_replace_enc_tokens_replaces_inline_secret_blocks():
    handler = HandlerOvpn()
    text = (
        "client\n\n"
        "<auth-user-pass>\n"
        "${enc:my-user}\n"
        "${enc:my-pass}\n"
        "</auth-user-pass>\n"
    )

    result = handler.replace_enc_tokens(text, lambda value: f"<{value}>")

    assert result == (
        "client\n\n"
        "<auth-user-pass>\n"
        "<${enc:my-user}>\n"
        "<${enc:my-pass}>\n"
        "</auth-user-pass>\n"
    )


# ── HandlerJson.setValue ──────────────────────────────────────────────────────

def test_handler_json_set_value_replaces_existing_key_with_enc_prefix():
    handler = HandlerJson()
    text = '{\n  "password": "old"\n}'

    result = handler.setValue(text, "password", "secret")

    data = json.loads(result)
    assert data["password"] == f"{ENC_PREFIX}secret"


def test_handler_json_set_value_creates_new_key():
    handler = HandlerJson()
    text = '{\n  "name": "alice"\n}'

    result = handler.setValue(text, "token", "abc123")

    data = json.loads(result)
    assert data["token"] == f"{ENC_PREFIX}abc123"
    assert data["name"] == "alice"


def test_handler_json_set_value_nested_path():
    handler = HandlerJson()
    text = '{\n  "db": {"host": "localhost"}\n}'

    result = handler.setValue(text, "db.password", "secret", encrypt=False)

    data = json.loads(result)
    assert data["db"]["password"] == "secret"
    assert data["db"]["host"] == "localhost"


def test_handler_json_set_value_plain_no_enc_prefix():
    handler = HandlerJson()
    text = '{\n  "key": "old"\n}'

    result = handler.setValue(text, "key", "plain", encrypt=False)

    data = json.loads(result)
    assert data["key"] == "plain"
    assert ENC_PREFIX not in result


# ── HandlerJsonc.setValue ─────────────────────────────────────────────────────

def test_handler_jsonc_set_value_raises_not_implemented():
    handler = HandlerJsonc()

    with pytest.raises(NotImplementedError):
        handler.setValue('{"key": "value"}', "key", "new")


# ── HandlerEnv.setValue ───────────────────────────────────────────────────────

def test_handler_env_set_value_replaces_existing_key():
    handler = HandlerEnv()
    text = "VAR1=old\nVAR2=other\n"

    result = handler.setValue(text, "VAR1", "secret")

    assert f"VAR1={ENC_PREFIX}secret" in result
    assert "VAR2=other" in result
    assert "VAR1=old" not in result


def test_handler_env_set_value_appends_new_key():
    handler = HandlerEnv()
    text = "VAR1=existing\n"

    result = handler.setValue(text, "NEW_VAR", "myvalue")

    assert f"NEW_VAR={ENC_PREFIX}myvalue" in result
    assert "VAR1=existing" in result


def test_handler_env_set_value_plain_no_enc_prefix():
    handler = HandlerEnv()
    text = "VAR1=old\n"

    result = handler.setValue(text, "VAR1", "plain", encrypt=False)

    assert "VAR1=plain" in result
    assert ENC_PREFIX not in result


# ── HandlerYaml.setValue ──────────────────────────────────────────────────────

def test_handler_yaml_set_value_replaces_existing_key():
    handler = HandlerYaml()
    text = "password: old\n"

    result = handler.setValue(text, "password", "secret")

    import yaml
    data = yaml.safe_load(result)
    assert data["password"] == f"{ENC_PREFIX}secret"


def test_handler_yaml_set_value_creates_new_key():
    handler = HandlerYaml()
    text = "host: localhost\n"

    result = handler.setValue(text, "password", "secret")

    import yaml
    data = yaml.safe_load(result)
    assert data["password"] == f"{ENC_PREFIX}secret"
    assert data["host"] == "localhost"


def test_handler_yaml_set_value_nested_path():
    handler = HandlerYaml()
    text = "db:\n  host: localhost\n"

    result = handler.setValue(text, "db.password", "secret", encrypt=False)

    import yaml
    data = yaml.safe_load(result)
    assert data["db"]["password"] == "secret"
    assert data["db"]["host"] == "localhost"


def test_handler_yaml_set_value_plain_no_enc_prefix():
    handler = HandlerYaml()
    text = "key: old\n"

    result = handler.setValue(text, "key", "plain", encrypt=False)

    import yaml
    data = yaml.safe_load(result)
    assert data["key"] == "plain"
    assert ENC_PREFIX not in result


# ── HandlerOvpn.setValue ──────────────────────────────────────────────────────

def test_handler_ovpn_set_value_replaces_inline_directive():
    handler = HandlerOvpn()
    text = "client\ndev tun\nproto udp\n"

    result = handler.setValue(text, "dev", "tap", encrypt=False)

    assert "dev tap" in result
    assert "dev tun" not in result
    assert "proto udp" in result


def test_handler_ovpn_set_value_replaces_block_section():
    handler = HandlerOvpn()
    text = (
        "client\n"
        "<auth-user-pass>\n"
        "old-user\n"
        "old-pass\n"
        "</auth-user-pass>\n"
    )

    result = handler.setValue(text, "auth-user-pass", "new-user\nnew-pass", encrypt=False)

    assert "<auth-user-pass>\nnew-user\nnew-pass\n</auth-user-pass>" in result
    assert "old-user" not in result
    assert "old-pass" not in result


def test_handler_ovpn_set_value_appends_new_directive():
    handler = HandlerOvpn()
    text = "client\nproto udp\n"

    result = handler.setValue(text, "verb", "3", encrypt=False)

    assert "verb 3" in result
    assert "client" in result


def test_handler_ovpn_set_value_encrypt_prefixes_lines_with_enc():
    handler = HandlerOvpn()
    text = (
        "client\n"
        "<auth-user-pass>\n"
        "old-user\n"
        "old-pass\n"
        "</auth-user-pass>\n"
    )

    result = handler.setValue(text, "auth-user-pass", "my-user\nmy-pass", encrypt=True)

    assert f"<auth-user-pass>\n{ENC_PREFIX}my-user\n{ENC_PREFIX}my-pass\n</auth-user-pass>" in result
    assert "old-user" not in result


def test_handler_ovpn_set_value_wraps_encrypted_inline_value():
    handler = HandlerOvpn()

    result = handler.setValue("client\nverb 3\n", "verb", "secret", encrypt=True)

    assert "verb ${enc:secret}" in result


def test_handler_ovpn_set_value_appends_multiline_value_as_block():
    handler = HandlerOvpn()

    result = handler.setValue("client\n", "auth-user-pass", "enc:user\nenc:password", encrypt=False)

    assert "<auth-user-pass>\nenc:user\nenc:password\n</auth-user-pass>" in result

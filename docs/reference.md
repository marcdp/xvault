# File-format reference

This reference describes the on-disk representation implemented by xvault version 1 handlers. Plaintext in the editor, encrypted source on disk, and decrypted `get` or `export` output are different representations.

## Supported file types

| Extension | Metadata location | `get` / `set` |
| --- | --- | --- |
| `.json` | top-level `_xvault` property | dot paths / dot paths |
| `.jsonc` | top-level `_xvault` property | dot paths / `set` unsupported |
| `.yaml`, `.yml` | top-level `_xvault` mapping key | dot paths / dot paths |
| `.env` | `_xvault=...` entry | variable name / variable name |
| `.md` | YAML-style front matter | unsupported / unsupported |
| `.ovpn` | `# _xvault=...` comment | directive or block / directive or block |

`.xml` is recognized by the constructor but has no implemented handler and is not a usable xvault file type.

## Secret markers

xvault processes two marker forms:

```text
enc:VALUE
${enc:VALUE}
```

When `edit` saves, `VALUE` is encrypted and replaced with URL-safe base64 ciphertext. The marker remains, so stored values look like `enc:...` or `${enc:...}`. When the editor opens, it decrypts the value but preserves the marker; `get` and `export` instead return the decrypted value without `enc:`.

Use a whole-value marker for a normal secret:

```env
PASSWORD=enc:plain-value-before-edit
```

Use the wrapped form inside surrounding content:

```env
URL=https://user:${enc:plain-value-before-edit}@example.test/db
```

Marker matching is textual, not a general parser. Marker content must be nonempty and single-line. In JSON, JSONC, YAML, and Markdown, an unwrapped marker stops at a double quote or line break. In ENV it also stops at `#` or a single quote. In OpenVPN, unwrapped `enc:` values are recognized only at the start of a line; wrapped markers may appear inline. Delimiters inside a secret therefore require the wrapped form where it is supported, or a format-safe representation such as base64.

`set` encrypts the supplied value before saving it and keeps the `enc:` marker on disk. With `--no-encrypt`, it intentionally stores the supplied value without a marker as plaintext.

## Variable references

`${var:NAME}` is a separate plaintext placeholder. `get --resolve` and `export --resolve` replace it with a value obtained from the same decrypted file through that format's lookup handler. `NAME` must match `[A-Za-z_][A-Za-z0-9_]*`; dot paths are not valid reference names even though JSON and YAML lookups accept dot paths. Missing names raise an error.

Resolution makes one substitution pass and has no escaping syntax. It does not read the environment, another file, or a keyring value. Markdown has no lookup handler, so resolving Markdown references is unsupported.

## File metadata

On first save, xvault adds `_xvault` metadata. Its value begins with `xvault:` followed by URL-safe base64 encoding of a JSON object:

```json
{
  "crypto_version": 1,
  "salt": "<32 hexadecimal characters>",
  "check": "<URL-safe base64 encrypted check value>"
}
```

`schema_version` is fixed at 1 by the handlers and is reported by `info`, but is not written into this JSON object. `salt` is 16 random bytes represented as 32 hexadecimal characters. `check` encrypts a known internal value and lets xvault verify that a supplied password or cached key is correct.

Metadata placement is format-specific:

```json
{"_xvault":"xvault:<base64-json>","password":"enc:<ciphertext>"}
```

```env
_xvault=xvault:<base64-json>
PASSWORD=enc:<ciphertext>
```

Markdown writes a front-matter block; OpenVPN writes commented metadata. The metadata is removed while the file is processed and written again on save. The leading explanatory comment is informational, not part of the cryptographic format.

## Encryption representation

For `crypto_version` 1, xvault derives a 32-byte key with Argon2id from the password and metadata salt. The current parameters are time cost 5, memory cost 131072 KiB, parallelism 4, and output length 32 bytes.

Each marked value uses AES-256-GCM with a new random 12-byte nonce. The stored payload is URL-safe base64 of:

```text
nonce (12 bytes) || AES-GCM ciphertext-and-tag
```

The `enc:` prefix and the payload do not contain an explicit per-token version. AES-GCM is invoked without associated data. A wrong key or changed payload fails authentication during decryption. Do not treat an example placeholder as real ciphertext; only values produced with the corresponding key can decrypt.

## Format-specific behavior

JSON and JSONC are read with a JSON5 parser; JSON `set` serializes the document as JSON, while JSONC `set` is deliberately unimplemented. YAML `set` loads and rewrites YAML, so formatting may change. ENV lookup uses dotenv-style parsing.

Markdown processing is text-based after its initial front matter. It is useful for notes and fenced blocks, but has neither `getValue` nor `setValue`.

OpenVPN supports a single-line directive such as `verb 3` and a block such as:

```text
<auth-user-pass>
${enc:user}
${enc:password}
</auth-user-pass>
```

When an OpenVPN value is set with encryption, each supplied line is encrypted independently and receives an `enc:` marker. This preserves line-oriented material without re-encrypting other values in the profile.

## Compatibility and limits

Only crypto version 1 is accepted. A different `crypto_version` in metadata is rejected. The code does not establish a broader compatibility guarantee or a multi-version migration protocol.

The file structure outside marked values is not authenticated by the value encryption. Marker matching is regex-based and can be affected by unsupported quoting or delimiter arrangements. Comments and formatting can also change when handlers serialize JSON, YAML, or metadata. Use `validate` and review the resulting diff before committing.

# File-format reference

This reference describes the versioned on-disk representation. Plaintext in the editor, encrypted source on disk, and decrypted `get` or `export` output are different representations.

## Supported file types

| Extension | Metadata location | `get` / `set` |
| --- | --- | --- |
| `.json` | top-level `_xvault` property | dot paths / dot paths |
| `.jsonc` | top-level `_xvault` property | dot paths / `set` unsupported |
| `.yaml`, `.yml` | top-level `_xvault` mapping key | dot paths / dot paths |
| `.env` | `_xvault=...` entry | variable name / variable name |
| `.md` | YAML-style front matter | unsupported / unsupported |
| `.ovpn` | `# _xvault=...` comment | directive or block / directive or block |

XML has no implemented handler and is not a supported xvault file type.

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

`set` encrypts the supplied value before saving it and keeps the `enc:` marker on disk. If the vault is uninitialized, the first encrypting `set` encrypts all existing plaintext `enc:` markers together with the new value before atomically writing v2 metadata. Once initialized, `set` encrypts only the supplied value and does not re-encrypt unrelated ciphertext. With `--no-encrypt`, it intentionally stores the supplied value without a marker as plaintext and does not initialize the vault.

## Variable references

`${var:NAME}` is a separate plaintext placeholder. `get --resolve` and `export --resolve` replace it with a value obtained from the same decrypted file through that format's lookup handler. `NAME` must match `[A-Za-z_][A-Za-z0-9_]*`; dot paths are not valid reference names even though JSON and YAML lookups accept dot paths. Missing names raise an error.

Resolution makes one substitution pass and has no escaping syntax. It does not read the environment, another file, or a keyring value. Markdown has no lookup handler, so resolving Markdown references is unsupported.

## File metadata

On the first encrypting save, xvault adds `_xvault` metadata. Its value begins with `xvault:` followed by URL-safe base64 encoding of a JSON object. Existing v1 vaults retain this form:

```json
{
  "crypto_version": 1,
  "salt": "<32 hexadecimal characters>",
  "check": "<URL-safe base64 encrypted check value>"
}
```

New vaults use v2:

```json
{
  "crypto_version": 2,
  "salt": "<32 hexadecimal characters>",
  "encrypted_key": "<URL-safe base64 wrapped DEK>"
}
```

`schema_version` remains fixed at 1 in the handlers and is reported by `info`, but is not written into this JSON object. Both salts are 16 random bytes represented as 32 hexadecimal characters. V1's `check` encrypts a known internal value. V2 authenticates a credential by unwrapping `encrypted_key` and never writes `check`. Missing or malformed required v2 fields are errors, not an invitation to create a replacement key. An absent `_xvault` field identifies an uninitialized vault; a present empty, invalidly encoded, duplicate, or otherwise malformed field is a load error and is never replaced with new metadata.

Metadata placement is format-specific:

```json
{"_xvault":"xvault:<base64-json>","password":"enc:<ciphertext>"}
```

```env
_xvault=xvault:<base64-json>
PASSWORD=enc:<ciphertext>
```

Markdown writes or updates `_xvault` inside the leading YAML front-matter block.
Unrelated keys, comments, nested values, delimiters, and body text are retained;
a literal `_xvault` in the Markdown body is not metadata. Existing malformed or
duplicate top-level `_xvault` fields fail safely. OpenVPN writes commented
metadata. The leading explanatory comment is informational, not part of the
cryptographic format.

## Encryption representation

Both versions use Argon2id with a 16-byte salt, time cost 5, memory cost 131072 KiB, parallelism 4, and a 32-byte output. V1 uses that output directly for value encryption. V2 uses it as a key-encryption key (KEK). A fresh random 32-byte data-encryption key (DEK) encrypts values and is generated exactly once when a new v2 vault is initialized.

V2 wraps the DEK with AES-256-GCM under the KEK, a fresh 12-byte nonce, and associated data `xvault:v2:dek`. `encrypted_key` is URL-safe base64 of:

```text
nonce (12 bytes) || encrypted DEK (32 bytes) || GCM tag (16 bytes)
```

Each marked value uses AES-256-GCM with a new random 12-byte nonce. The stored payload is URL-safe base64 of:

```text
nonce (12 bytes) || AES-GCM ciphertext-and-tag
```

The `enc:` prefix and payload do not contain a per-token version; metadata selects the crypto implementation. Secret AES-GCM is invoked with no associated data in both v1 and v2. Field identity authentication is deliberately not part of v2. A wrong key or changed payload fails authentication during decryption.

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

Crypto versions 1 and 2 are accepted; other versions are rejected. Existing v1 files are never upgraded implicitly. `xvault upgrade FILE` performs the explicit v1-to-v2 migration and re-encrypts marked values under a fresh DEK. V2 password rotation only rewraps the existing DEK, leaving every secret ciphertext unchanged.

The file structure outside marked values is not authenticated by the value encryption. Marker matching is regex-based and can be affected by unsupported quoting or delimiter arrangements. Comments and formatting can also change when handlers serialize JSON, YAML, or metadata. Use `validate` and review the resulting diff before committing.

## Interoperability contract

The structures and algorithms above are the compatibility contract for
independent readers. In particular:

- Metadata JSON contains exactly the version-specific fields shown above and is
  URL-safe-base64 encoded after `xvault:`.
- Argon2id parameters are time cost 5, memory cost 131072 KiB, parallelism 4,
  and 32-byte output with the 16-byte metadata salt.
- V1 uses the derived key for values and authenticates it by decrypting `check`.
- V2 wraps a random 32-byte DEK with the fixed AAD bytes `xvault:v2:dek`; secret
  values use no AAD in either version.
- Wrapped DEKs and values use `nonce || ciphertext || GCM tag` and URL-safe
  base64. AES-GCM nonces are 12 bytes and tags are 16 bytes.
- Rekeying V2 changes salt and wrapped-DEK metadata but preserves the DEK and
  value ciphertext. Migration from V1 is explicit and generates a new V2 DEK.
- Keyring identities are implementation integration details described in the
  usage guide; they are version-separated and are not part of the file format.

The independent .NET `DProjects.XVault` library in `marcdp/libs` is a read-only
consumer of this contract; it does not have feature parity with the Python CLI.
The committed `tests/fixtures/v1.env` and `tests/fixtures/v2.env` files are the
canonical Python-generated fixed vectors for consumers. Python tests cover their
valid passwords, invalid credentials, corrupted wrapped DEKs and ciphertext,
V2 metadata-only rotation, explicit migration, and generated round trips for all
supported formats. Downstream consumers should test these same vectors rather
than inventing a divergent protocol representation.

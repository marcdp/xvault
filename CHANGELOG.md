# Changelog

All notable changes to xvault are documented here.

## [Unreleased]

### Changed

- Prepare the `0.1.0` pre-1.0 compatibility milestone without publishing it.
- Make single-secret editing a real public `XVault` operation for addressable
  formats, preserving unrelated ciphertext.
- Preserve user-owned Markdown front matter when initializing, editing, and
  migrating vaults.
- Make full-document edits prepare, atomically commit, and only then activate
  candidate text, metadata, and cryptographic state.
- Add strict authenticated validation and non-sensitive verbose diagnostics while
  retaining warning exit compatibility by default.
- Declare PyYAML as a direct runtime dependency and expand cross-platform,
  packaging, and clean-install CI verification.

### CryptoV2 milestone

- Envelope encryption is the default for new vaults: a password-derived KEK
  authenticates and wraps a random DEK stored in versioned metadata.
- CryptoV1 files remain supported and are upgraded only through explicit
  `xvault upgrade` migration.
- CryptoV2 password rotation changes salt and wrapped-DEK metadata while
  preserving the DEK and all value ciphertext.
- V1 and V2 keyring identities are separated.
- Atomic persistence and malformed-metadata failure handling are strengthened.
- The byte-level interoperability contract and canonical Python fixtures for the
  independent read-only .NET consumer are documented.

### Limitations

- Encryption covers marked values, not the complete document or field identity.
- V2 password rotation is not DEK rotation and cannot revoke historical Git
  revisions.
- CryptoV2 has not undergone an independent security audit.

[Unreleased]: https://github.com/marcdp/xvault/compare/main...HEAD


# xvault

**xvault is a CLI for keeping secrets _inside_ your real config and notes files, while staying Git-friendly.**

Your files remain readable and reviewable, and only the values you explicitly mark as secret are encrypted.

The core idea is a **single source of truth**: store secrets, notes, and configuration together in a small set of canonical files (.json, .jsonc, .yaml, .env, .md), and let `xvault` handle safe editing, encryption, and export.

From these files, you can **derive/export/resolve** the exact formats your tooling expects (e.g., `.env`, JSON config, certificate files) without duplicating plaintext secrets across multiple files or repositories.

To minimize **cognitive load**, `xvault` keeps the workflow intentionally simple: secure defaults, straightforward commands, and optional OS key caching (no servers to run, no KMS to configure, and no complex policy systems). It’s optimized for **solo developers and small teams** who want a **local-first** vault that integrates cleanly with Git.

---

## Intro

### Motivation: single source of truth for developer secrets
Most developer workflows end up with friction such as:

- a config file plus a separate secrets file
- manual merging before deployment / resolving secrets at runtime
- ugly diffs (whole files encrypted)
- accidental leaks when exporting plaintext

`xvault` is designed to keep your **notes and configs** as the source of truth, with **inline secrets** that stay encrypted on disk.

### Comparison: SOPS and git-crypt
`xvault` overlaps with tools like SOPS and git-crypt, but it targets a slightly different “developer ergonomics” space:

- **SOPS** shines for GitOps/Kubernetes workflows and KMS-backed key management. It’s great when your infra pipeline is already built around SOPS + KMS/PGP/age.  
  `xvault` is not trying to replace that ecosystem; it focuses on **editing arbitrary files (.json, .jsonc, .env, .yml, .md)** with minimal ceremony and clean diffs.

- **git-crypt** is effective for encrypting entire files transparently in Git.  
  `xvault` takes a more explicit approach: secrets are marked with `enc:` and only those values are encrypted, keeping the rest of the document readable.

If your main need is “encrypt a whole directory of files in git”, git-crypt may be enough.  
If your main need is “keep notes/config readable while only encrypting secret values”, `xvault` is a better fit.

### Design philosophy
- **Explicit by default**: only values marked with `enc:` are treated as secrets.
- **Git diffs matter**: keep secrets stored as single-line ciphertext.
- **Stay close to real formats**: work with .json, .jsonc, .yaml, .env, .md, without forcing a rigid schema.
- **Developer UX first**: `edit` is the primary workflow; everything else supports it.
- **Safe defaults**: prefer failing loudly over producing ambiguous output.

---

## Usage

`xvault` is designed for two main workflows. Both rely on the same core idea: **keep secrets inside the files you already use**, encrypt only what you explicitly mark as secret (`enc:`), and derive/export the exact outputs when needed.

### 1) Application config files with embedded secrets

Use `xvault` directly on configuration files that your applications and tooling already understand:

- `.env` files
- JSON / JSONC
- YAML
- md files

You keep the config readable, and only encrypt values marked as secrets (`enc:...`, and in YAML also `{enc:...}`).

Example (`dev.env`):
```env
DB_HOST=localhost
DB_USER=enc:admin
DB_PASS=enc:"my password with spaces"
```
Typical workflow:

- `xvault edit ./dev.env` to safely edit secrets and non-secret config together
- `xvault export ./dev.env` to materialize a decrypted output for scripts/CI/runtime
- `xvault get ./dev.env DB_PASS` to extract a decrypted value from file

### 2) Personal vault notes (Markdown)

Use `xvault` as a local-first personal vault where you store notes, runbooks, logs, credentials, and key material inside Markdown files.

A common pattern is:

- one Markdown file per topic (e.g., servers.md, accounts.md, infra.md)
- secrets stored inside standard fenced blocks like ```env

Example (servers.md):

````md
## prod-api-01

Notes and runbook steps in plain text...

```env
SSH_HOST=prod-api-01.example.com
SSH_USER=enc:admin
SSH_PASS=enc:"my password with spaces"
SSH_KEY_PEM_B64=enc:LS0tLS1CRUdJTiBPU...
```
```` 

Guidelines:
- Use enc: for secret values (YAML also supports `{enc:...}`).
- Use *_B64 variables for multi-line or binary material (PEM/PFX/PDF/PNG) encoded as base64.
- Keep everything else (notes, procedures, logs) in plain text for excellent Git diffs and searchability.

---

## Features

- **Formats**: .json, .jsonc, .yaml, .env, .md
- **Inline secret marking**: `enc:` prefix indicates secret values (YAML also supports `{enc:...}`)
- **Single-line ciphertext** for clean Git diffs
- **Optional variable substitution**: resolve `${VAR}` placeholders (`xvault get file.json secret_name --resolve`)
- **Key caching (optional)**:
  - `unlock` stores a derived key in the OS key store
  - `lock` removes it
  - `--no-cache-key` disables cache read/write per command
- **Crypto (v1)**:
  - Password-based key derivation: **Argon2id**
  - Encryption: **AES-256-GCM** (authenticated encryption)
- **Rekey support**: rotate secrets to a new password (`xvault rekey`)
- **Validation**: sanity checks for file structure and encrypted markers (`xvault validate`)

---

## Security Model

### What xvault protects against
- Accidental commits of plaintext secrets by keeping secrets **encrypted on disk**
- “Diff leakage”: avoids storing whole plaintext configs; only `enc:` values become ciphertext
- Backup leakage: encrypted vault files are safe to back up as ciphertext
- Tampering detection: AES-GCM provides integrity/authentication for secret values (wrong key or modified ciphertext fails to decrypt)
- By default, xvault edit uses an in-terminal editor and does not write plaintext temp files.

### Threats it does NOT fully solve (limitations)
- **Weak passwords**: your vault is only as strong as the password you choose. Use a strong passphrase (e.g., 12–16+ characters, preferably more).
- **Compromised machine**: if an attacker owns your box while you edit, they can read memory, or use a keylogger, or inspect terminal buffers. Or if an attacker gains access to your machine, they may be able to extract the cached key from the OS key store and decrypt your vault without ever needing to wait for you to edit.
- **Plaintext exports**: `export` can produce decrypted content. Handle it carefully (gitignore, temporary locations).
- **OS key cache availability**: keyring/credential storage may fail in some contexts (e.g., Windows over SSH). Use `--no-cache-key` or alternative cache strategies.

### Threat mitigations (practical)
- Use a strong, unique password (prefer long passphrases).
- Keep repositories private; avoid cloning vault repos on untrusted machines.
- Prefer `--no-cache-key` in sensitive environments (remote sessions, servers, CI).
- Run `xvault validate` before committing.

### Example file (conceptual)
`xvault` stores a small metadata header (e.g. `_xvault`) and secrets as `enc:` values:

```jsonc
{
  "_xvault": "xvault:<opaque-metadata-blob>",
  "db": {
    "host": "...",
    "user": "enc:...",
    "password": "enc:..."
  }
}
```

```env
_xvault="xvault:<opaque-metadata-blob>"
DB_HOST=...
DB_USER=enc:...
DB_PASSWORD=enc:...
```

## Installation

Install from PyPI:

```bash
pip install xvault
xvault version
```

### Install from source (development)

Clone the repository:

```bash
# clone the repository:
git clone https://github.com/marcdp/xvault.git
# run the CLI:
python -m xvault
# or install as a command:
pip install .
```

---




## Roadmap

Short-term (quality and UX):
- Improve TUI editor UX (colors, navigation, safer save guards, undo-redo)
- Better Markdown conventions for multi-line secrets and binary references
- Safer export modes (explicit confirmations)

Mid-term (developer workflows):
- Export filtering by section/scope in Markdown (e.g., server.var)
- SSH-agent helpers (load selected keys with TTL)
- A "blob store" for large binary secrets (PFX/PDF/PNG) with manifest + encrypted blobs

Long-term:
- VS Code virtual filesystem provider (xvault:/...) backed by xvault (no plaintext temp files)
- Optional policy validation hooks (pre-commit integration)
- Optional alternative key caching backends (more reliable across SSH / WSL)


## License

MIT License

See the LICENSE file for details.
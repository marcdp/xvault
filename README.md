# XVault

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/encryption-AES--256--GCM-purple)
![KDF](https://img.shields.io/badge/KDF-Argon2id-orange)

**XVault** is a portable encrypted vault designed for developers to securely store secrets, tokens, and sensitive files while keeping encrypted vaults safe to store in Git repositories.

The tool is built around a simple idea:

> **Keep encrypted secrets versioned in Git while protecting the keys locally.**

XVault supports modern cryptography, OS keyring integration, and flexible project configuration to make secret management safe and developer-friendly.

---

# Why XVault

Developers often need to store:

- API tokens
- credentials
- environment variables
- configuration files
- private keys
- sensitive documents

These frequently end up in `.env` files, local folders, or worse — accidentally committed to Git.

XVault solves this by providing:

- **Encrypted storage**
- **Git-friendly files**
- **Secure key caching**
- **CLI automation**

## Comparison with SOPS

**XVault** and **SOPS (Secrets OPerationS)**(https://github.com/mozilla/sops))share a similar goal: storing encrypted secrets safely inside version-controlled files. Both tools allow developers to keep encrypted configuration in Git while protecting the decryption keys locally. However, their design philosophies differ. SOPS focuses on infrastructure and DevOps workflows (Kubernetes, Terraform, cloud KMS integration), whereas **xvault** is designed primarily as a **developer-centric vault**, emphasizing simplicity, local password-based encryption, and flexible secret storage for development environments and personal projects.

| Feature | xvault | SOPS |
|-------|-------|------|
| Primary goal | Developer secret vault | Infrastructure secret management |
| Encryption model | Password-derived key (Argon2id) | External key management (KMS, GPG, Age) |
| Encryption algorithm | AES-256-GCM | AES-256-GCM |
| Key derivation | Argon2id | Not applicable (external keys) |
| Key storage | OS keyring (optional cache) | External key providers |
| File format | JSON vault file | YAML / JSON / ENV |
| Git-friendly storage | Yes | Yes |
| CLI workflow | Developer-oriented | DevOps / infrastructure-oriented |
| External dependencies | None required | Often requires KMS / GPG / Age |
| Secret import/export | dotenv, JSON | YAML/JSON editing |
| Typical use case | Developer secrets, local environments, personal vaults | Kubernetes, CI/CD, infrastructure configuration |

### Design Philosophy

- **SOPS** integrates deeply with cloud infrastructure and centralized key management systems.
- **XVault** prioritizes simplicity and portability by using password-derived encryption and local key caching.

This makes XVault particularly suitable for:

- developer environments
- local secret management
- personal encrypted vaults
- Git-friendly secret storage without external infrastructure
---

# Features

- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Cross-platform keyring integration
- Git-friendly JSON vault files
- dotenv and JSON import/export
- Multiple vault stores per project
- Flexible vault location configuration
- Designed for automation and developer workflows

---

# Example Vault File

Vault files are JSON documents containing encrypted values.

```json
{
  "meta": {
    "schema_version": 1,
    "crypto_version": 1,
    "salt": "0a24afe64ea0b73bee45f1ad31fcbd2e",
    "check": "enc:v1:DtZmJqBmJbL+uvvojo4DmCs5+qhQUb80LiwV9mVqqy2VFfh5"
  },
  "secrets": {
    "API_KEY": {
      "type": "password",
      "description": "API key for external service",
      "meta": {},
      "services": [],
      "value": "enc:v1:..."
    }
  }
}
```

The vault file can safely be stored in Git because **all secret values are encrypted**.

---


# Installation

Clone the repository:

```bash
git clone https://github.com/<your-user>/xvault.git
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the CLI:

```bash
python -m xvault
```

Or install as a command:

```bash
pip install .
```

---

# Quick Start

### Create a vault

```bash
xvault create dev
```

### List vaults

```bash
xvault list
```

Example output:

```
Stores
------

default   - 3 keys (unlocked)
dev       - 1 key (locked)
```

### Store a secret

```bash
xvault set dev API_KEY
```

### Retrieve a secret

```bash
xvault get dev API_KEY
```

### Remove a secret

```bash
xvault remove dev API_KEY
```

---

# Import Secrets

xvault can import from common formats.

### Import `.env`

```bash
xvault import dev .env
```

Example `.env`:

```
DATABASE_URL=postgres://localhost/db
API_KEY=abcdef123
```

### Import JSON

```bash
xvault import dev config.json
```

Example:

```json
{
  "API_KEY": "123456",
  "SERVICE_TOKEN": "abcdef"
}
```

---

# Export Secrets

Export vault contents:

```bash
xvault export dev
```

Formats supported:

```
--format env
--format json
--format xvault
```

---

# Vault Unlocking

xvault can cache vault keys securely using the system keyring.

Unlock a store:

```bash
xvault unlock dev
```

Lock it again:

```bash
xvault lock dev
```

Supported keyring backends:

- Windows DPAPI
- macOS Keychain
- Linux Secret Service

---

# Project Configuration

Vault location can be configured per Git repository.

Create a `.xvault` file in the project root:

```
file = ../dev/secrets/{project}-{name}.json
```

Variables:

| Variable | Meaning |
|---------|---------|
| `{project}` | Git repository name |
| `{name}` | vault store name |

Example resulting file:

```
../dev/secrets/myproject-dev.json
```

This allows multiple repositories to share a centralized secrets directory.

---

# Security Design

XVault uses modern cryptographic primitives.

| Component | Algorithm |
|----------|-----------|
| Key derivation | Argon2id |
| Encryption | AES-256-GCM |
| Nonce size | 96 bits |
| Key size | 256 bits |

Recommended KDF parameters:

```
time_cost = 5
memory_cost = 128 MB
parallelism = 4
```

These settings significantly increase resistance to brute-force attacks.

---

# Architecture Overview

```
+----------------------+
|      CLI (xvault)    |
+----------+-----------+
           |
           v
+----------------------+
|   Vault JSON Store   |
| encrypted values     |
+----------+-----------+
           |
           v
+----------------------+
|  Crypto Layer        |
| Argon2id + AES-GCM   |
+----------+-----------+
           |
           v
+----------------------+
| OS Keyring           |
| DPAPI / Keychain     |
+----------------------+
```

---

# Use Cases

XVault is useful for:

- managing `.env` secrets
- storing API credentials
- secure developer configuration
- Git-friendly encrypted storage
- automation scripts and CI setups
- personal encrypted document vaults

---

# Roadmap

Planned improvements:

- web UI vault editor
- virtual filesystem support
- VSCode extension
- vault synchronization
- secret rotation support
- encrypted document vault mode

---

# Related Projects

This tool is part of a broader ecosystem of developer tools:

| Project | Description |
|--------|-------------|
| **xtrader** | algorithmic trading engine |
| **xshell** | modular web runtime |
| **xvault** | encrypted developer vault |

---

# License

MIT License

---

# Author

Marc Delos  
Software engineer focused on distributed systems, algorithmic trading platforms, and developer tooling.
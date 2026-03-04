# XVault

![Python](https://img.shields.io/badge/python-3.10+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green)
![Security](https://img.shields.io/badge/encryption-AES--256--GCM-purple)
![KDF](https://img.shields.io/badge/KDF-Argon2id-orange)
![PyPI](https://img.shields.io/pypi/v/xvault)

**XVault** is a portable encrypted vault designed for **developers** to securely store secrets, tokens, and sensitive files while keeping encrypted vaults safe to store in Git repositories.

XVault is built around a simple idea:

> **Keep encrypted secrets versioned in Git while protecting the keys locally.**

XVault supports modern cryptography, OS keyring integration, and flexible project configuration to make secret management safe and developer-friendly.

## Single Source of Truth

XVault is designed to act as a **single source of truth** for all sensitive configuration a project needs (secrets, tokens, passwords, certificates, and file blobs). From this encrypted vault, you can **derive** or **export** the exact formats required by your tooling (e.g., `.env`, JSON config, certificate files) without duplicating sensitive values across multiple files or repos.

---

## Contents
- [Motivation](#motivation)
- [Features](#features)
- [Security Model](#security-model)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Import Secrets](#import-secrets)
- [Export Secrets](#export-secrets)
- [Project Configuration](#project-configuration)
- [Architecture Overview](#architecture-overview)
- [Roadmap](#roadmap)
- [License](#license)

---

## Motivation

Many developers store secrets in `.env` files or private folders.
These files are frequently committed accidentally to Git repositories.

Tools such as **Hashicorp Vault** or **Mozilla SOPS** solve this problem
for infrastructure environments, but they often require external
key management systems.

XVault was created to provide a **lightweight developer-focused vault**
that works locally, integrates with Git workflows, and requires no
external infrastructure.

Developers often need to store:

- API tokens
- credentials
- environment variables
- configuration files
- private keys
- sensitive documents

XVault focuses on a **different niche** than most secret-management tools:

- **Local-first** — works without external infrastructure
- **Git-friendly** — encrypted files are safe to version in repositories
- **Developer-oriented** — designed for development workflows
- **Portable** — no dependency on cloud KMS providers


### Comparison with SOPS

**XVault** and [SOPS (Secrets OPerationS)](https://github.com/mozilla/sops) share a similar goal: storing encrypted secrets safely inside version-controlled files. Both tools allow developers to keep encrypted configuration in Git while protecting the decryption keys locally. However, their design philosophies differ. SOPS focuses on infrastructure and DevOps workflows (Kubernetes, Terraform, cloud KMS integration), whereas **XVault** is designed primarily as a **developer-centric vault**, emphasizing simplicity, local password-based encryption, and flexible secret storage for development environments and personal projects.

| Feature | XVault | SOPS |
|-------|-------|------|
| Primary goal | Developer secret vault | Infrastructure secret management |
| Encryption model | Password-derived key (Argon2id) | External key management (KMS, GPG, Age) |
| Encryption algorithm | AES-256-GCM | AES-256-GCM |
| Key derivation | Argon2id | Not applicable (external keys) |
| Key storage | OS keyring (optional cache) | External key providers |
| File format | XVault file | YAML / JSON / ENV |
| Git-friendly storage | Yes | Yes |
| CLI workflow | Developer-oriented | DevOps / infrastructure-oriented |
| External dependencies | None required | Often requires KMS / GPG / Age |
| Secret import/export | dotenv, JSON | YAML/JSON editing |
| Typical use case | Developer secrets, local environments, personal vaults | Kubernetes, CI/CD, infrastructure configuration |

### Example workflow

```
D:\Reps\myrepos> xvault create dev
Enter password: ********
Confirm password: ********
Store created: dev
Path: D:\Reps\myrepos\.secrets\xvault-dev.xvault
Status: unlocked

D:\Reps\myrepos> xvault set dev API_KEY
Enter secret value:   ********
Confirm secret value: ********
API_KEY created

D:\Reps\myrepos> xvault get dev API_KEY
12345678

D:\Reps\myrepos> xvault export dev --format env
API_KEY=12345678

```

### Design Philosophy

- **SOPS** integrates deeply with cloud infrastructure and centralized key management systems.
- **XVault** prioritizes simplicity and portability by using password-derived encryption and local key caching.

This makes XVault particularly well-suited for:

- developer environments
- local secret management
- personal encrypted vaults
- Git-friendly secret storage without external infrastructure
---

## Features

- AES-256-GCM authenticated encryption
- Argon2id password-based key derivation
- Cross-platform keyring integration
- Git-friendly JSON vault files
- dotenv and JSON import/export
- Multiple vault stores per project
- Flexible vault location configuration
- Designed for automation and developer workflows

---


## Security Model

XVault is designed to protect secrets stored in version-controlled repositories.

### Threats mitigated

- accidental disclosure of secrets committed to Git
- unauthorized access to vault files without the password
- offline brute-force attacks through strong password-based key derivation

### Cryptographic design

| Component | Algorithm |
|----------|-----------|
| Key derivation | Argon2id |
| Encryption | AES-256-GCM |
| Nonce | 96-bit random nonce |
| Authentication | GCM tag |

Argon2id parameters:

time_cost = 5  
memory_cost = 128 MB  
parallelism = 4  

These parameters significantly increase the cost of offline password brute-force attacks.

### Limitations

XVault does **not** protect against:

- compromised host machines
- malicious code execution
- memory extraction attacks
- weak user passwords

---

## Example Vault File

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


## Installation

Install from PyPI:

```bash
pip install xvault
```

### Install from source (development)

Clone the repository:

```bash
# clone the repository:
git clone https://github.com/<your-user>/xvault.git
# install dependencies:
pip install -r requirements.txt
# run the CLI:
python -m xvault
# or install as a command:
pip install .
```

---

## Quick Start

### Create a vault

```bash
xvault create dev
```

After creating a new vault, it is unlocked (key cached in the OS keyring)

### List vaults

```bash
xvault list
```

Example output:

```
default   3 keys  unlocked
dev       1 key   locked
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

## Import Secrets

XVault can import from common formats.

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
xvault import dev config.xvault
```

Example:

```json
{
  "API_KEY": "123456",
  "SERVICE_TOKEN": "abcdef"
}
```

---

## Export Secrets 

### Derive Project Secrets from the Vault

A common problem in real projects is secret sprawl: the same values end up duplicated across `.env`, CI variables, deployment scripts, and certificate files.

XVault avoids this by storing everything in one place and generating the rest on demand:

- Store secrets once in XVault
- Export to the format your project needs (`.env`, JSON, etc.)
- (Optional) export file entries (certs/keys) back to real files when needed

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

## Vault Unlocking

XVault can cache vault keys securely using the system keyring.

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

## Project Configuration

Vault location can be configured per Git repository.

Create a `.xvault` file in the project root:

```
file = ../dev/secrets/{project}-{name}.xvault
```

Variables:

| Variable | Meaning |
|---------|---------|
| `{project}` | Git repository name |
| `{name}` | vault store name |

Example resulting file:

```
../dev/secrets/myproject-dev.xvault
```

This allows multiple repositories to share a centralized secrets directory.

---

## Architecture Overview

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

## Roadmap

Planned improvements:

- VSCode extension (to manage xvault contents)
- rekey password

---

## License

MIT License

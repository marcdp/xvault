# Using xvault

## Installation

Install the published package from PyPI:

```bash
pip install xvault
xvault version
```

For development, clone the repository and install it in editable mode:

```bash
pip install -e .
python -m xvault version
```

xvault requires Python 3.10 or later. Its runtime dependencies are installed with the package.

## Quick start

Start with an ordinary file and mark values that should become secrets:

```env
API_HOST=localhost
API_TOKEN=enc:replace-me
API_URL=https://${var:API_HOST}/v1
```

Run `xvault edit app.env`, enter a password when prompted, and save. The editor shows marked values as plaintext with their `enc:` marker; the saved file contains ciphertext and `_xvault` metadata. Retrieve or materialize values when needed:

```bash
xvault get app.env API_TOKEN
xvault export app.env --resolve
```

Exports go to standard output. Redirecting them creates plaintext files, so keep those files out of version control and remove them when no longer needed.

## CLI commands

Commands prompt for a password when the file is locked or uninitialized. The `--no-cache-key` (`-n`) option on the commands below prevents reading or writing the OS-keyring cache for that invocation.

### `edit`

```text
xvault edit PATH [KEY] [--no-cache-key]
```

Edits the decrypted document in xvault's terminal editor, then encrypts marked values when the edit is saved. With `KEY`, it invokes the implementation's single-secret edit path.

```bash
xvault edit dev.yaml
xvault edit dev.env DB_PASS
```

### `get`

```text
xvault get PATH KEY [--resolve] [--no-cache-key]
```

Prints a decrypted value. JSON and YAML keys can use dot-separated paths; ENV uses a variable name. `--resolve` (`-r`) resolves `${var:NAME}` first.

```bash
xvault get settings.json db.password
xvault get dev.env DATABASE_URL --resolve
```

### `set`

```text
xvault set PATH KEY VALUE [--no-encrypt] [--no-cache-key]
```

Sets a value in JSON, YAML, ENV, or OpenVPN files. By default it writes an `enc:` marker; `--no-encrypt` (`-e`) writes a plain value. **Current behavior:** `set` writes the marker and saves metadata, but does not encrypt the newly written plaintext itself. Run `edit` and save before committing a value written with the default option.

```bash
xvault set dev.env DB_PASS 'new-password'
xvault edit dev.env
```

JSONC and Markdown do not implement `set`.

### `export`

```text
xvault export PATH [--resolve] [--no-cache-key]
```

Writes the whole decrypted document to standard output. `--resolve` (`-r`) also substitutes supported variable references.

```bash
xvault export dev.env --resolve > runtime.env
```

### `info`

```text
xvault info PATH
```

Displays the path, extension, lock status, schema and crypto versions, and a count of `enc:` occurrences.

```bash
xvault info dev.env
```

### `validate`

```text
xvault validate PATH [--verbose] [--no-cache-key]
```

Loads the file and reports parser, metadata, lock-status, and decryption checks. `--verbose` (`-v`) is accepted by the CLI; the current command output does not vary by that flag.

```bash
xvault validate dev.env --no-cache-key
```

### `unlock` and `lock`

```text
xvault unlock PATH
xvault lock PATH
```

`unlock` validates the password and stores the derived key in the configured OS keyring. `lock` removes that cached key. Neither command encrypts or decrypts the file itself.

```bash
xvault unlock dev.env
xvault lock dev.env
```

### `rekey`

```text
xvault rekey PATH [--no-cache-key]
```

Prompts for a new password (with confirmation), decrypts the marked values, and saves them under a newly derived key and salt.

```bash
xvault rekey dev.env
```

### `version`

```text
xvault version
```

Prints the installed package version.

## Working with files

JSON and JSONC support reading and editing; JSON uses dot-separated object paths for `get` and `set`, while JSONC supports `get` but not `set`. YAML has the same dot-path convention. ENV uses `NAME=value` entries. Markdown is for editing encrypted inline text and fenced configuration; it does not support key lookup or `set`. OpenVPN supports normal directives and `<name>...</name>` blocks for `get` and `set`.

The exact metadata location, marker matching rules, and syntax limitations are specified in [reference.md](reference.md). xvault's constructor recognizes `.xml`, but there is no implemented XML handler; do not use XML as a vault format.

## Personal Markdown vaults

Markdown files can combine ordinary notes with marked values. xvault keeps metadata in YAML-style front matter and processes markers in the remaining text, including fenced blocks.

````markdown
## Production VPN

```env
VPN_USER=enc:alice
VPN_PASSWORD=${enc:replace-me}
```
````

For binary material such as a PEM, PFX, or image, encode it as base64 before placing it in a supported textual value. Keep the base64 data on one line if the selected format's marker rules require it; secret markers do not span lines.

## Exporting and resolving values

`get` and `export` decrypt `enc:` values. They only resolve `${var:NAME}` when `--resolve` is supplied. References look up values in the same decrypted file; they do not read process environment variables or other files. A missing name is an error, and resolution is not recursive. There is no escape syntax for a literal supported `${var:NAME}` sequence.

Use `export` only for the short period a consuming tool needs plaintext. It does not automatically redact output, choose a safe destination, or delete a redirected file.

## Key caching

After `unlock`, xvault stores the derived key—not the password—in the OS keyring under a file-specific entry. A later command can use it without a password prompt. `lock` removes that entry, and `--no-cache-key` disables both cache reads and writes for one invocation.

Some keyring backends are unavailable or unsuitable in SSH, CI, container, WSL, or headless sessions. In those environments, expect password prompts or use `--no-cache-key`; do not assume a cache exists.

## Common workflows

For Git-managed application configuration, edit the canonical file with `xvault edit`, review that values on disk are ciphertext, and run `validate` before committing. For password rotation, update the marked value with `edit` and save, or use `set` followed by `edit` and save. Use `rekey` when rotating the vault password.

For an OpenVPN profile, store credentials in an `<auth-user-pass>` block or other supported directive, edit it with xvault, and export a decrypted profile only to the process that needs it. The encrypted source can remain in Git; the exported profile must not.

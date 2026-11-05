#!/usr/bin/env python3
"""Compare real CryptoV1 and CryptoV2 password rotation in xvault.

Run from an editable-install checkout:
    python benchmarks/rekey_benchmark.py --repeats 3

Only synthetic credentials are used. Vaults live in a temporary directory.
No cryptographic parameters are patched or reduced.
"""

import argparse
import csv
import difflib
import platform
import random
import re
import statistics
import tempfile
import time
from importlib.metadata import version
from pathlib import Path

from xvault.crypto.v1 import CryptoV1
from xvault.crypto.v2 import CryptoV2
from xvault.handlers.env import HandlerEnv
from xvault.meta import META_CHECK_VALUE, XVaultMeta
from xvault.xvault import XVault

OLD_PASSWORD = "synthetic-benchmark-old-password"
NEW_PASSWORD = "synthetic-benchmark-new-password"
TOKEN_PATTERN = re.compile(r"^(SECRET_\d+)=enc:([^\r\n]+)\r?$", re.MULTILINE)


def plain_secret(index: int) -> str:
    return f"synthetic-secret-{index:06d}-" + ("x" * 32)


def create_vault(path: Path, crypto_version: int, count: int) -> None:
    """Seed an authentic on-disk vault. Setup is outside the timed region."""
    if crypto_version == 1:
        meta = XVaultMeta(schema_version=1, crypto_version=1, salt=None)
        crypto = CryptoV1(meta, password=OLD_PASSWORD)
    else:
        meta = XVaultMeta.new(schema_version=1)
        crypto = CryptoV2(meta, password=OLD_PASSWORD)

    body = "".join(
        f"SECRET_{i:06d}=enc:{crypto.encrypt(plain_secret(i))}\n"
        for i in range(count)
    )
    if crypto_version == 1:
        meta.check = crypto.encrypt(META_CHECK_VALUE)
    else:
        assert meta.salt and meta.encrypted_key
        meta.metadata_present = True

    # Write exactly the bytes that xvault persists (LF newlines). On Windows,
    # Path.write_text() uses newline translation, introducing CRLF and making
    # the before/after diff report unrelated line-ending churn.
    path.write_bytes(HandlerEnv().stringify(meta, body).encode("utf-8"))


def tokens(text: str) -> dict[str, str]:
    return dict(TOKEN_PATTERN.findall(text))


def benchmark_case(directory: Path, crypto_version: int, count: int, run: int) -> dict:
    path = directory / f"vault-v{crypto_version}-{count}-{run}.env"
    create_vault(path, crypto_version, count)
    before = path.read_bytes()
    before_text = before.decode("utf-8")
    old_tokens = tokens(before_text)
    assert len(old_tokens) == count

    # Constructor and initial file parsing are excluded. Key derivation that
    # happens inside rekey() is included. No OS keyring is accessed.
    vault = XVault(str(path), password=OLD_PASSWORD, no_cache_key=True)
    start = time.perf_counter_ns()
    vault.rekey(NEW_PASSWORD)
    elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000

    after = path.read_bytes()
    after_text = after.decode("utf-8")
    new_tokens = tokens(after_text)
    assert set(old_tokens) == set(new_tokens)
    changed = sum(old_tokens[name] != new_tokens[name] for name in old_tokens)
    assert changed == (count if crypto_version == 1 else 0), (
        f"Unexpected ciphertext churn: v{crypto_version}, {count} secrets, {changed} changed"
    )

    # Verification deliberately excluded from elapsed_ms.
    reopened = XVault(str(path), password=NEW_PASSWORD, no_cache_key=True)
    assert reopened.get("SECRET_000000") == plain_secret(0)
    assert reopened.get(f"SECRET_{count - 1:06d}") == plain_secret(count - 1)

    diff = "".join(
        difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile="before.env", tofile="after.env",
        )
    ).encode("utf-8")

    return {
        "crypto_version": crypto_version,
        "secret_count": count,
        "run": run,
        "rekey_ms": round(elapsed_ms, 3),
        "ciphertexts_changed": changed,
        "ciphertexts_total": count,
        "unified_diff_bytes": len(diff),
        "file_bytes_before": len(before),
        "file_bytes_after": len(after),
        "python_version": platform.python_version(),
        "platform": platform.platform(),
        "xvault_version": version("xvault"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", nargs="+", type=int, default=[10, 100, 1000])
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--output", type=Path, default=Path("benchmarks/results/rekey.csv"))
    args = parser.parse_args()
    if not args.sizes or any(n < 1 for n in args.sizes) or args.repeats < 1:
        parser.error("Sizes and repeats must be positive integers")

    cases = [(v, n, r) for n in args.sizes for v in (1, 2)
             for r in range(1, args.repeats + 1)]
    random.Random(2026).shuffle(cases)
    with tempfile.TemporaryDirectory(prefix="xvault-rekey-bench-") as tmp:
        rows = [benchmark_case(Path(tmp), v, n, r) for v, n, r in cases]

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(sorted(rows, key=lambda row: (
            row["secret_count"], row["crypto_version"], row["run"]
        )))

    print("Secrets  Version  Median rekey (ms)  Ciphertexts changed  Median diff (bytes)")
    for n in args.sizes:
        for v in (1, 2):
            sample = [row for row in rows if row["secret_count"] == n
                      and row["crypto_version"] == v]
            t = statistics.median(row["rekey_ms"] for row in sample)
            d = statistics.median(row["unified_diff_bytes"] for row in sample)
            print(f"{n:7}  v{v:<7}  {t:17.2f}  "
                  f"{sample[0]['ciphertexts_changed']:19}  {d:19.0f}")
    print(f"\nRaw measurements: {args.output}")
    print("Diff bytes use Python unified diffs as a Git-review proxy, not actual git diff output.")


if __name__ == "__main__":
    main()

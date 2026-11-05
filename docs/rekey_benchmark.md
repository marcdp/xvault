# CryptoV1 vs. CryptoV2: password rotation benchmark

> **Scope:** Reproducible, synthetic measurements of xvault's existing password-rotation implementations. This experiment evaluates execution time and the amount of encrypted-file content rewritten; it is **not** a cryptographic security benchmark or an independent security audit.

## Question

What changes operationally when xvault moves from direct password-derived encryption (CryptoV1) to envelope encryption (CryptoV2)? In particular, how does the number of secrets affect password-rotation time and Git-review churn?

## Architectural hypothesis

- **CryptoV1** derives a new value-encryption key from the replacement password and re-encrypts every marked value. Each encrypted token is therefore expected to change.
- **CryptoV2** derives a new key-encryption key (KEK) and rewraps the existing data-encryption key (DEK). Secret ciphertexts should remain byte-for-byte identical, even as the number of secrets increases.
- Both schemes use the production Argon2id settings. For small and medium vaults, password derivation may dominate runtime, so dramatic speed gains are **not** assumed.

See the [format contract](reference.md#interoperability-contract) and [engineering case study](engineering-case-study.md) for design context.

## Methodology

The benchmark script is [`benchmarks/rekey_benchmark.py`](../benchmarks/rekey_benchmark.py). It:

1. Creates independent synthetic `.env` vaults containing 10, 100, or 1,000 uniquely named values using the actual `CryptoV1`/`CryptoV2` implementations and ENV serializer.
2. Opens each initialized vault with its original password and `no_cache_key=True`, excluding keyring behavior.
3. Times **only `XVault.rekey(new_password)`** using `time.perf_counter_ns()`. Vault creation, opening, and post-rekey verification are excluded from the timed region; any key derivation performed *within* `rekey()` is included.
4. Compares encrypted token values before and after rotation, asserts the expected change counts, and checks that the first and last values remain decryptable with the new password.
5. Computes byte counts of UTF-8 encoded **Python unified diffs** (`difflib.unified_diff`) between the before/after documents. This represents text-diff churn; it is **not** the output size of `git diff`.
6. Executes five runs per combination, in a deterministic shuffled order, and reports median times and median diff sizes.

The benchmark uses real Argon2id settings and synthetic credentials only. Fixtures use LF line endings on every platform so Windows newline conversion cannot inflate the diff.

### Environment

- **Execution environment:** Windows PowerShell (`D:\\Reps\\xvault`).
- **Command:** `python benchmarks/rekey_benchmark.py --repeats 5`
- **Vault sizes:** 10, 100, and 1,000 secrets.
- **Repetitions:** 5 per version and size.
- **Python version, CPU, OS build, xvault commit:** *Record from the machine used for the benchmark before publishing comparative performance claims.* The CSV records the Python, platform, and installed package versions for each run.

## Results

These are the observed values from the local run, not theoretical estimates.

| Secrets | Version | Median rekey (ms) | Ciphertexts changed | Median unified diff (bytes) |
| ---: | :---: | ---: | ---: | ---: |
| 10 | v1 | 216.22 | 10 / 10 | 3,161 |
| 10 | v2 | 214.48 | 0 / 10 | 895 |
| 100 | v1 | 225.73 | 100 / 100 | 26,923 |
| 100 | v2 | 206.14 | 0 / 100 | 895 |
| 1,000 | v1 | 211.70 | 1,000 / 1,000 | 264,525 |
| 1,000 | v2 | 210.07 | 0 / 1,000 | 895 |

### Change-surface comparison

| Secrets | Reduction in unified-diff bytes with v2 |
| ---: | ---: |
| 10 | 71.69% |
| 100 | 96.68% |
| 1,000 | 99.66% |

At **1,000 secrets**, CryptoV1 changed every ciphertext and produced a 264,525-byte unified diff; CryptoV2 changed **zero** ciphertexts and produced an 895-byte unified diff. The v2 diff is not zero because the vault metadata, including the salt and wrapped DEK, changes on rekey.

### Time comparison

Median rekey times were near 210–225 ms across the tested cases. CryptoV2 was nominally faster in each group, but the differences were small or inconsistent (about **1.74 ms**, **19.59 ms**, and **1.63 ms** at 10, 100, and 1,000 secrets, respectively). With only five observations per configuration and no published variance analysis, these results **do not establish a reliable performance advantage** for CryptoV2.

The close timings are compatible with the hypothesis that Argon2id derivation dominates this workload; profiling would be needed to quantify the contribution of derivation, encryption, serialization, and file I/O separately.

## Interpretation

The measured benefit of envelope encryption here is **bounded change scope** rather than proven execution-time improvement:

- **CryptoV1:** Password rotation changes every encrypted secret and the document diff grows with the number of secrets.
- **CryptoV2:** Password rotation changes the wrapped DEK and associated metadata, but does not rewrite secret ciphertext. Diff size remained constant across the tested sizes.

For configuration committed to Git, this creates a concrete operational benefit: password rotation need not introduce changes to all encrypted fields. That makes the change easier to inspect and avoids needless ciphertext churn.

This decision has a security trade-off: **rewrapping the same DEK is not DEK rotation**. Changing the current password does not revoke access to historical Git revisions, nor does it recover from a compromised DEK.

## Limitations and next steps

- Synthetic `.env` vaults with distinct plaintext values may not represent other file formats, secret distributions, or real application workloads.
- Five samples per case and median-only reporting are insufficient for a statistically robust claim about speed. For performance analysis, publish individual runs from `benchmarks/results/rekey.csv`, add variance, and repeat on a documented machine.
- `difflib.unified_diff` measures generated text diff bytes, not the exact size of a Git patch and not repository storage consumption.
- Post-rotation verification reopens the file and checks selected values; it does not independently verify every decrypted value, although ciphertext change counts are checked across every token.
- The experiment checks password rotation, not security under active compromise or multi-user key distribution.
- These measurements do not establish external adoption or organizational impact; xvault is presently a personally used tool.

## Reproduce

From a local repository checkout with xvault installed in editable mode:

```bash
python -m pip install -e .
python benchmarks/rekey_benchmark.py --repeats 5
```

The script writes full per-run data to `benchmarks/results/rekey.csv`. Preserve the script, raw CSV, exact commit identifier, and machine details with any published performance comparison.

---

[Back to engineering case study](engineering-case-study.md) · [Back to xvault](../README.md)

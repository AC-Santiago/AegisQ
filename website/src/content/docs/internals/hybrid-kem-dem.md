---
title: Hybrid KEM-DEM
description: How AegisQ combines ML-KEM key encapsulation with AES-256-GCM data encryption.
---

AegisQ implements a **Hybrid KEM-DEM** architecture. ML-KEM cannot encrypt large payloads directly — it only produces a 32-byte shared secret. AegisQ pairs it with AES-256-GCM as the Data Encapsulation Mechanism (DEM).

## The Hybrid Approach

1. **ML-KEM (KEM):** Generates a 32-byte shared secret, quantum-safe
2. **AES-256-GCM (DEM):** Uses that 32-byte secret as the symmetric key to encrypt the actual payload with authenticated encryption (confidentiality + integrity)

## AES-256-GCM Properties

| Property | Value |
|----------|-------|
| Key size | 256 bits (32 bytes) — from ML-KEM shared secret |
| Nonce (IV) | 96 bits (12 bytes) — random per operation via `OsRng` |
| Authentication Tag | 128 bits (16 bytes) |
| Security | IND-CPA + INT-CTXT (authenticated encryption) |

Once ML-KEM generates the 32-byte shared secret `K`, AegisQ feeds it directly into AES-256-GCM as the symmetric encryption key. No additional KDF is needed — the 32-byte output of ML-KEM is already uniformly random and the correct size for AES-256.

## Nonce Management — Critical Rule

:::caution[Nonce Uniqueness]
A nonce must **NEVER** be reused with the same key. One-shot `encrypt()` samples a fresh cryptographically random 96-bit nonce using the local `OsRng` wrapper backed by `getrandom::fill`. RNG failure is propagated. Random sampling reduces collision risk but does not guarantee uniqueness.

For `n` independent random nonces **under one key**, the birthday approximation is `n(n−1) / 2^97`; at `n = 2^32`, this is approximately `1.16 × 10⁻¹⁰`. One-shot encryption performs a fresh ML-KEM encapsulation per call; this same-key calculation is not a claim that those calls reuse an AES key. Streaming uses a different indexed nonce scheme; see [Streaming Encryption](/api-reference/streaming/).
:::

## Transit Package Assembly

The `hybrid.rs` module in `aegisq-core` is responsible for assembling and parsing the transit package.

### Transit Package Structure

The final `encrypted_package` byte array has this fixed structure:

```text
[ ML-KEM Capsule (var) | AES Nonce (12 bytes) | AES Auth Tag (16 bytes) | Ciphertext (var) ]
```

Where `ML-KEM Capsule` size depends on the security level:
- ML-KEM-512: 768 bytes
- ML-KEM-768: 1088 bytes
- ML-KEM-1024: 1568 bytes

### Encrypt Flow

1. Call `kem::encapsulate(public_key, level)` → result containing capsule and shared secret
2. Generate random 12-byte nonce via `OsRng`
3. Call `aes_gcm::encrypt(key=shared_secret, nonce, plaintext)` → `(tag, ciphertext)`
4. **Zeroize `shared_secret` immediately**
5. Assemble and return: `capsule || nonce || tag || ciphertext`

### Decrypt Flow

1. Split the transit package by known offsets (capsule_size, then 12, 16, rest)
2. Call `kem::decapsulate(capsule, secret_key, level)` → `shared_secret_32B`
3. Call `aes_gcm::decrypt(key=shared_secret, nonce, tag, ciphertext)` → `plaintext` or `Err`
4. **Zeroize `shared_secret` immediately**
5. If tag verification fails → return `Err(AegisQError::DecryptionFailed)`

## Error Behavior Contrast

| Scenario | ML-KEM Decaps | AES-GCM Decrypt |
|----------|---------------|-----------------|
| Invalid contents, correct capsule size | Returns pseudorandom K | Tag verification is expected to fail |
| Wrong key/capsule size or too-short package | Structural error (`InvalidParameterError`) | Not reached |
| Correct capsule, wrong AES key | N/A (key derived from capsule) | Error: `DecryptionError` |
| Auth tag mismatch (tampered payload) | N/A | Error: `DecryptionError` |
| Correct everything | Returns shared secret | Returns plaintext |

:::note
Unlike ML-KEM's silent rejection, a failed AES-GCM auth tag **always** raises `DecryptionError`. This is the correct behavior — it tells the caller that the payload was tampered with or the wrong key was used, without revealing anything about the ML-KEM decapsulation step.
:::

## Rust Internal API

```rust
use aegisq_core::{hybrid, kem::SecurityLevel};

// Hybrid encrypt: ML-KEM encaps + AES-256-GCM
let encrypted_package: Vec<u8> = hybrid::encrypt(
    recipient_public_key,
    plaintext,
    SecurityLevel::MlKem768,
)?;

// Hybrid decrypt: ML-KEM decaps + AES-256-GCM verify + decrypt
let plaintext: Vec<u8> = hybrid::decrypt(
    &encrypted_package,
    secret_key,
    SecurityLevel::MlKem768,
)?;
```

:::note[OsRng]
`OsRng` is a local wrapper around `getrandom::fill`, not `rand_core::OsRng`. The caller does not pass an RNG. The `getrandom` crate selects the platform backend; failures become `AegisQError::RngError`. Cleanup after AES-GCM does not imply complete erasure of all buffers or early-error paths; see [Security Model](/internals/security-model/).
:::

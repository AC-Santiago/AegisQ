---
title: Security Model
description: AegisQ security mechanisms, assumptions, and known limitations.
---

## Security Mechanisms

AegisQ implements ML-KEM and AES-256-GCM. Their security depends on cryptographic assumptions, correct implementation, key management, and the execution environment. This page is not a certification or a proof of implementation security.

| Property | Implemented mechanism | Limit |
|----------|-----------------------|-------|
| Key encapsulation | ML-KEM with implicit rejection | No universal attack-probability bound is asserted |
| Payload confidentiality and integrity | AES-256-GCM with a 128-bit tag | Does not authenticate the sender's identity |
| Timing defenses | Constant-time capsule comparison and key selection; Barrett reduction | Not an end-to-end side-channel audit |
| Memory cleanup | Explicit shared-secret cleanup after one-shot AES operations; `Zeroizing` in selected Rust paths | Not all copies or error paths are covered |
| Integer overflow | `overflow-checks = true` in release builds | Intentional wrapping operations remain explicit exceptions |
| One-shot nonces | Fresh random 96-bit nonce from the OS per encryption | Random sampling is not a guarantee of uniqueness |

## IND-CCA2 Security

ML-KEM is designed for **IND-CCA2** security (Indistinguishability under Adaptive Chosen Ciphertext Attack). For invalid capsule contents of the correct size, decapsulation returns `J(z || c)`, a pseudorandom 32-byte key, rather than a validity error. Here `J` is SHAKE256 with a 32-byte output. Incorrect key or capsule sizes are structural errors and raise `InvalidParameterError` in the current API.

## Timing Defenses

`mlkem/decaps.rs` uses `subtle::ConstantTimeEq` to compare capsules and `ConditionallySelectable` to select the output key without a validity-dependent branch. Field arithmetic uses Barrett reduction. These mechanisms do not establish timing immunity for the complete Rust core, FFI bridge, Python runtime, compiler, or hardware.

## Memory Zeroization

`hybrid.rs` explicitly zeroizes its shared-secret buffer after AES-GCM returns, including authentication failure. Some other Rust paths use `Zeroizing`. This is not complete secret-erasure coverage: for example, nonce-generation failure in one-shot encryption occurs before that explicit cleanup.

The Python-facing `KeyPair` stores its secret in a Rust `Vec<u8>` without destruction-time zeroization in the current bridge. Its `secret_key` getter creates an immutable Python `bytes` copy. Neither deleting that copy nor leaving `with AegisCipher()` guarantees its erasure. ML-KEM intermediate buffers and copies also require separate lifecycle review.

The cipher context manager only overwrites mutable buffers registered with its private hook. It does not erase caller-owned keys, plaintext, or a suspended streaming generator's Rust state. See [Context Manager](/api-reference/context-manager/).

## Integer Overflow Protection

The Cargo release profile sets `overflow-checks = true`, retaining overflow checks for ordinary integer operations in release builds. Explicit wrapping operations bypass those checks and must be reviewed separately; this setting alone does not prove arithmetic correctness.

## Known Limitations

:::caution[No Forward Secrecy by Default]
If a secret key is compromised, **all payloads encrypted to that key are compromised**. This is inherent to any static key exchange mechanism.

**Risk reduction:** Use independent keypairs per session or message and avoid retaining obsolete keys. `EphemeralSession.close()` marks the session closed and drops its keypair reference; it does not guarantee physical erasure. Forward secrecy additionally requires an appropriate authenticated protocol and secure disposal of past keys. The session helper alone does not provide that guarantee.
:::

Public keys must be obtained through a trusted or authenticated channel. Anyone with a public key can encrypt to its holder; successful AES-GCM verification is not proof of sender identity. AegisQ also does not provide replay protection, metadata privacy, or persistent-key storage policy.

### Error Behavior Contrast

Understanding how errors propagate through the hybrid KEM-DEM system is critical for security:

| Scenario | ML-KEM Decaps | AES-GCM Decrypt |
|----------|---------------|-----------------|
| Invalid capsule contents, correct size | Returns pseudorandom K | Tag verification is expected to fail |
| Incorrect key/capsule size or too-short package | Structural error (`InvalidParameterError`) | Not reached |
| Correct capsule, wrong AES key | N/A (key derived from capsule) | Error: `DecryptionError` |
| Auth tag mismatch (tampered payload) | N/A | Error: `DecryptionError` |
| Correct everything | Returns shared secret | Returns plaintext |

AES-GCM authentication failures surface as `DecryptionError`, without a separate capsule-validity signal. Structural errors remain distinct. These mechanisms do not replace protocol review or independent security auditing.

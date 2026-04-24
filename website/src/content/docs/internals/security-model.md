---
title: Security Model
description: AegisQ security guarantees, implementation mechanisms, and known limitations.
---

## Security Guarantees

| Property | Guarantee | Implementation Mechanism |
|----------|-----------|--------------------------|
| **IND-CCA2 Security** | Attack prob. ≤ 2⁻¹²⁸ | Implicit rejection in ML-KEM Decaps |
| **Data Confidentiality** | Quantum-safe payload secrecy | ML-KEM + AES-256-GCM |
| **Data Integrity & Auth** | Tamper-proof payload | AES-GCM 128-bit Authentication Tag |
| **Timing Attack Immunity** | No secret-dependent branches | `subtle::ConstantTimeEq`, Barrett reduction |
| **Memory Scrubbing** | Secret keys zeroed after use | `zeroize::Zeroize` on all sensitive structs |
| **Integer Overflow** | All arithmetic checked | `overflow-checks = true` in release profile |
| **Nonce Uniqueness** | No nonce reuse | Random 96-bit nonce via `OsRng` per call |

## IND-CCA2 Security

AegisQ achieves **IND-CCA2** (Indistinguishability under Adaptive Chosen Ciphertext Attack) security through ML-KEM's implicit rejection mechanism. When decapsulation encounters an invalid ciphertext, it returns a pseudorandom key derived from the secret key's rejection seed `z`, rather than signaling an error. This prevents attackers from using decapsulation as an oracle.

## Timing Attack Immunity

All secret-dependent comparisons use `subtle::ConstantTimeEq` from the `subtle` crate. Field arithmetic uses Barrett reduction instead of division, eliminating timing variations. There are **no branches that depend on secret values** anywhere in the cryptographic code.

## Memory Zeroization

All structures containing secret material implement `zeroize::Zeroize`:
- Secret keys are zeroed when dropped
- Shared secrets are zeroed immediately after use in AES-GCM
- Intermediate values in ML-KEM computations are zeroed after each operation

This prevents secret recovery from process memory after keys are no longer needed.

## Integer Overflow Protection

The Cargo release profile sets `overflow-checks = true`, ensuring all integer arithmetic is checked even in release builds. This prevents subtle bugs in field arithmetic (ℤq where q = 3329) from silently producing wrong results.

## Known Limitations

:::caution[No Forward Secrecy by Default]
If a secret key is compromised, **all payloads encrypted to that key are compromised**. This is inherent to any static key exchange mechanism.

**Mitigation:** Use **ephemeral keypairs** — generate a new keypair per session or per message, transmit the public key, then discard the secret key after decryption. This provides forward secrecy by ensuring that compromise of a future key does not affect past sessions.
:::

### Error Behavior Contrast

Understanding how errors propagate through the hybrid KEM-DEM system is critical for security:

| Scenario | ML-KEM Decaps | AES-GCM Decrypt |
|----------|---------------|-----------------|
| Invalid capsule (wrong bytes) | Silent: returns pseudorandom K | N/A |
| Correct capsule, wrong AES key | N/A (key derived from capsule) | Error: `DecryptionError` |
| Auth tag mismatch (tampered payload) | N/A | Error: `DecryptionError` |
| Correct everything | Returns shared secret | Returns plaintext |

The key insight: ML-KEM's silent rejection combined with AES-GCM's explicit error creates a system where **invalid capsules always surface as `DecryptionError`** (because the pseudorandom key will fail AES-GCM tag verification), but the error message reveals nothing about *why* decapsulation failed.

---
title: FIPS 203 Compliance
description: AegisQ implementation roadmap, standards compliance, and Rust dependency inventory.
---

## Implementation Roadmap

AegisQ was developed in 25 strict phases. Each phase had to pass all tests before advancing to the next.

| Phase | Component | Reference | Status |
|-------|-----------|-----------|--------|
| 1 | Field arithmetic (Zq) & Barrett reduction | FIPS 203 §4.2 | ✅ |
| 2 | NTT & inverse NTT | FIPS 203 §4.3 | ✅ |
| 3 | Polynomial operations | FIPS 203 §4.1 | ✅ |
| 4 | Compress / Decompress | FIPS 203 §4.2.1 | ✅ |
| 5 | Parameters module | FIPS 203 §5 | ✅ |
| 6 | CBD sampling & XOF | FIPS 203 §4.1, §4.2.2 | ✅ |
| 7 | KeyGen (Algorithm 15) | FIPS 203 Alg. 15 | ✅ |
| 8 | Encaps (Algorithm 16) | FIPS 203 Alg. 16 | ✅ |
| 9 | Decaps with implicit rejection | FIPS 203 Alg. 17 | ✅ |
| 10 | Public KEM API (`kem.rs`) | — | ✅ |
| 11 | AES-256-GCM Hybrid (`hybrid.rs`) | NIST SP 800-38D | ✅ |
| 12 | FFI error types | — | ✅ |
| 13 | PyO3 types (KeyPair, EncryptedPackage) | — | ✅ |
| 14 | PyO3 KEM bindings | — | ✅ |
| 15 | PyO3 Hybrid bindings | — | ✅ |
| 16 | PyO3 module registration | — | ✅ |
| 17 | Python exceptions | — | ✅ |
| 18 | Python type stubs | PEP 561 | ✅ |
| 19 | Python KEM API (`MlKem`) | — | ✅ |
| 20 | Python high-level API (`AegisCipher`) | — | ✅ |
| 21 | Python package exports | — | ✅ |
| 22 | KEM bridge tests | — | ✅ |
| 23 | Hybrid bridge tests | — | ✅ |
| 24 | AegisCipher end-to-end tests | — | ✅ |
| 25 | NIST KATs + ML-KEM integration tests | NIST vectors | ✅ |

## Standards Compliance

| Standard | Description |
|----------|-------------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM — Module-Lattice-Based Key-Encapsulation Mechanism (NIST, 2024) |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AES-GCM — Galois/Counter Mode specification |

## Rust Dependencies

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes-gcm` | 0.10 | AES-256-GCM authenticated encryption (no_std, hardware AES-NI) |
| `sha3` | 0.10 | SHAKE-128/256 and SHA3-256/512 for ML-KEM (no_std) |
| `zeroize` | 1.8 | Secure memory erasure of secrets |
| `subtle` | 2.6 | Constant-time comparisons |
| `rand_core` | 0.6 | OS-level CSPRNG via `OsRng` (no_std) |
| `pyo3` | 0.28 | Rust-Python FFI bindings (abi3-py311) |

All cryptographic crates are `no_std` compatible.

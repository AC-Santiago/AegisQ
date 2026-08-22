---
title: FIPS 203 Compliance
description: AegisQ implementation roadmap, standards compliance, and Rust dependency inventory through v1.5.0.
---

## Implementation Roadmap

AegisQ was developed in phases. Each phase had to pass all tests before advancing to the next. The current stable release is **v1.5.0**; `develop` is currently tracking **v1.6.0-rc1** (the next prerelease).

### v1.0–v1.2 — Core FIPS 203 ML-KEM + Hybrid KEM-DEM

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
| 13 | PyO3 types (KeyPair, SecurityLevel) | — | ✅ |
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
| 25 | KEM API tests + NIST KAT vectors | — | ✅ |
| 26 | GitHub Actions CI/CD | — | ✅ |
| 27 | NIST ACVP KAT vector JSON files | NIST vectors | ✅ |
| 27b | KAT vector verification tests | NIST vectors | ✅ |
| 28 | EphemeralSession (forward secrecy) | — | ✅ |
| 29 | Async support (`encrypt_async`, `decrypt_async`) | — | ✅ |

### v1.3.0 — KDF, Key Wrap, and Key Serialization

| Phase | Component | Reference | Status |
|-------|-----------|-----------|--------|
| 30 | HKDF-SHA3-256 + AES-256-GCM key wrap (`kdf.rs`, `key_wrap.rs`) | RFC 5869, NIST SP 800-38D | ✅ |
| 31 | Key serialization: PEM, JSON, encrypted PEM (`key_io_bindings.rs`, `aegisq/keys.py`) | RFC 7468 (adapted) | ✅ |

### v1.4.0 — Safe Repr, Context Manager, Implicit-Rejection Coverage

| Phase | Component | Reference | Status |
|-------|-----------|-----------|--------|
| 32 | `KeyPair.__repr__` fingerprint + `AegisCipher` context manager + 25-case `__repr__` regression suite + 25-case implicit-rejection regression suite (FIPS 203 §7.3) | FIPS 203 §7.3 | ✅ |

### v1.5.0 — Streaming + Benchmarks

| Phase | Component | Reference | Status |
|-------|-----------|-----------|--------|
| 33a | Streaming encrypt/decrypt (`stream.rs`, `stream_bindings.rs`, `encrypt_stream` / `decrypt_stream`) | NIST SP 800-38D §5.2 (frame-based AEAD) | ✅ |
| 33b | Criterion benchmarks for NTT and KEM (`benches/ntt.rs`, `benches/kem.rs`) | — | ✅ |

## Standards Compliance

| Standard | Description |
|----------|-------------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM — Module-Lattice-Based Key-Encapsulation Mechanism (NIST, 2024) |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AES-GCM — Galois/Counter Mode specification |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Base16, Base32, Base64 data encodings (used for PEM bodies and Base64 URL-safe keys) |
| [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) | Textual Encodings of PKIX, PKCS, and CMS Structures (PEM format adapted for ML-KEM) |
| [PEP 561](https://peps.python.org/pep-0561/) | Distributing and Packaging Type Information (AegisQ ships `py.typed` + `.pyi` stubs) |

## Rust Dependencies

Versions reflect the **v1.5.0** release. Workspace-wide declarations live in `Cargo.toml`.

| Crate | Version | Purpose | `no_std` |
|-------|---------|---------|----------|
| `aes-gcm` | 0.11 | AES-256-GCM authenticated encryption (hardware AES-NI) | ✅ |
| `sha3` | 0.12 | SHA3-256/512 and SHAKE-128/256 for ML-KEM | ✅ |
| `shake` | 0.1 | XOF variants moved out of `sha3` upstream (RustCrypto/XOFs split) | ✅ |
| `zeroize` | 1.9 | Secure memory erasure of secrets | ✅ |
| `subtle` | 2.6 | Constant-time comparisons | ✅ |
| `getrandom` | 0.4 | OS-level CSPRNG (`OsRng`) for nonces and keygen | ✅ |
| `base64` | 0.23 | PEM body encoding | ✅ |
| `thiserror` | 2.0 | Error type definitions | ✅ |
| `pyo3` | 0.29 | Rust-Python FFI bindings (`abi3-py311`) | — |
| `criterion` (dev) | 0.5 | Benchmarks for NTT and KEM operations | — |

All cryptographic crates are `no_std` compatible. `pyo3` and `criterion` are excluded — they are used only at the FFI and dev-dependency layers respectively.

## NIST ACVP Test Vectors

AegisQ verifies its ML-KEM implementation against the official NIST ACVP (Automated Cryptographic Validation Program) test vectors:

- **KeyGen** — `tests/python/json-files/ML-KEM-keyGen-FIPS203/`
- **Encap/Decap** — `tests/python/json-files/ML-KEM-encapDecap-FIPS203/`

The test runner `tests/python/test_kat_vectors.py` parses each JSON vector and asserts bit-exact equality between the implementation output and the expected bytes. This is the strongest possible correctness signal — running AegisQ against the same vectors NIST uses to certify reference implementations.

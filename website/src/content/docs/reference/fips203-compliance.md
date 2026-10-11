---
title: FIPS 203 Compliance
description: Standards references, implementation boundaries, dependency requirements, and test-vector scope.
---

## Implementation Scope

AegisQ implements ML-KEM for key encapsulation and AES-256-GCM for authenticated encryption. Published versions are listed on [PyPI](https://pypi.org/project/aegisq-pqc/); checkout versions live in the package manifests. Release history is maintained in the repository's [CHANGELOG.md](https://github.com/AC-Santiago/AegisQ/blob/main/CHANGELOG.md).

:::caution[Implementation is not certification]
FIPS 203 specifies ML-KEM. Implementing it and running known-answer tests does not constitute official ACVP validation, FIPS 140 module certification, or an independent audit of AegisQ. The streaming frame format and ML-KEM PEM-like envelopes are AegisQ formats, not standardized by the references below.
:::

- [Mathematical foundation](/internals/mathematical-foundation/) explains the ML-KEM primitives and parameters.
- [Hybrid KEM-DEM](/internals/hybrid-kem-dem/) describes the one-shot transit package.
- [Key serialization](/api-reference/key-serialization/) and [streaming](/api-reference/streaming/) describe AegisQ-specific formats and derivation.
- [Security model](/internals/security-model/) separates implemented defenses from guarantees the library does not provide.

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

Versions are current manifest requirements, not exact lockfile resolutions or an inventory of a published release. Workspace declarations live in `Cargo.toml`; PyO3 and Criterion are declared in the bridge/core manifests. `Cargo.lock` records resolved versions.

| Crate | Version | Purpose | `no_std` |
|-------|---------|---------|----------|
| `aes-gcm` | 0.11 | AES-256-GCM authenticated encryption (hardware AES-NI) | ✅ |
| `sha3` | 0.12 | SHA3-256/512 for ML-KEM | ✅ |
| `shake` | 0.1 | XOF variants moved out of `sha3` upstream (RustCrypto/XOFs split) | ✅ |
| `zeroize` | 1.9 | Cleanup of selected secret buffers | ✅ |
| `subtle` | 2.6 | Constant-time comparisons | ✅ |
| `getrandom` | 0.4 | OS-level randomness for nonces and keygen | ✅ |
| `base64` | 0.23 | PEM body encoding | ✅ |
| `thiserror` | 2.0 | Error type definitions | ✅ |
| `pyo3` | 0.29 | Rust-Python FFI bindings (`abi3-py311`) | — |
| `criterion` (dev) | 0.5 | Benchmarks for NTT and KEM operations | — |

All cryptographic crates are `no_std` compatible. `pyo3` and `criterion` are excluded — they are used only at the FFI and dev-dependency layers respectively.

## NIST ACVP Test Vectors

AegisQ verifies its ML-KEM implementation against the official NIST ACVP (Automated Cryptographic Validation Program) test vectors:

- **KeyGen** — `tests/python/json-files/ML-KEM-keyGen-FIPS203/`
- **Encap/Decap** — `tests/python/json-files/ML-KEM-encapDecap-FIPS203/`

`tests/python/test_kat_vectors.py` explicitly compares expected KeyGen and encapsulation outputs byte-for-byte. It does not invoke decapsulation or assert the expected decapsulation/rejection outputs from the combined corpus. Roundtrips are checked separately in `tests/python/test_kem_api.py`; `tests/python/test_implicit_rejection.py` covers invalid capsule contents. Those tests do not replace decapsulation known-answer tests.

Passing these tests is correctness evidence for the checked inputs, not a proof of security, exhaustive vector coverage, or official certification. A pass claim must refer to an actual run against the matching source and native extension.

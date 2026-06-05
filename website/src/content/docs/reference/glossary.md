---
title: Glossary
description: Glossary of cryptographic terms and references to standards used in AegisQ.
---

## Terms

| Term | Definition |
|------|------------|
| **KEM** | Key Encapsulation Mechanism — establishes a shared secret using asymmetric cryptography. ML-KEM is the quantum-safe KEM used here. |
| **DEM** | Data Encapsulation Mechanism — symmetric encryption for the actual payload. AES-256-GCM is the DEM used here. |
| **AEAD** | Authenticated Encryption with Associated Data — provides both confidentiality and integrity. AES-GCM is an AEAD scheme. |
| **M-LWE** | Module Learning With Errors — the hard lattice problem underlying ML-KEM's quantum resistance. |
| **NTT** | Number Theoretic Transform — FFT over finite fields for O(n log n) polynomial multiplication. |
| **CBD** | Centered Binomial Distribution — used to sample small error terms in ML-KEM key generation. |
| **Implicit Rejection** | ML-KEM Decaps returns a pseudorandom key (not an error) when the capsule is invalid. Prevents CCA oracle attacks. |
| **Transit Package** | The complete byte array sent over the network: `[Capsule \| Nonce \| Tag \| Ciphertext]`. |
| **Zeroization** | Securely overwriting sensitive memory (keys, secrets) with zeros before deallocation. |
| **Auth Tag** | AES-GCM's 16-byte cryptographic MAC. A tag mismatch means the ciphertext was tampered with. |

## References

### Standards & Libraries

| Document | URL |
|----------|-----|
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| NIST SP 800-38D (AES-GCM) | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| CRYSTALS-Kyber spec v3.02 | https://pq-crystals.org/kyber/ |
| aes-gcm Rust crate | https://docs.rs/aes-gcm |
| PyO3 User Guide | https://pyo3.rs/latest/ |
| Maturin Documentation | https://www.maturin.rs/ |

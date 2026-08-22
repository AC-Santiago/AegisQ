---
title: Glossary
description: Glossary of cryptographic and AegisQ-specific terms, plus references to the standards used.
---

## Cryptographic Terms

| Term | Definition |
|------|------------|
| **KEM** | Key Encapsulation Mechanism — establishes a shared secret using asymmetric cryptography. ML-KEM is the quantum-safe KEM used here. |
| **DEM** | Data Encapsulation Mechanism — symmetric encryption for the actual payload. AES-256-GCM is the DEM used here. |
| **AEAD** | Authenticated Encryption with Associated Data — provides both confidentiality and integrity. AES-GCM is an AEAD scheme. |
| **AAD** | Additional Authenticated Data — input to the AES-GCM tag computation that is **not** encrypted but **is** authenticated. In AegisQ streaming, AAD is the 4-byte big-endian chunk index. |
| **M-LWE** | Module Learning With Errors — the hard lattice problem underlying ML-KEM's quantum resistance. |
| **NTT** | Number Theoretic Transform — FFT over finite fields for O(n log n) polynomial multiplication. |
| **CBD** | Centered Binomial Distribution — used to sample small error terms in ML-KEM key generation. |
| **Implicit Rejection** | ML-KEM Decaps returns a pseudorandom key (not an error) when the capsule is invalid. Prevents CCA oracle attacks. |
| **Transit Package** | The complete byte array sent over the network: `[Capsule \| Nonce \| Tag \| Ciphertext]`. |
| **Zeroization** | Securely overwriting sensitive memory (keys, secrets) with zeros before deallocation. |
| **Auth Tag** | AES-GCM's 16-byte cryptographic MAC. A tag mismatch means the ciphertext was tampered with. |
| **Forward Secrecy** | Property that compromising a long-term secret does not compromise past session keys. AegisQ's [`EphemeralSession`](/api-reference/ephemeral-session/) achieves this by destroying each ephemeral key after use. |

## Streaming Encryption Terms (v1.5.0)

| Term | Definition |
|------|------------|
| **Header** | First chunk of a stream-mode Transit Package: `[capsule \| base_nonce (12 B) \| chunk_size (4 B BE u32)]`. |
| **Frame** | One chunk's envelope in a stream-mode Transit Package: `[length (4 B BE u32) \| ciphertext \| tag (16 B)]`. |
| **base_nonce** | The 12-byte random nonce stored in the stream header. Per-chunk nonces are derived from this. |
| **chunk_size** | Maximum ciphertext size per yielded chunk (1..=16 MiB; default 64 KiB). Encoded in the header. |
| **EOF Marker** | Special frame with `length = 0` and a tag over empty plaintext. Closes the stream. |
| **Chunk Index** | 0-based position of a frame in the stream (uint32). Used in nonce derivation and AAD. |

## Key Serialization Terms (v1.3.0)

| Term | Definition |
|------|------------|
| **PEM** | Privacy-Enhanced Mail envelope: ASCII-armored key with `-----BEGIN ... -----` / `-----END ... -----` headers. AegisQ uses an adapted form (RFC 7468). |
| **JSON Key** | Self-describing key format with `algorithm`, `level`, and `public_key` fields. Useful when the level cannot be conveyed out of band. |
| **Base64 URL-safe** | Base64 variant that uses `-` and `_` instead of `+` and `/`, and omits `=` padding. Suitable for HTTP headers, URLs, and env vars. |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869). AegisQ uses HKDF-SHA3-256 to derive an AES key from a user-supplied password. |
| **Key Wrap** | Encrypting a key under another key. AegisQ uses AES-256-GCM with an HKDF-SHA3-256-derived key from a password. |
| **Fingerprint** | Stable, non-reversible identifier for a public key: first 8 bytes of `SHA3-256(public_key)` in hex. Used by `KeyPair.__repr__` (v1.4.0) to log without leaking raw bytes. |
| **Magic** | Internal byte sequence marking an AegisQ encrypted key blob. Validated on load to catch format mismatch. |

## References

### Standards & Libraries

| Document | URL |
|----------|-----|
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| NIST SP 800-38D (AES-GCM) | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| RFC 5869 (HKDF) | https://www.rfc-editor.org/rfc/rfc5869 |
| RFC 4648 (Base64) | https://www.rfc-editor.org/rfc/rfc4648 |
| RFC 7468 (PEM) | https://www.rfc-editor.org/rfc/rfc7468 |
| CRYSTALS-Kyber spec v3.02 | https://pq-crystals.org/kyber/ |
| aes-gcm Rust crate | https://docs.rs/aes-gcm |
| zeroize Rust crate | https://docs.rs/zeroize |
| subtle Rust crate | https://docs.rs/subtle |
| PyO3 User Guide | https://pyo3.rs/latest/ |
| Maturin Documentation | https://www.maturin.rs/ |
| Starlight Documentation | https://starlight.astro.build/ |

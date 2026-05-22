# AegisQ: Complete Technical Documentation
**Post-Quantum Cryptography Engine — ML-KEM (FIPS 203) & AES-256-GCM Hybrid Implementation**

> **Audience:** AI Code Assistants, Senior Cryptographic Engineers, Security Auditors
> **Last Updated:** May 22, 2026
> **Project Status:** Implementation Complete — All 29 phases passing tests

---

## Table of Contents

1. [Project Identity & Philosophy](#1-project-identity--philosophy)
2. [The Problem Space & Hybrid Solution](#2-the-problem-space--hybrid-solution)
3. [Architecture (The Three-Layer Model)](#3-architecture-the-three-layer-model)
4. [Mathematical Foundation (ML-KEM)](#4-mathematical-foundation-ml-kem)
5. [Data Encapsulation (AES-256-GCM)](#5-data-encapsulation-aes-256-gcm)
6. [Security Model](#6-security-model)
7. [Implementation Roadmap](#7-implementation-roadmap)
8. [API Design](#8-api-design)
9. [Performance & Testing](#9-performance--testing)
10. [References & Glossary](#10-references--glossary)

---

## 1. Project Identity & Philosophy

**AegisQ** is a production-grade, quantum-resistant cryptographic library. It implements a **Hybrid KEM-DEM architecture** combining:

- **ML-KEM** (Module Lattice-based Key Encapsulation Mechanism), standardized by NIST as **FIPS 203**, for quantum-safe key establishment.
- **AES-256-GCM**, for authenticated symmetric encryption of the actual user payload.

**Aegis** (Greek: Αἰγίς) is the indestructible shield of Zeus in Greek mythology. **Q** stands for Quantum-safe.

### Design Philosophy

1. **Security First:** Every decision prioritizes protection against side-channel attacks (timing, power analysis) and implementation vulnerabilities (memory corruption, oracle attacks).
2. **Standards Compliance:** 100% adherence to FIPS 203 without "optimizations" that deviate from the standard.
3. **Developer Ergonomics:** A Python developer should be able to encrypt data securely with 3 lines of code, without understanding lattice cryptography or hybrid encryption internals.
4. **Auditability:** The codebase is structured for formal verification. Clear separation between layers prevents cascading bugs.

---

## 2. The Problem Space & Hybrid Solution

### The Quantum Threat ("Harvest Now, Decrypt Later")

**Shor's Algorithm** (1994) can factor large integers and solve discrete logarithms in polynomial time on a sufficiently large quantum computer. This breaks RSA, ECDSA, ECDH, and Diffie-Hellman. Nation-states are currently capturing encrypted traffic for future decryption.

### Why Not Pure Python?

Pure Python implementations of ML-KEM are 100–1000x slower than needed for production. Python's garbage collector also makes it impossible to guarantee that secret keys are zeroized after use, and Python's `==` operator leaks timing information for secret comparisons.

### The Hybrid Solution (KEM-DEM)

ML-KEM cannot encrypt large payloads directly — it only produces a 32-byte shared secret. AegisQ pairs it with AES-256-GCM as the Data Encapsulation Mechanism:

1. **ML-KEM (Rust):** Generates a 32-byte shared secret, quantum-safe.
2. **AES-256-GCM (Rust):** Uses that 32-byte secret as the symmetric key to encrypt the actual payload with authenticated encryption (confidentiality + integrity).

### Transit Package Structure

The final `encrypted_package` byte array has this fixed structure:

```
[ ML-KEM Capsule (var) | AES Nonce (12 bytes) | AES Auth Tag (16 bytes) | Ciphertext (var) ]
```

Where `ML-KEM Capsule` size depends on the security level:
- ML-KEM-512: 768 bytes
- ML-KEM-768: 1088 bytes
- ML-KEM-1024: 1568 bytes

---

## 3. Architecture (The Three-Layer Model)

AegisQ enforces strict separation between three architectural layers. **Violating layer boundaries is a critical security bug.**

```
╔═══════════════════════════════════════════════════════════════╗
║  LAYER 3: Python API (aegisq/)                                ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  AegisCipher class — .encrypt() / .decrypt()            │  ║
║  │  Abstracts ML-KEM + AES-GCM into one ergonomic API      │  ║
║  │  Type hints, Google-style docstrings, Exception hierarchy│  ║
║  └─────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════╣
║  LAYER 2: FFI Bridge (crates/aegisq-pyo3/)                    ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  PyO3 bindings (#[pyfunction], #[pyclass])              │  ║
║  │  Zero-copy data passing (&[u8] → Python bytes)          │  ║
║  │  GIL release (py.detach) for crypto operations          │  ║
║  │  NO cryptographic logic — pure translation layer        │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════╣
║  LAYER 1: Rust Core (crates/aegisq-core/)                     ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  FIPS 203 algorithms (ML-KEM math, NTT, Zq arithmetic)  │  ║
║  │  Symmetric encryption (AES-256-GCM via `aes-gcm` crate) │  ║
║  │  Transit package assembly/parsing (hybrid.rs)           │  ║
║  │  #![no_std] compatible — constant-time — zeroize        │  ║
║  │  NO knowledge of Python or FFI                          │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════╝
```

### Canonical File Structure

```text
aegisq/
├── Cargo.toml                    # Workspace manifest
├── pyproject.toml                # Maturin build config
├── AGENTS.md                     # AI agent system prompt (rules & constraints)
├── DOCUMENTATION.md              # This file (technical context for LLMs & auditors)
│
├── crates/
│   ├── aegisq-core/              # Layer 1: Pure Rust crypto (no_std)
│   │   └── src/
│   │       ├── mlkem/math/       # Field arithmetic, NTT, Poly operations
│   │       ├── mlkem/keygen.rs   # FIPS 203 Alg 15
│   │       ├── mlkem/encaps.rs   # FIPS 203 Alg 16
│   │       ├── mlkem/decaps.rs   # FIPS 203 Alg 17 (implicit rejection)
│   │       ├── kem.rs            # Public KEM API (traits + structs)
│   │       └── hybrid.rs         # AES-256-GCM + Transit Package assembly
│   │
│   └── aegisq-pyo3/              # Layer 2: FFI Bridge
│       └── src/
│           ├── kem_bindings.rs   # #[pyfunction] KEM operations
│           └── hybrid_bindings.rs # #[pyfunction] encrypt_hybrid, decrypt_hybrid
│
├── aegisq/                       # Layer 3: Python Package
│   ├── cipher.py                 # AegisCipher — main high-level API
│   ├── kem.py                    # MlKem — raw KEM operations (advanced users)
│   ├── exceptions.py             # AegisQError hierarchy
│   └── __init__.py               # Public exports
│
└── tests/
    ├── python/
    │   ├── test_kem_bindings.py
    │   ├── test_hybrid_bindings.py
    │   ├── test_cipher_api.py    # AegisCipher end-to-end tests
    │   └── test_kem_api.py      # MlKem API + roundtrip tests
    └── rust/                     # Rust unit tests (inside each crate via #[cfg(test)])
```

---

## 4. Mathematical Foundation (ML-KEM)

ML-KEM is based on the **Module Learning With Errors (M-LWE)** problem. Polynomial arithmetic is performed in the ring: `Rq = Zq[X] / (X^256 + 1)` where `q = 3329`.

### Core Parameters by Security Level

| Level        | k | η₁ | η₂ | dᵤ | dᵥ | pk size | sk size | ct size | ss size |
|--------------|---|----|----|----|----|---------|---------|---------| --------|
| ML-KEM-512   | 2 | 3  | 2  | 10 | 4  | 800 B   | 1632 B  | 768 B   | 32 B    |
| ML-KEM-768   | 3 | 2  | 2  | 10 | 4  | 1184 B  | 2400 B  | 1088 B  | 32 B    |
| ML-KEM-1024  | 4 | 2  | 2  | 11 | 5  | 1568 B  | 3168 B  | 1568 B  | 32 B    |

### Number Theoretic Transform (NTT)

The NTT is the discrete Fourier transform over finite fields. It allows polynomial multiplication in O(n log n) instead of O(n²).

```
NTT(f) = [f(ζ^(2i+1)) mod q] for i = 0..127
```

Where `ζ = 17` is a primitive 256th root of unity in ℤq.

### The Three Core Algorithms (FIPS 203)

#### ML-KEM.KeyGen (Algorithm 15)

```text
Input:  d (32-byte random seed)
Output: (pk, sk)

1. (ρ, σ) := G(d)              # G is SHA3-512
2. A_hat := SampleMatrix(ρ, k)
3. s := SampleCBD(σ, η₁, k)
4. e := SampleCBD(σ, η₁, k)
5. t_hat := NTT(A_hat · s + e)
6. pk := (t_hat || ρ)
7. sk := (s || pk || H(pk) || z)   # z is random 32 bytes
```

#### ML-KEM.Encaps (Algorithm 16)

```text
Input:  pk (public key)
Output: (K, c)  where K is shared_secret (32 bytes), c is the capsule

1. m := random(32)
2. (K_bar, r) := G(m || H(pk))
3. (u, v) := Encrypt(pk, m, r)
4. c := Compress(u, v)
5. K := KDF(K_bar || H(c))         # Final 32-byte shared secret
```

#### ML-KEM.Decaps (Algorithm 17) — Implicit Rejection

```text
Input:  c (capsule), sk (secret key)
Output: K (shared secret — NEVER an error for invalid ciphertext!)

1. Parse sk as (s, pk, h, z)
2. m' := Decrypt(c, s)
3. (K_bar', r') := G(m' || h)
4. c' := Encaps_internal(pk, m', r')
5. if ct_eq(c, c'):                  # CONSTANT-TIME comparison (subtle::ConstantTimeEq)
       return KDF(K_bar' || H(c))
   else:                              # IMPLICIT REJECTION — no exception, no oracle
       return KDF(z || H(c))         # Pseudorandom key derived from z
```

**Critical Security Property:** Invalid ciphertext returns a pseudorandom key instead of throwing an exception. This prevents Chosen Ciphertext Attacks (CCA) via oracle queries.

---

## 5. Data Encapsulation (AES-256-GCM)

### Overview

Once ML-KEM generates the 32-byte shared secret `K`, AegisQ feeds it directly into AES-256-GCM as the symmetric encryption key. No additional KDF is needed — the 32-byte output of ML-KEM is already uniformly random and the correct size for AES-256.

### AES-256-GCM Properties

| Property | Value |
|----------|-------|
| Key size | 256 bits (32 bytes) — from ML-KEM shared secret |
| Nonce (IV) | 96 bits (12 bytes) — random per operation via `OsRng` |
| Authentication Tag | 128 bits (16 bytes) |
| Security | IND-CPA + INT-CTXT (authenticated encryption) |

### Nonce Management — Critical Rule

> **A nonce must NEVER be reused with the same key.** In AegisQ, this is guaranteed by generating a fresh cryptographically random 96-bit nonce for every `encrypt()` call using `OsRng.fill_bytes()`. There is no counter, no state, no sequential nonce. This is safe because the probability of a 96-bit nonce collision under 2³² encryptions with the same key is negligible (~10⁻¹⁹).

### Transit Package Assembly (`hybrid.rs`)

The `hybrid.rs` module in `aegisq-core` is responsible for:

1. **Encrypting (`encrypt`):**
   - Call `mlkem::encaps(public_key)` → `(capsule, shared_secret_32B)`
   - Generate random 12-byte nonce via `OsRng`
   - Call `aes_gcm::encrypt(key=shared_secret, nonce, plaintext)` → `(tag, ciphertext)`
   - Zeroize `shared_secret` immediately
   - Assemble and return: `capsule || nonce || tag || ciphertext`

2. **Decrypting (`decrypt`):**
   - Split the transit package by known offsets (capsule_size, then 12, 16, rest)
   - Call `mlkem::decaps(secret_key, capsule)` → `shared_secret_32B`
   - Call `aes_gcm::decrypt(key=shared_secret, nonce, tag, ciphertext)` → `plaintext` or `Err`
   - Zeroize `shared_secret` immediately
   - If tag verification fails → return `Err(AegisQError::DecryptionFailed)` (this IS an error, unlike ML-KEM implicit rejection)

### Error Behavior Contrast

| Scenario | ML-KEM Decaps | AES-GCM Decrypt |
|----------|--------------|-----------------|
| Invalid capsule (wrong bytes) | Silent: returns pseudorandom K | N/A |
| Correct capsule, wrong AES key | N/A (key derived from capsule) | Error: `DecryptionError` |
| Auth tag mismatch (tampered payload) | N/A | Error: `DecryptionError` |
| Correct everything | Returns plaintext | Returns plaintext |

---

## 6. Security Model

| Property | Guarantee | Implementation Mechanism |
|----------|-----------|--------------------------|
| **IND-CCA2 Security** | Attack prob. ≤ 2⁻¹²⁸ | Implicit rejection in ML-KEM Decaps |
| **Data Confidentiality** | Quantum-safe payload secrecy | ML-KEM + AES-256-GCM |
| **Data Integrity & Auth** | Tamper-proof payload | AES-GCM 128-bit Authentication Tag |
| **Timing Attack Immunity** | No secret-dependent branches | `subtle::ConstantTimeEq`, Barrett reduction |
| **Memory Scrubbing** | Secret keys zeroed after use | `zeroize::Zeroize` on all sensitive structs |
| **Integer Overflow** | All arithmetic checked | `overflow-checks = true` in release profile |
| **Nonce Uniqueness** | No nonce reuse | Random 96-bit nonce via `OsRng` per call |

### Known Limitations

- **No Forward Secrecy by Default:** If a secret key is compromised, all payloads encrypted to that key are compromised. Mitigation: use ephemeral keypairs per session (generate a new keypair per message/session, transmit the public key, then discard the secret key after decryption).

---

## 7. Implementation Roadmap

The project is divided into 25 strict phases. **Each phase must have passing tests before advancing.**

| Phase | Component | Reference | Status |
|-------|-----------|-----------|--------|
| 1 | Field arithmetic (Zq) & Barrett reduction | FIPS 203 §4.2 | ✅ Complete |
| 2 | NTT & inverse NTT | FIPS 203 §4.3 | ✅ Complete |
| 3 | Polynomial operations | FIPS 203 §4.1 | ✅ Complete |
| 4 | Compress / Decompress | FIPS 203 §4.2.1 | ✅ Complete |
| 5 | Parameters module (k, η₁, η₂, dᵤ, dᵥ per level) | FIPS 203 §5 | ✅ Complete |
| 6 | CBD sampling & XOF (SHAKE-128/256) | FIPS 203 §4.1, §4.2.2 | ✅ Complete |
| 7 | KeyGen (Algorithm 15) | FIPS 203 Alg. 15 | ✅ Complete |
| 8 | Encaps (Algorithm 16) | FIPS 203 Alg. 16 | ✅ Complete |
| 9 | Decaps with implicit rejection (Algorithm 17) | FIPS 203 Alg. 17 | ✅ Complete |
| 10 | Public KEM API (`kem.rs`) | — | ✅ Complete |
| 11 | **AES-256-GCM Hybrid Integration (`hybrid.rs`)** | NIST SP 800-38D | ✅ Complete |
| 12 | FFI error types (`aegisq-pyo3/error.rs`) | — | ✅ Complete |
| 13 | PyO3 types (`types.rs`: KeyPair, EncryptedPackage) | — | ✅ Complete |
| 14 | PyO3 KEM bindings (`kem_bindings.rs`) | — | ✅ Complete |
| 15 | **PyO3 Hybrid bindings (`hybrid_bindings.rs`)** | — | ✅ Complete |
| 16 | PyO3 module registration (`lib.rs`) | — | ✅ Complete |
| 17 | Python exceptions (`exceptions.py`, incl. `DecryptionError`) | — | ✅ Complete |
| 18 | Python type stubs (`_aegisq_core.pyi`) | PEP 561 | ✅ Complete |
| 19 | Python KEM API (`kem.py`, class `MlKem`) | — | ✅ Complete |
| 20 | **Python high-level API (`cipher.py`, class `AegisCipher`)** | — | ✅ Complete |
| 21 | Python package exports (`__init__.py`) | — | ✅ Complete |
| 22 | KEM bridge tests (`test_kem_bindings.py`) | — | ✅ Complete |
| 23 | **Hybrid bridge tests (`test_hybrid_bindings.py`)** | — | ✅ Complete |
| 24 | **AegisCipher end-to-end tests (`test_cipher_api.py`)** | — | ✅ Complete |
| 25 | NIST KATs + ML-KEM integration tests | NIST vectors | ✅ Complete |
| 26 | `.github/workflows/ci.yml` | CI/CD con GitHub Actions | ✅ Completo |
| 27 | `tests/python/json-files/` | Vectores KAT NIST ACVP para ML-KEM | ✅ Completo |
| 27b | `tests/python/test_kat_vectors.py` | Tests de verificación con KAT vectors | ✅ Completo |
| 28 | `aegisq/session.py` | EphemeralSession con forward secrecy | ✅ Completo |
| 29 | `aegisq/cipher.py` + `test_cipher_async.py` | Soporte async (encrypt_async/decrypt_async) | ✅ Completo |

---

## 8. API Design

### Python High-Level API — `AegisCipher` (Target Design)

```python
from aegisq import AegisCipher, SecurityLevel

# 1. Bob (receiver) generates a keypair — public key is shared openly
cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher_bob.generate_keypair()
public_key: bytes  = keypair.public_key   # 1184 bytes — share with anyone
secret_key: bytes  = keypair.secret_key   # 2400 bytes — NEVER share, zeroized on del

# 2. Alice (sender) encrypts using Bob's public key
cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
payload = b"Top secret medical records"
encrypted_package: bytes = cipher_alice.encrypt(
    plaintext=payload,
    recipient_public_key=public_key,
)
# encrypted_package = [ ML-KEM Capsule (1088 B) | Nonce (12 B) | Tag (16 B) | Ciphertext ]
# This is the ONLY thing Alice sends to Bob over the network.

# 3. Bob decrypts the package
decrypted_payload: bytes = cipher_bob.decrypt(
    encrypted_package=encrypted_package,
    secret_key=secret_key,
)
assert decrypted_payload == payload  # ✓
```

### Python Raw KEM API — `MlKem` (Advanced Users)

For users who need to manage keys and shared secrets manually (e.g., building custom protocols):

```python
from aegisq import MlKem, SecurityLevel

kem = MlKem(level=SecurityLevel.ML_KEM_768)
keypair = kem.generate_keypair()

capsule, shared_secret = kem.encapsulate(keypair.public_key)
# capsule        → 1088 bytes — send to key holder
# shared_secret  → 32 bytes  — use as symmetric key

recovered = kem.decapsulate(capsule, keypair.secret_key)
assert shared_secret == recovered
```

#### Base64 Serialization

ML-KEM public keys (800/1184/1568 bytes) can be serialized to URL-safe Base64
without padding for transport as text strings:

```python
from aegisq import MlKem, SecurityLevel

kem = MlKem(level=SecurityLevel.ML_KEM_768)
keypair = kem.generate_keypair()

# Serialize public key to Base64 URL-safe (no padding)
b64 = keypair.public_key_b64()

# Reload public key from Base64 string
recovered = kem.load_public_key_b64(b64)
assert recovered == keypair.public_key
```

This is useful for:
- Transmitting keys via text-based protocols (HTTP headers, JSON payloads)
- Storing keys in environment variables
- Interoperability with NIST ACVP test vectors formats

### Rust Internal API (`aegisq-core`)

```rust
use aegisq_core::{hybrid, SecurityLevel};

// Hybrid encrypt: ML-KEM encaps + AES-256-GCM
let encrypted_package: Vec<u8> = hybrid::encrypt(
    recipient_public_key,
    plaintext,
    SecurityLevel::MlKem768,
)?;

// Hybrid decrypt: ML-KEM decaps + AES-256-GCM verify + decrypt
let plaintext: Vec<u8> = hybrid::decrypt(
    secret_key,
    &encrypted_package,
    SecurityLevel::MlKem768,
)?;
```

> **Note on OsRng:** AegisQ uses `rand_core::OsRng` internally within `hybrid::encrypt`
> to generate fresh random nonces. The caller does not need to pass an RNG — this ensures
> nonce management is handled correctly and prevents accidental nonce reuse.
> `OsRng` sources entropy from `/dev/urandom` on Linux,
> `BCryptGenRandom` on Windows, and `getentropy` on macOS — all OS-level CSPRNGs.

---

## 9. Performance & Testing

### Benchmarks (Estimated vs RSA-2048)

| Operation | ML-KEM-768 (AegisQ) | RSA-2048 |
|-----------|---------------------|----------|
| KeyGen | ~80 µs | ~500 µs |
| Encaps/Encrypt | ~95 µs + AES | ~300 µs |
| Decaps/Decrypt | ~110 µs + AES | ~2,000 µs |

AES-256-GCM overhead adds ~0.1 µs per KB of payload (hardware AES-NI).

### Testing Strategy

1. **Rust Unit Tests (`cargo test`):** Field arithmetic, NTT correctness, polynomial operations, AES-256-GCM, and hybrid encrypt/decrypt. Each module has `#[cfg(test)]` inline tests including 18 tests in `hybrid.rs`.
2. **FFI Bridge Tests:** Validate that Python `bytes` → Rust `&[u8]` → `Vec<u8>` → Python `bytes` round-trips correctly with no memory leaks. Covers KEM bindings (`test_kem_bindings.py`) and hybrid bindings (`test_hybrid_bindings.py`).
3. **AegisCipher End-to-End Tests:** Full encrypt → decrypt round trips across all three security levels, including tampered payload tests (must raise `DecryptionError`), wrong key tests, and empty/large/binary payload tests.
4. **MlKem API Tests:** Round-trip encapsulate/decapsulate across all levels, shared secret size validation, and implicit rejection verification (tampered capsule + wrong key both return valid-looking but different secrets).

---

## 10. References & Glossary

### Standards & Libraries

| Document | URL |
|----------|-----|
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| NIST SP 800-38D (AES-GCM) | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| CRYSTALS-Kyber spec v3.02 | https://pq-crystals.org/kyber/ |
| aes-gcm Rust crate | https://docs.rs/aes-gcm |
| PyO3 User Guide | https://pyo3.rs/latest/ |
| Maturin Documentation | https://www.maturin.rs/ |

### Glossary

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

---

*Document version: 1.3 — Hybrid KEM-DEM architecture (ML-KEM + AES-256-GCM) fully implemented.*

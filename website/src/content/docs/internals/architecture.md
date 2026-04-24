---
title: Architecture
description: AegisQ's three-layer architecture — Rust core, FFI bridge, and Python API.
---

AegisQ enforces strict separation between three architectural layers. **Violating layer boundaries is a critical security bug.** Each layer only depends on the one below it.

## The Three-Layer Model

```text
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

## Layer Responsibilities

### Layer 1: Rust Core (`crates/aegisq-core/`)

Implements all cryptographic math in pure Rust with `no_std` compatibility. It has **no knowledge of Python**.

- FIPS 203 ML-KEM algorithms (KeyGen, Encaps, Decaps)
- Field arithmetic in ℤq (q = 3329) with Barrett reduction
- Number Theoretic Transform (NTT)
- AES-256-GCM authenticated encryption
- Transit package assembly and parsing
- Constant-time operations via `subtle::ConstantTimeEq`
- Memory zeroization via `zeroize::Zeroize`

### Layer 2: FFI Bridge (`crates/aegisq-pyo3/`)

Translates Rust types to Python types via PyO3 and releases the GIL during expensive operations.

- `#[pyfunction]` and `#[pyclass]` bindings
- Zero-copy data passing (`&[u8]` ↔ Python `bytes`)
- GIL release via `py.detach()` for crypto operations
- **No cryptographic logic** — pure translation layer

### Layer 3: Python API (`aegisq/`)

Provides the ergonomic Python classes that end users interact with.

- `AegisCipher` — High-level encrypt/decrypt API
- `MlKem` — Raw KEM operations for advanced users
- `SecurityLevel` — Enum for ML-KEM parameter sets
- Exception hierarchy (`AegisQError` and subclasses)
- PEP 561 type stubs for IDE autocompletion

## Canonical File Structure

```text
aegisq/
├── Cargo.toml                    # Workspace manifest
├── pyproject.toml                # Maturin build config
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
    │   └── test_kem_api.py       # MlKem API + roundtrip tests
    └── rust/                     # Rust unit tests (inside each crate via #[cfg(test)])
```

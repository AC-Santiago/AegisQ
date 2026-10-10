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
║  │  AegisCipher — encrypt / decrypt / stream / async / ctx │  ║
║  │  EphemeralSession — session keypair lifecycle           │  ║
║  │  MlKem — raw KEM for advanced users                     │  ║
║  │  aegisq.keys — PEM/JSON/encrypted file persistence      │  ║
║  │  Exception hierarchy + PEP 561 type stubs               │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════╣
║  LAYER 2: FFI Bridge (crates/aegisq-pyo3/)                    ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  PyO3 bindings (#[pyfunction], #[pyclass])              │  ║
║  │  Borrowed inputs (&[u8]); copied Python bytes outputs   │  ║
║  │  GIL release (py.detach) for crypto operations          │  ║
║  │  NO cryptographic logic — pure translation layer        │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════╣
║  LAYER 1: Rust Core (crates/aegisq-core/)                     ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  FIPS 203 ML-KEM (KeyGen, Encaps, Decaps + math)        │  ║
║  │  AES-256-GCM authenticated encryption                   │  ║
║  │  HKDF-SHA3-256 + encrypted secret-key wrap              │  ║
║  │  Transit Package (one-shot + streaming formats)         │  ║
║  │  #![no_std] + alloc — subtle — scoped zeroization       │  ║
║  │  NO knowledge of Python or FFI                          │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════╝
```

## Layer Responsibilities

### Layer 1: Rust Core (`crates/aegisq-core/`)

Implements all cryptographic math in pure Rust with `no_std` compatibility. It has **no knowledge of Python**.

- FIPS 203 ML-KEM algorithms (KeyGen, Encaps, Decaps with implicit rejection)
- Field arithmetic in ℤq (q = 3329) with Barrett reduction
- Number Theoretic Transform (NTT)
- AES-256-GCM authenticated encryption
- HKDF-SHA3-256 + AES-256-GCM key wrap for encrypted secret-key export
- Transit Package assembly (one-shot + streaming modes)
- Constant-time operations via `subtle::ConstantTimeEq`
- Memory zeroization via `zeroize::Zeroize`

### Layer 2: FFI Bridge (`crates/aegisq-pyo3/`)

Translates Rust types to Python types via PyO3 and releases the GIL during expensive operations.

- `#[pyfunction]` and `#[pyclass]` bindings
- Borrowed byte-slice inputs (`&[u8]`); `PyBytes::new` copies native outputs and key getter results
- GIL release via `py.detach()` for crypto operations
- Native streaming classes with explicit methods (`encrypt_chunk`, `finalize`, `decrypt_chunk`, `process_eof`) used by Python generators
- PyO3 types `KeyPair` and `SecurityLevel`; keypair repr contains the level and a truncated public-key fingerprint, not secret bytes
- **No cryptographic logic** — pure translation layer

### Layer 3: Python API (`aegisq/`)

Provides the ergonomic Python classes that end users interact with.

- `AegisCipher` — High-level encrypt/decrypt/streaming/async/context-manager API
- `EphemeralSession` — Auto-managed session keypair; closure drops its reference, without a complete secure-erasure guarantee
- `MlKem` — Raw KEM operations for advanced users
- `aegisq.keys` — File-oriented key persistence (PEM, JSON, encrypted PEM)
- `SecurityLevel` — Enum for ML-KEM parameter sets
- Exception hierarchy (`AegisQError` and subclasses)
- PEP 561 type stubs for IDE autocompletion

## Canonical File Structure

```text
aegisq/
├── Cargo.toml                      # Workspace manifest
├── pyproject.toml                  # Maturin build config
├── deny.toml                       # cargo-deny 0.20.2 policy
│
├── crates/
│   ├── aegisq-core/                # Layer 1: Pure Rust crypto (no_std)
│   │   ├── Cargo.toml
│   │   ├── benches/                # Criterion benchmarks
│   │   │   ├── ntt.rs              # NTT forward/inverse/multiply
│   │   │   └── kem.rs              # KeyGen/Encaps/Decaps across 3 levels
│   │   └── src/
│   │       ├── lib.rs              # Module roots + re-exports
│   │       ├── error.rs            # AegisQError variants (thiserror)
│   │       ├── kem.rs              # Public KEM API (traits + structs)
│   │       ├── hybrid.rs           # AES-256-GCM + one-shot Transit Package
│   │       ├── stream.rs           # StreamEncryptor/StreamDecryptor (v1.5.0)
│   │       ├── kdf.rs              # HKDF-SHA3-256 (v1.3.0)
│   │       ├── key_wrap.rs         # AES-256-GCM wrap with HKDF key (v1.3.0)
│   │       └── mlkem/
│   │           ├── mod.rs
│   │           ├── params.rs       # Parameters per security level
│   │           ├── keygen.rs       # FIPS 203 Alg. 15
│   │           ├── encaps.rs       # FIPS 203 Alg. 16
│   │           ├── decaps.rs       # FIPS 203 Alg. 17 (implicit rejection)
│   │           ├── sampling.rs     # CBD + rejection sampling + SHAKE
│   │           └── math/
│   │               ├── mod.rs
│   │               ├── field.rs    # �q arithmetic, Barrett reduction
│   │               ├── ntt.rs       # Forward / inverse NTT
│   │               ├── poly.rs      # Polynomial ops in Rq
│   │               └── compress.rs  # FIPS 203 §4.2.1
│   │
│   └── aegisq-pyo3/                # Layer 2: FFI Bridge
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs              # #[pymodule] _aegisq_core registration
│           ├── types.rs            # #[pyclass] KeyPair, SecurityLevel
│           ├── error.rs            # AegisQError → PyException mapping
│           ├── kem_bindings.rs     # #[pyfunction] KEM operations
│           ├── hybrid_bindings.rs  # #[pyfunction] encrypt_hybrid/decrypt_hybrid
│           ├── key_io_bindings.rs  # PEM/JSON load/save (v1.3.0)
│           └── stream_bindings.rs  # StreamEncryptor/StreamDecryptor PyO3 (v1.5.0)
│
├── aegisq/                         # Layer 3: Python Package
│   ├── __init__.py                 # Public API re-exports
│   ├── _aegisq_core.pyi            # Type stubs (PEP 561)
│   ├── _aegisq_core.abi3.so        # Compiled PyO3 extension (built artifact)
│   ├── cipher.py                   # AegisCipher — main high-level API
│   ├── kem.py                      # MlKem — raw KEM operations
│   ├── keys.py                     # File-based key persistence (v1.3.0)
│   ├── session.py                  # EphemeralSession — session lifecycle
│   ├── exceptions.py               # AegisQError hierarchy (+ SessionExpiredError)
│   └── py.typed                    # PEP 561 marker
│
├── tests/
│   ├── python/
│   │   ├── conftest.py
│   │   ├── test_cipher_api.py
│   │   ├── test_cipher_async.py
│   │   ├── test_cipher_context_manager.py
│   │   ├── test_hybrid_bindings.py
│   │   ├── test_implicit_rejection.py
│   │   ├── test_kat_vectors.py
│   │   ├── test_kem_api.py
│   │   ├── test_kem_bindings.py
│   │   ├── test_kem_serialization.py
│   │   ├── test_keypair_repr.py
│   │   ├── test_key_serialization.py
│   │   ├── test_session.py
│   │   ├── test_stream.py
│   │   └── json-files/             # NIST ACVP KAT vectors
│   │       ├── ML-KEM-keyGen-FIPS203/
│   │       └── ML-KEM-encapDecap-FIPS203/
│   └── rust/                       # Rust unit tests (inside each crate via #[cfg(test)])
│
└── website/                        # This documentation site (Astro + Starlight)
```

## Layer-Boundary Rules (Non-Negotiable)

| If you see… | In layer… | It's a bug |
|-------------|-----------|------------|
| `use pyo3` | `aegisq-core` | ❌ Core must not know about Python |
| Lattice arithmetic | `aegisq-pyo3` | ❌ FFI must not implement crypto |
| `import _aegisq_core` | end-user code | ❌ Users must use the public `aegisq` API |
| `use aegisq_core::mlkem::math` (public re-export) | `aegisq-pyo3` | � Internal math types must stay internal |
| `println!` / `eprintln!` | `aegisq-core` | ❌ `no_std` + potential side-channel leakage |

## Why Three Layers?

- **Testability** — Each layer can be tested in isolation. Rust unit tests live in `#[cfg(test)]` modules without Python. The bridge and Python API have integration and end-to-end tests under `tests/python/`.
- **Auditability** — Cryptographic review focuses on Layer 1. FFI correctness review focuses on Layer 2. Ergonomics review focuses on Layer 3.
- **Portability** — Layer 1 is `no_std` + `alloc`. A future Node.js / Go / WASM binding is a Layer 2 rewrite, not a Layer 1 rewrite.
- **Performance** — Borrowed inputs avoid unnecessary input copies and `py.detach()` permits other Python threads to run during expensive native work. Outputs still require Python allocations; this architecture alone is not a benchmark or a guarantee of multi-core scaling.

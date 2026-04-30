# AegisQ

**Post-Quantum Cryptography Engine for Python**

AegisQ is a hybrid cryptographic library that combines **ML-KEM** (FIPS 203) for quantum-resistant key encapsulation with **AES-256-GCM** for authenticated symmetric encryption. The cryptographic core is written in Rust for performance and security guarantees, exposed to Python via PyO3.

```python
from aegisq import AegisCipher, SecurityLevel

cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher.generate_keypair()

# Encrypt
package = cipher.encrypt(b"Secret data", keypair.public_key)

# Decrypt
plaintext = cipher.decrypt(package, keypair.secret_key)
```

---

## Features

- **Quantum-safe key exchange** — ML-KEM (Module Lattice-based KEM), standardized as NIST FIPS 203
- **Authenticated encryption** — AES-256-GCM provides confidentiality and integrity in a single operation
- **Three security levels** — ML-KEM-512 (NIST Level 1), ML-KEM-768 (Level 3, default), ML-KEM-1024 (Level 5)
- **Rust core, Python API** — Cryptographic operations run in optimized Rust; Python developers get an ergonomic 3-line API
- **Constant-time operations** — Timing-attack resistant via `subtle::ConstantTimeEq` and Barrett reduction
- **Memory zeroization** — All secret keys and shared secrets are securely erased after use via `zeroize`
- **Zero-copy FFI** — Data passes between Python and Rust without unnecessary copies
- **GIL release** — Rust crypto operations release the Python GIL via `py.detach()`, enabling true parallelism
- **Type-safe** — Full PEP 561 type stubs with IDE autocompletion support
- **Python 3.11+** — Built with PyO3 abi3 stable ABI for broad compatibility (3.11 through 3.13+)
- **Ephemeral sessions with forward secrecy** — `EphemeralSession` class auto-generates keypairs and destroys secrets on close
- **Async support** — `encrypt_async()` / `decrypt_async()` methods for non-blocking cryptographic operations

---

## Installation

### From source (requires Rust toolchain)

```bash
# Prerequisites: Rust (via rustup), Python >= 3.11, maturin
pip install maturin

# Clone and build
git clone <repository-url>
cd aegisq
maturin develop --release
```

### Development build (debug, faster compilation)

```bash
maturin develop
```

---

## Quick Start

### Encrypt and Decrypt (Recommended API)

The `AegisCipher` class handles the entire hybrid KEM-DEM flow — ML-KEM key encapsulation followed by AES-256-GCM encryption — in a single `.encrypt()` call.

```python
from aegisq import AegisCipher, SecurityLevel

# 1. Receiver generates a keypair
cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher_bob.generate_keypair()
# keypair.public_key  → 1184 bytes (share openly)
# keypair.secret_key  → 2400 bytes (keep private)

# 2. Sender encrypts with the receiver's public key
cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
encrypted_package = cipher_alice.encrypt(
    plaintext=b"Top secret medical records",
    recipient_public_key=keypair.public_key,
)
# encrypted_package is a single bytes object:
# [ ML-KEM Capsule (1088 B) | Nonce (12 B) | Auth Tag (16 B) | Ciphertext ]

# 3. Receiver decrypts
decrypted = cipher_bob.decrypt(
    encrypted_package=encrypted_package,
    secret_key=keypair.secret_key,
)
assert decrypted == b"Top secret medical records"
```

### Raw KEM Operations (Advanced)

The `MlKem` class exposes low-level ML-KEM operations for users building custom protocols:

```python
from aegisq import MlKem, SecurityLevel

kem = MlKem(level=SecurityLevel.ML_KEM_768)
keypair = kem.generate_keypair()

# Encapsulate: produces a capsule + 32-byte shared secret
capsule, shared_secret = kem.encapsulate(keypair.public_key)

# Decapsulate: recovers the same 32-byte shared secret
recovered = kem.decapsulate(capsule, keypair.secret_key)
assert shared_secret == recovered
```

---

## Security Levels

| Level | Enum Value | NIST Level | Public Key | Secret Key | Capsule | Package Overhead |
|-------|------------|------------|------------|------------|---------|------------------|
| ML-KEM-512 | `SecurityLevel.ML_KEM_512` | 1 | 800 B | 1632 B | 768 B | 796 B |
| ML-KEM-768 | `SecurityLevel.ML_KEM_768` | 3 (default) | 1184 B | 2400 B | 1088 B | 1116 B |
| ML-KEM-1024 | `SecurityLevel.ML_KEM_1024` | 5 | 1568 B | 3168 B | 1568 B | 1596 B |

**Package overhead** = capsule + AES nonce (12 B) + AES auth tag (16 B). The total encrypted package size is overhead + plaintext length.

---

## API Reference

### `AegisCipher` (recommended for most users)

```python
class AegisCipher:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def generate_keypair(self) -> KeyPair
    def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    def decrypt(self, encrypted_package: bytes, secret_key: bytes) -> bytes
    async def encrypt_async(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    async def decrypt_async(self, encrypted_package: bytes, secret_key: bytes) -> bytes
```

### `EphemeralSession` (forward secrecy)

```python
class EphemeralSession:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def public_key(self) -> bytes  # Read-only, secret key never exposed
    def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    def decrypt(self, encrypted_package: bytes) -> bytes
    def close(self) -> None
    # Also supports context manager: `with EphemeralSession() as s: ...`
```

### `MlKem` (advanced, raw KEM operations)

```python
class MlKem:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def generate_keypair(self) -> KeyPair
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]
    def decapsulate(self, capsule: bytes, secret_key: bytes) -> bytes
```

### `KeyPair`

```python
class KeyPair:
    public_key: bytes   # Encryption key (share openly)
    secret_key: bytes   # Decapsulation key (keep private)
    level: SecurityLevel
```

### Exceptions

```
AegisQError(Exception)                          Base exception
├── DecapsulationError(AegisQError)             ML-KEM structural error (wrong buffer size)
├── DecryptionError(AegisQError)               AES-GCM auth tag failed (tampered or wrong key)
├── InvalidParameterError(AegisQError, ValueError)  Incorrect parameter sizes
├── RngError(AegisQError)                      OS CSPRNG unavailable
└── SessionExpiredError(AegisQError)           Attempted operation on closed EphemeralSession
```

All exceptions can be imported from the top-level package:

```python
from aegisq import AegisQError, DecryptionError
```

---

## Architecture

AegisQ is structured in three hermetic layers. Each layer only depends on the one below it:

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 3: Python API  (aegisq/)                             │
│  AegisCipher, MlKem, SecurityLevel, exception hierarchy     │
│  Type hints, docstrings, developer-facing abstractions       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: FFI Bridge  (crates/aegisq-pyo3/)                 │
│  PyO3 bindings, GIL release, zero-copy data passing          │
│  No cryptographic logic — pure translation layer             │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Rust Core   (crates/aegisq-core/)                 │
│  ML-KEM (FIPS 203), AES-256-GCM, Transit Package assembly   │
│  #![no_std] compatible, constant-time, zeroize               │
└─────────────────────────────────────────────────────────────┘
```

- **Layer 1** implements all cryptographic math in pure Rust with `no_std` compatibility. It has no knowledge of Python.
- **Layer 2** translates Rust types to Python types via PyO3 and releases the GIL during expensive operations.
- **Layer 3** provides the ergonomic Python classes that end users interact with.

---

## Development

### Build

```bash
maturin develop                    # Debug build (fast compilation)
maturin develop --release          # Release build (optimized)
```

### Test

```bash
# Rust tests (unit + integration, all crates)
cargo test --workspace

# Python tests
pytest tests/python/ -v

# Specific test suites
cargo test -p aegisq-core                     # Core crypto only
pytest tests/python/test_cipher_api.py        # AegisCipher end-to-end
pytest tests/python/test_hybrid_bindings.py   # Hybrid bridge
pytest tests/python/test_kem_bindings.py      # KEM bridge
pytest tests/python/test_kem_api.py           # MlKem API
```

### Code Quality

```bash
cargo clippy --workspace -- -D warnings   # Rust linter (warnings are errors)
cargo fmt --all                           # Rust formatting
ruff check aegisq/                        # Python type checking
```

---

## Security

### Guarantees

| Property | Mechanism |
|----------|-----------|
| IND-CCA2 security | Implicit rejection in ML-KEM Decaps (FIPS 203 §7.3) |
| Quantum resistance | M-LWE hardness assumption (ML-KEM) |
| Data confidentiality + integrity | AES-256-GCM authenticated encryption |
| Timing attack immunity | `subtle::ConstantTimeEq`, Barrett reduction |
| Memory scrubbing | `zeroize::Zeroize` on all secrets |
| Nonce uniqueness | Fresh 96-bit random nonce via `OsRng` per encrypt call |
| Integer overflow protection | `overflow-checks = true` in release profile |

### Important Notes

- **No forward secrecy by default.** If a secret key is compromised, all payloads encrypted to that key are compromised. **Mitigation:** Use ephemeral keypairs — generate a new keypair per session and discard the secret key after decryption.
- **ML-KEM Decaps never raises an error for invalid capsules** (implicit rejection). Instead, it returns a pseudorandom key, which causes AES-GCM to fail with `DecryptionError`. This prevents chosen-ciphertext oracle attacks.
- **AES-GCM tag failure always raises `DecryptionError`.** Unlike ML-KEM's silent rejection, a failed auth tag means the payload was tampered with or the wrong key was used.

---

## Standards Compliance

| Standard | Description |
|----------|-------------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM — Module-Lattice-Based Key-Encapsulation Mechanism (NIST, 2024) |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AES-GCM — Galois/Counter Mode specification |

### Dependencies

| Crate | Purpose |
|-------|---------|
| `aes-gcm` 0.10 | AES-256-GCM authenticated encryption (no_std, hardware AES-NI) |
| `sha3` 0.10 | SHAKE-128/256 and SHA3-256/512 for ML-KEM (no_std) |
| `zeroize` 1.8 | Secure memory erasure of secrets |
| `subtle` 2.6 | Constant-time comparisons |
| `rand_core` 0.6 | OS-level CSPRNG via `OsRng` (no_std) |
| `pyo3` 0.28 | Rust-Python FFI bindings (abi3-py311) |

---

For complete technical documentation including the mathematical foundation, algorithm specifications, and security model details, see [DOCUMENTATION.md](DOCUMENTATION.md).

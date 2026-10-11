# AegisQ

**Post-Quantum Cryptography Engine for Python**

AegisQ is a hybrid cryptographic library that combines **ML-KEM** (FIPS 203) for quantum-resistant key encapsulation with **AES-256-GCM** for authenticated symmetric encryption. The cryptographic core is written in Rust and exposed to Python via PyO3.

**Status: Beta.** See [PyPI](https://pypi.org/project/aegisq-pqc/) for published versions and [CHANGELOG.md](CHANGELOG.md) for release history. Checkout versions are declared in the package manifests; `develop` can contain an unpublished prerelease. Algorithm implementation and test-vector coverage do not constitute FIPS certification or an independent security audit.

**Website:** [aegisq.dev](https://aegisq.dev/) · **Documentation:** [English](https://docs.aegisq.dev/) / [Español](https://docs.aegisq.dev/es/)

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
- **Timing defenses** — Constant-time capsule comparison and key selection via `subtle`; Barrett reduction in field arithmetic
- **Scoped memory cleanup** — Explicit zeroization in selected Rust paths; not a guarantee of erasure for every key or Python copy
- **Borrowed FFI inputs** — Bindings accept byte slices; returned Python bytes and key getters create copies
- **GIL release** — Rust crypto operations release the Python GIL via `py.detach()`, enabling true parallelism
- **Type information** — PEP 561 marker and native API stubs; streaming bindings are not yet included in the native stub
- **Python 3.11+** — Built with PyO3 abi3 stable ABI for broad compatibility (3.11 through 3.13+)
- **Ephemeral sessions** — `EphemeralSession` generates a session keypair and disables access on close; secure erasure and protocol-level forward secrecy are not guaranteed
- **Async support** — `encrypt_async()` / `decrypt_async()` methods for non-blocking cryptographic operations

---

## Installation

### From PyPI (recommended)

```bash
pip install aegisq-pqc
```

> **Python 3.11+ required.** A compatible wheel avoids a Rust build; otherwise installation requires a Rust toolchain. The extension targets `abi3-py311`, but wheels remain OS/architecture-specific and future/free-threaded runtimes require separate validation.

### From source (requires Rust toolchain)

```bash
# Prerequisites: Rust (via rustup), Python >= 3.11
git clone https://github.com/AC-Santiago/AegisQ.git
cd AegisQ
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install maturin
maturin develop --release
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
import hmac
assert hmac.compare_digest(shared_secret, recovered)
```

### Async Operations

```python
import asyncio
from aegisq import AegisCipher, SecurityLevel

async def main():
    cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
    keypair = await asyncio.to_thread(cipher.generate_keypair)

    # Non-blocking encryption
    package = await cipher.encrypt_async(
        b"Secret data",
        keypair.public_key,
    )

    # Non-blocking decryption
    plaintext = await cipher.decrypt_async(
        package,
        keypair.secret_key,
    )
    print(plaintext)  # b'Secret data'

asyncio.run(main())
```

### Ephemeral Sessions

`EphemeralSession` generates a keypair internally. Closing it drops its keypair reference and prevents further operations, but does not guarantee memory erasure. Forward secrecy additionally requires an appropriate authenticated protocol and secure disposal of past keys.

```python
from aegisq import EphemeralSession

# Receiver creates a session with no public secret-key getter
with EphemeralSession() as receiver:
    public_key = receiver.public_key  # Share this with the sender

    # Sender encrypts using the receiver's public key
    sender_cipher = EphemeralSession()
    package = sender_cipher.encrypt(
        b"Secret data",
        recipient_public_key=public_key,
    )
    sender_cipher.close()

    # Receiver decrypts
    plaintext = receiver.decrypt(package)

# Session closes and drops its keypair reference; no complete erasure guarantee
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

### `EphemeralSession` (session keypair lifecycle)

```python
class EphemeralSession:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    @property
    def public_key(self) -> bytes  # No public secret-key getter
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
    def load_public_key_b64(self, b64: str, level: SecurityLevel | None = None) -> bytes
```

#### Base64 Serialization

```python
# Serialize public key to Base64 URL-safe (no padding)
b64 = keypair.public_key_b64()

# Load public key from Base64 URL-safe string
kem = MlKem(level=SecurityLevel.ML_KEM_768)
public_key_bytes = kem.load_public_key_b64(b64)
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
├── DecapsulationError(AegisQError)             Exported structural error type
├── DecryptionError(AegisQError)               AES-GCM auth tag failed (tampered or wrong key)
├── InvalidParameterError(AegisQError)          Incorrect parameter sizes
├── KeySerializationError(AegisQError)          Malformed key serialization
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
│  PyO3 bindings, GIL release, borrowed byte-slice inputs      │
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
ruff check aegisq/                        # Python linting (not type checking)
```

---

## Security

### Mechanisms and Limits

| Property | Mechanism |
|----------|-----------|
| Capsule-validity oracle defense | Implicit rejection in ML-KEM Decaps (FIPS 203 §7.3) |
| Quantum resistance | M-LWE hardness assumption (ML-KEM) |
| Data confidentiality + integrity | AES-256-GCM authenticated encryption |
| Timing defenses | Constant-time capsule comparison/key selection; not a complete side-channel audit |
| Scoped memory cleanup | Selected Rust buffers are zeroized; bridge keys and Python copies are not covered completely |
| Random one-shot nonces | Fresh 96-bit OS-random nonce per encrypt call; uniqueness is probabilistic |
| Integer overflow protection | `overflow-checks = true` in release profile |

### Important Notes

- **No forward-secrecy guarantee.** A compromised secret key permits decryption of recorded payloads addressed to it. Independent session keys reduce key reuse, but `EphemeralSession.close()` is not a secure-erasure guarantee.
- **Implicit rejection applies to invalid contents of correctly sized capsules.** Decaps returns a pseudorandom key; AES-GCM authentication is expected to fail with `DecryptionError`. Incorrect key/capsule sizes raise `InvalidParameterError` in the current implementation.
- **No sender-identity or replay protection.** Authenticate public keys and enforce protocol-level replay protection separately.
- **AES-GCM tag failure always raises `DecryptionError`.** Unlike ML-KEM's silent rejection, a failed auth tag means the payload was tampered with or the wrong key was used.

---

## Standards Compliance

| Standard | Description |
|----------|-------------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM — Module-Lattice-Based Key-Encapsulation Mechanism (NIST, 2024) |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AES-GCM — Galois/Counter Mode specification |

### Dependencies

The table summarizes current manifest requirements, not exact resolved versions or a historical release. See [Cargo.toml](Cargo.toml), the [bridge manifest](crates/aegisq-pyo3/Cargo.toml), and `Cargo.lock` for the complete inventory.

| Crate | Version | Purpose |
|-------|---------|---------|
| `aes-gcm` | 0.11 | AES-256-GCM authenticated encryption (no_std) |
| `sha3` | 0.12 | SHA3-256/512 for ML-KEM (no_std) |
| `shake` | 0.1 | SHAKE-128/256 for ML-KEM (no_std) |
| `zeroize` | 1.9 | Cleanup of selected secret buffers |
| `subtle` | 2.6 | Constant-time comparisons |
| `getrandom` | 0.4 | Cross-platform CSPRNG (no_std) |
| `pyo3` | 0.29 | Rust-Python FFI bindings (abi3-py311) |

---

## Documentation

Start with [installation](https://docs.aegisq.dev/getting-started/installation/),
the [API reference](https://docs.aegisq.dev/api-reference/aegiscipher/), and the
[security model](https://docs.aegisq.dev/internals/security-model/).
Canonical English/Spanish sources are in
[website/src/content/docs/](website/src/content/docs/); contributor checks and the
manual publication procedure are in [website/README.md](website/README.md).

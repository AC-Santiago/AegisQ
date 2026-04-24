---
title: AegisCipher
description: High-level hybrid encryption API — ML-KEM key encapsulation + AES-256-GCM authenticated encryption in one call.
---

`AegisCipher` is the **recommended API** for most users. It handles the entire hybrid KEM-DEM flow — ML-KEM key encapsulation followed by AES-256-GCM encryption — behind a simple, ergonomic interface.

## Class Signature

```python
class AegisCipher:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def generate_keypair(self) -> KeyPair
    def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    def decrypt(self, encrypted_package: bytes, secret_key: bytes) -> bytes
```

## Constructor

```python
AegisCipher(level: SecurityLevel = SecurityLevel.ML_KEM_768)
```

Creates a new cipher instance with the specified security level.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | `SecurityLevel` | `ML_KEM_768` | The ML-KEM security level to use |

## Methods

### `generate_keypair()`

Generates a new ML-KEM keypair for the configured security level.

**Returns:** `KeyPair` — An object with `public_key` (bytes) and `secret_key` (bytes) attributes.

```python
keypair = cipher.generate_keypair()
# keypair.public_key  → share openly
# keypair.secret_key  → keep private, zeroized on deletion
# keypair.level       → the SecurityLevel used
```

### `encrypt(plaintext, recipient_public_key)`

Encrypts plaintext using the recipient's public key. Internally performs ML-KEM encapsulation to derive a shared secret, then encrypts the plaintext with AES-256-GCM.

| Parameter | Type | Description |
|-----------|------|-------------|
| `plaintext` | `bytes` | The data to encrypt |
| `recipient_public_key` | `bytes` | The recipient's ML-KEM public key |

**Returns:** `bytes` — The encrypted transit package: `[Capsule | Nonce (12 B) | Auth Tag (16 B) | Ciphertext]`

**Raises:**
- `InvalidParameterError` — If the public key size doesn't match the security level
- `RngError` — If the OS CSPRNG is unavailable

### `decrypt(encrypted_package, secret_key)`

Decrypts an encrypted transit package using the recipient's secret key. Internally performs ML-KEM decapsulation to recover the shared secret, then decrypts and verifies the ciphertext with AES-256-GCM.

| Parameter | Type | Description |
|-----------|------|-------------|
| `encrypted_package` | `bytes` | The encrypted transit package from `encrypt()` |
| `secret_key` | `bytes` | The recipient's ML-KEM secret key |

**Returns:** `bytes` — The original plaintext

**Raises:**
- `DecryptionError` — If the AES-GCM auth tag verification fails (tampered payload or wrong key)
- `InvalidParameterError` — If the package or key sizes are incorrect

## KeyPair

The `KeyPair` object returned by `generate_keypair()`:

```python
class KeyPair:
    public_key: bytes   # Encryption key (share openly)
    secret_key: bytes   # Decapsulation key (keep private)
    level: SecurityLevel
```

## Complete Example

```python
from aegisq import AegisCipher, SecurityLevel

# 1. Bob (receiver) generates a keypair — public key is shared openly
cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher_bob.generate_keypair()
public_key: bytes = keypair.public_key   # 1184 bytes — share with anyone
secret_key: bytes = keypair.secret_key   # 2400 bytes — NEVER share, zeroized on del

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

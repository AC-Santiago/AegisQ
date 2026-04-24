---
title: MlKem
description: Low-level ML-KEM API for raw key encapsulation and decapsulation operations.
---

`MlKem` exposes the raw ML-KEM (FIPS 203) operations for advanced users building custom protocols. If you just need to encrypt and decrypt data, use [`AegisCipher`](/api-reference/aegiscipher/) instead.

## Class Signature

```python
class MlKem:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def generate_keypair(self) -> KeyPair
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]
    def decapsulate(self, capsule: bytes, secret_key: bytes) -> bytes
```

## Constructor

```python
MlKem(level: SecurityLevel = SecurityLevel.ML_KEM_768)
```

Creates a new ML-KEM instance with the specified security level.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `level` | `SecurityLevel` | `ML_KEM_768` | The ML-KEM security level to use |

## Methods

### `generate_keypair()`

Generates a new ML-KEM keypair for the configured security level.

**Returns:** `KeyPair` — An object with `public_key` (bytes) and `secret_key` (bytes) attributes.

### `encapsulate(public_key)`

Performs ML-KEM encapsulation: generates a capsule and a 32-byte shared secret using the recipient's public key.

| Parameter | Type | Description |
|-----------|------|-------------|
| `public_key` | `bytes` | The recipient's ML-KEM public key |

**Returns:** `tuple[bytes, bytes]` — A tuple of `(capsule, shared_secret)`:
- `capsule` — The encapsulated key (send to the key holder)
- `shared_secret` — 32 bytes to use as a symmetric key

**Raises:**
- `InvalidParameterError` — If the public key size doesn't match the security level
- `RngError` — If the OS CSPRNG is unavailable

### `decapsulate(capsule, secret_key)`

Performs ML-KEM decapsulation: recovers the 32-byte shared secret from a capsule using the secret key.

| Parameter | Type | Description |
|-----------|------|-------------|
| `capsule` | `bytes` | The capsule from `encapsulate()` |
| `secret_key` | `bytes` | The recipient's ML-KEM secret key |

**Returns:** `bytes` — The 32-byte shared secret

:::caution[Implicit Rejection]
`decapsulate()` **never raises an error** for invalid capsules. Instead, it returns a pseudorandom key (derived from the secret key's rejection seed `z`). This is the **implicit rejection** mechanism defined in FIPS 203 Algorithm 17 — it prevents Chosen Ciphertext Attacks (CCA) via oracle queries.

If you're using `MlKem` directly, you must handle this behavior yourself. `AegisCipher` handles it automatically: an invalid capsule produces a wrong AES-GCM key, which causes `DecryptionError` on tag verification.
:::

## Example

```python
from aegisq import MlKem, SecurityLevel

kem = MlKem(level=SecurityLevel.ML_KEM_768)
keypair = kem.generate_keypair()

# Encapsulate: produces a capsule + 32-byte shared secret
capsule, shared_secret = kem.encapsulate(keypair.public_key)
# capsule        → 1088 bytes — send to key holder
# shared_secret  → 32 bytes  — use as symmetric key

# Decapsulate: recovers the same 32-byte shared secret
recovered = kem.decapsulate(capsule, keypair.secret_key)
assert shared_secret == recovered
```

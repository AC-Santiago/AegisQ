---
title: Quick Start
description: Get started with AegisQ in minutes — encrypt and decrypt data with post-quantum security.
---

## Encrypt and Decrypt (Recommended API)

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

## Raw KEM Operations (Advanced)

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

## What Happens Under the Hood?

When you call `cipher.encrypt()`, AegisQ performs the following steps automatically:

1. **ML-KEM Encapsulation** — Generates a quantum-safe 32-byte shared secret using the recipient's public key
2. **AES-256-GCM Encryption** — Uses that shared secret as the symmetric key to encrypt your plaintext with authenticated encryption
3. **Transit Package Assembly** — Packs everything into a single `bytes` object: `[Capsule | Nonce | Auth Tag | Ciphertext]`

Decryption reverses this process: the capsule is decapsulated to recover the shared secret, which is then used to decrypt and verify the ciphertext.

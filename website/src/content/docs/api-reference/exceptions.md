---
title: Exceptions
description: AegisQ exception hierarchy — error types, when they are raised, and how to handle them.
---

AegisQ defines a hierarchy of exceptions that map to specific cryptographic failure modes. All exceptions can be imported from the top-level `aegisq` package.

## Exception Hierarchy

```text
AegisQError(Exception)                          Base exception
├── DecapsulationError(AegisQError)             ML-KEM structural error (wrong buffer size)
├── DecryptionError(AegisQError)                AES-GCM auth tag failed (tampered or wrong key)
├── InvalidParameterError(AegisQError, ValueError)  Incorrect parameter sizes
└── RngError(AegisQError)                       OS CSPRNG unavailable
```

## Exception Details

### `AegisQError`

The base exception for all AegisQ errors. Catch this to handle any AegisQ-specific error.

### `DecapsulationError`

Raised when the ML-KEM capsule has an incorrect buffer size (structural error). This is **not** raised for invalid capsule contents — see the note on implicit rejection below.

### `DecryptionError`

Raised when AES-GCM authentication tag verification fails. This means either:
- The encrypted payload was **tampered with** in transit
- The **wrong secret key** was used for decryption
- The capsule was **invalid**, causing ML-KEM to return a pseudorandom key (implicit rejection), which in turn causes AES-GCM to fail

### `InvalidParameterError`

Raised when parameter sizes don't match the expected values for the security level (e.g., providing a 768-byte public key when ML-KEM-1024 expects 1568 bytes). Inherits from both `AegisQError` and `ValueError`.

### `RngError`

Raised when the operating system's CSPRNG (Cryptographically Secure Pseudo-Random Number Generator) is unavailable. This is extremely rare and typically indicates a system-level issue.

## Error Handling Example

```python
from aegisq import (
    AegisCipher,
    SecurityLevel,
    AegisQError,
    DecryptionError,
    InvalidParameterError,
)

cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher.generate_keypair()

# Encrypt some data
package = cipher.encrypt(b"Sensitive data", keypair.public_key)

# --- Handling decryption errors ---
try:
    plaintext = cipher.decrypt(package, keypair.secret_key)
except DecryptionError:
    # AES-GCM auth tag failed: payload was tampered with or wrong key
    print("Decryption failed: data integrity check failed")
except InvalidParameterError:
    # Wrong key/package size for this security level
    print("Invalid parameter: check key and package sizes")
except AegisQError:
    # Catch-all for any other AegisQ error
    print("An unexpected cryptographic error occurred")
```

:::note[Implicit Rejection]
ML-KEM's `decapsulate()` **never raises an exception** for invalid capsule *contents*. Instead, it silently returns a pseudorandom key (FIPS 203, Algorithm 17). When using `AegisCipher`, this pseudorandom key causes AES-GCM decryption to fail, which surfaces as a `DecryptionError`. This design prevents Chosen Ciphertext Attacks (CCA) by not revealing whether a capsule was valid or invalid.
:::

## Importing Exceptions

All exceptions are available from the top-level package:

```python
from aegisq import (
    AegisQError,
    DecapsulationError,
    DecryptionError,
    InvalidParameterError,
    RngError,
)
```

---
title: Security Levels
description: ML-KEM security levels — key sizes, capsule sizes, and package overhead for ML-KEM-512, 768, and 1024.
---

AegisQ supports all three ML-KEM security levels defined in FIPS 203. The default is **ML-KEM-768** (NIST Level 3), which provides a balance of security and performance suitable for most applications.

## Security Level Comparison

| Level | Enum Value | NIST Level | Public Key | Secret Key | Capsule | Package Overhead |
|-------|------------|------------|------------|------------|---------|------------------|
| ML-KEM-512 | `SecurityLevel.ML_KEM_512` | 1 | 800 B | 1632 B | 768 B | 796 B |
| ML-KEM-768 | `SecurityLevel.ML_KEM_768` | 3 (default) | 1184 B | 2400 B | 1088 B | 1116 B |
| ML-KEM-1024 | `SecurityLevel.ML_KEM_1024` | 5 | 1568 B | 3168 B | 1568 B | 1596 B |

**Package overhead** = capsule + AES nonce (12 B) + AES auth tag (16 B). The total encrypted package size is overhead + plaintext length.

## NIST Security Levels Explained

- **Level 1** — At least as hard to break as AES-128. Suitable for short-term data protection.
- **Level 3** — At least as hard to break as AES-192. Recommended for most applications. **(Default)**
- **Level 5** — At least as hard to break as AES-256. Maximum security for the most sensitive data.

## Usage

```python
from aegisq import AegisCipher, SecurityLevel

# Default: ML-KEM-768 (NIST Level 3)
cipher = AegisCipher()

# Explicit level selection
cipher_512 = AegisCipher(level=SecurityLevel.ML_KEM_512)    # Fastest, smallest keys
cipher_768 = AegisCipher(level=SecurityLevel.ML_KEM_768)    # Recommended (default)
cipher_1024 = AegisCipher(level=SecurityLevel.ML_KEM_1024)  # Maximum security
```

## Core Parameters (FIPS 203)

These are the internal ML-KEM parameters for each security level:

| Level | k | η₁ | η₂ | dᵤ | dᵥ | pk size | sk size | ct size | ss size |
|-------|---|----|----|----|----|---------|---------|---------|---------|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 B | 3168 B | 1568 B | 32 B |

Where:
- **k** — Module dimension (number of polynomial vectors)
- **η₁, η₂** — CBD sampling parameters for error terms
- **dᵤ, dᵥ** — Compression bit-widths
- **pk** — Public key, **sk** — Secret key, **ct** — Ciphertext (capsule), **ss** — Shared secret

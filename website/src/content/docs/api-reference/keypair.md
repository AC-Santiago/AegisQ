---
title: KeyPair
description: KeyPair class — properties, serialization methods (PEM, JSON, Base64) and encrypted secret-key export.
sidebar:
  badge:
    text: v1.3.0
    variant: tip
---

The `KeyPair` class encapsulates an ML-KEM keypair returned by [`AegisCipher.generate_keypair()`](/api-reference/aegiscipher/#generate_keypair) and [`MlKem.generate_keypair()`](/api-reference/mlkem/#generate_keypair). It exposes the raw public/secret material in `bytes` and convenience methods to serialize them in transport-friendly formats.

## Class Signature

```python
class KeyPair:
    # Properties
    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

    # Serialization methods (v1.3.0)
    def public_key_b64(self) -> str
    def public_key_pem(self) -> str
    def public_key_json(self) -> str
    def export_secret_key_raw(self, password: bytes) -> bytes
    def export_secret_key_pem(self, password: bytes) -> str
```

## Properties

### `public_key`

The ML-KEM public key as `bytes`. Share it openly.

| Level | Size |
|-------|------|
| ML-KEM-512 | 800 B |
| ML-KEM-768 | 1184 B |
| ML-KEM-1024 | 1568 B |

### `secret_key`

The ML-KEM secret key as `bytes`. **Never share it.** It is zeroized via Rust `zeroize::Zeroize` when the `KeyPair` is dropped and the GIL is released during every cryptographic operation that touches it.

| Level | Size |
|-------|------|
| ML-KEM-512 | 1632 B |
| ML-KEM-768 | 2400 B |
| ML-KEM-1024 | 3168 B |

### `level`

The `SecurityLevel` the keypair was generated with.

### `__repr__` (v1.4.0 — safe fingerprint)

The repr intentionally **does not leak** raw bytes or key sizes (sizes alone enable correlation attacks between instances). It returns:

```text
KeyPair(level=<SecurityLevel.ML_KEM_768>, fp=<16-hex>)
```

Where `<16-hex>` is the first 8 bytes of `SHA3-256(public_key)` in hexadecimal — a stable, non-reversible fingerprint useful for logs.

```python
>>> from aegisq import AegisCipher
>>> cipher = AegisCipher()
>>> kp = cipher.generate_keypair()
>>> repr(kp)
"KeyPair(level=<SecurityLevel.ML_KEM_768>, fp=a3f1c0b27d4e9f12)"
```

## Public-Key Serialization Methods

These methods convert the raw `public_key` bytes into transport-friendly strings. Choose whichever format fits your channel.

### `public_key_b64() -> str`

Returns the public key as **Base64 URL-safe without padding** (RFC 4648 §5). Compact, URL-safe, no metadata.

```python
>>> b64 = kp.public_key_b64()
>>> b64
"6BDM8h...snip..."
>>> import base64
>>> roundtrip = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
>>> roundtrip == kp.public_key
True
```

Use this when you need to embed the key in HTTP headers, JSON, environment variables, or short URLs.

### `public_key_pem() -> str`

Returns the public key as a **PEM-like envelope**:

```text
-----BEGIN ML-KEM PUBLIC KEY-----
<Base64 STANDARD of public_key>
-----END ML-KEM PUBLIC KEY-----
```

The body uses Base64 STANDARD (not URL-safe). The level **is not encoded** in the PEM — the caller must know which `SecurityLevel` the PEM was generated for. Use [`load_public_key(path, level=...)`](/api-reference/key-serialization/#load_public_key) when reading back.

### `public_key_json() -> str`

Returns the public key as a **self-describing JSON** with `algorithm`, `level`, and `public_key` (Base64 STANDARD) fields. Use this when you want a format that records its own level — useful for archival and interop with non-Python clients.

```json
{
  "algorithm": "ML-KEM",
  "level": "ML-KEM-768",
  "public_key": "6BDM8h...snip..."
}
```

## Secret-Key Export Methods

:::caution[Secret keys are NEVER exported in plaintext]
The secret key is encrypted with **AES-256-GCM** using a key derived from your `password` via **HKDF-SHA3-256**. Losing the password means losing the key — there is no recovery mechanism. There is intentionally no API to export the secret key without a password.
:::

### `export_secret_key_raw(password: bytes) -> bytes`

Returns the encrypted secret key as an **opaque binary blob** with an internal magic/version header. Use this when you need to store the key in a binary format (databases, key-value stores, custom protocols).

### `export_secret_key_pem(password: bytes) -> str`

Returns the encrypted secret key as a **PEM-like envelope**:

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD of encrypted blob>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

The body uses Base64 STANDARD. Use [`load_secret_key(path, password=...)`](/api-reference/key-serialization/#load_secret_key) or [`MlKem`](/api-reference/mlkem/) to decrypt.

## Complete Example

```python
from aegisq import AegisCipher

cipher = AegisCipher()
keypair = cipher.generate_keypair()

# Raw bytes (used internally)
pk_bytes: bytes = keypair.public_key
sk_bytes: bytes = keypair.secret_key

# Transport formats for the public key
b64_string: str = keypair.public_key_b64()      # for HTTP headers / env vars
pem_string: str = keypair.public_key_pem()      # for files (.pem)
json_string: str = keypair.public_key_json()    # for archival / interop

# Encrypted export of the secret key
password: bytes = b"correct horse battery staple"
sk_pem: str = keypair.export_secret_key_pem(password)
sk_blob: bytes = keypair.export_secret_key_raw(password)

# Safe to log: only level + fingerprint
print(repr(keypair))
# KeyPair(level=<SecurityLevel.ML_KEM_768>, fp=a3f1c0b27d4e9f12)
```

## See Also

- [`AegisCipher.generate_keypair()`](/api-reference/aegiscipher/#generate_keypair) — how to obtain a `KeyPair`
- [`MlKem.generate_keypair()`](/api-reference/mlkem/#generate_keypair) — same, via the low-level API
- [Key Serialization helpers](/api-reference/key-serialization/) — `save_*` / `load_*` for file-based persistence
- [EphemeralSession](/api-reference/ephemeral-session/) — auto-managed keypair with forward secrecy

---
title: Key Serialization
description: File-based persistence for ML-KEM keys — PEM, JSON, and encrypted PEM with password-derived AES-256-GCM keys.
sidebar:
  badge:
    text: v1.3.0
    variant: tip
---

The `aegisq.keys` module provides file-oriented helpers built on top of [`KeyPair`](/api-reference/keypair/). It handles the common patterns of saving public keys to disk, loading them back, and round-tripping encrypted secret keys with a password.

The module is **v1.3.0** and lives in `aegisq/keys.py`. Every function accepts either a string path or a `pathlib.Path`.

## Quick Reference

| Function | Direction | Format | Encryption |
|---|---|---|---|
| `save_public_key` | KeyPair → file | PEM (default) or JSON | None |
| `load_public_key` | file → bytes | Auto-detect PEM/JSON | None |
| `save_secret_key` | KeyPair → file | Encrypted PEM | AES-256-GCM (HKDF-SHA3-256) |
| `load_secret_key` | file → bytes | Encrypted PEM | AES-256-GCM (HKDF-SHA3-256) |
| `public_key_to_pem` | KeyPair → str | PEM | None |
| `public_key_to_json` | KeyPair → str | JSON | None |
| `secret_key_to_pem` | KeyPair → str | Encrypted PEM | AES-256-GCM (HKDF-SHA3-256) |

:::caution[Secret keys are always encrypted]
There is no API to save or export a secret key in plaintext. The `save_secret_key` / `load_secret_key` / `secret_key_to_pem` functions all require a `password: bytes` argument — losing it means losing the key.
:::

## Public-Key Persistence

### `save_public_key`

```python
def save_public_key(keypair: KeyPair, path: str | Path, *, fmt: str = "pem") -> None
```

Writes the public key to `path` in either **PEM** (default) or **JSON** format.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `keypair` | `KeyPair` | — | Source keypair. |
| `path` | `str \| Path` | — | Destination file. Use `.pem` for PEM or `.json` for JSON. |
| `fmt` | `str` | `"pem"` | Either `"pem"` or `"json"`. |

**Raises:** `ValueError` if `fmt` is not `"pem"` or `"json"`; `OSError` on filesystem failure.

```python
from aegisq import AegisCipher
from aegisq.keys import save_public_key

cipher = AegisCipher()
keypair = cipher.generate_keypair()

# PEM (recommended for long-term storage)
save_public_key(keypair, "recipient.pem")

# JSON (self-describing, useful for interop)
save_public_key(keypair, "recipient.json", fmt="json")
```

### `load_public_key`

```python
def load_public_key(path: str | Path, *, level: SecurityLevel | None = None) -> bytes
```

Reads a public key back from disk and returns it as `bytes` (ready to pass to `AegisCipher.encrypt()`).

**Format detection** is automatic — the function inspects the first non-empty line of the file:

- `-----BEGIN ML-KEM PUBLIC KEY-----` → PEM (caller **must** supply `level=`)
- `{` → JSON (level is read from the `"level"` field and `level` argument is ignored)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `path` | `str \| Path` | — | Source file. |
| `level` | `SecurityLevel \| None` | `None` | Required for PEM. Ignored for JSON. |

**Returns:** `bytes` — the public key.

**Raises:**
- `ValueError` — file format not recognizable, or PEM file without `level=`
- `KeySerializationError` — malformed PEM header or JSON fields
- `InvalidParameterError` — decoded size does not match the level
- `OSError` — file not readable

```python
from aegisq import SecurityLevel
from aegisq.keys import load_public_key

# PEM file — you must know the level
pk = load_public_key("recipient.pem", level=SecurityLevel.ML_KEM_768)

# JSON file — level is read from the file
pk = load_public_key("recipient.json")
```

## Secret-Key Persistence (Encrypted)

### `save_secret_key`

```python
def save_secret_key(keypair: KeyPair, path: str | Path, *, password: bytes) -> None
```

Encrypts the secret key with **AES-256-GCM** (key derived via **HKDF-SHA3-256** from your `password`) and writes it as **Encrypted PEM**.

The file looks like:

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD of encrypted blob>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

The body contains a magic/version header, a fresh random 12-byte nonce, the AES-GCM ciphertext, and a 16-byte auth tag. A fresh nonce is generated per call via `OsRng`, so saving the same keypair twice produces **different** output.

**Raises:** `RngError` if the OS CSPRNG is unavailable; `OSError` on filesystem failure.

```python
from aegisq.keys import save_secret_key

save_secret_key(keypair, "private.key", password=b"s3cr3t p@ssw0rd")
```

### `load_secret_key`

```python
def load_secret_key(path: str | Path, *, password: bytes) -> bytes
```

Reads an Encrypted PEM file, verifies the auth tag, and returns the secret key as `bytes`.

**Raises:**
- `DecryptionError` — wrong password or tampered file
- `KeySerializationError` — invalid PEM header, Base64, or magic/version
- `OSError` — file not readable

```python
from aegisq.keys import load_secret_key

sk = load_secret_key("private.key", password=b"s3cr3t p@ssw0rd")
plaintext = cipher.decrypt(encrypted_package, sk)
```

:::note[Wrong password vs. tampered file]
Both surface as `DecryptionError`. AES-GCM auth-tag verification is binary — the only signal the library gets is "valid" or "invalid". A wrong password and a corrupted file look identical to the caller, by design.
:::

## String-Only Convenience Functions

These three functions produce or consume `str` instead of files, which is useful when keys live in environment variables, secret managers, or database columns.

### `public_key_to_pem`

```python
def public_key_to_pem(keypair: KeyPair) -> str
```

Equivalent to `keypair.public_key_pem()` exposed as a module-level function for ergonomic imports.

### `public_key_to_json`

```python
def public_key_to_json(keypair: KeyPair) -> str
```

Equivalent to `keypair.public_key_json()` exposed as a module-level function for ergonomic imports.

### `secret_key_to_pem`

```python
def secret_key_to_pem(keypair: KeyPair, *, password: bytes) -> str
```

Equivalent to `keypair.export_secret_key_pem(password)` exposed as a module-level function for ergonomic imports.

## End-to-End Example

```python
from aegisq import AegisCipher, SecurityLevel
from aegisq.keys import (
    save_public_key, load_public_key,
    save_secret_key, load_secret_key,
)

# Receiver side: generate and persist
cipher = AegisCipher()
keypair = cipher.generate_keypair()
save_public_key(keypair, "alice.pub.pem", fmt="pem")
save_secret_key(keypair, "alice.sec.pem", password=b"hunter2")

# Later (or in another process): load back
cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
pub = load_public_key("alice.pub.pem", level=SecurityLevel.ML_KEM_768)
sec = load_secret_key("alice.sec.pem", password=b"hunter2")

# Use as normal
package = cipher.encrypt(b"secret message", pub)
plaintext = cipher.decrypt(package, sec)
assert plaintext == b"secret message"
```

## Format Reference

### PEM Public Key

```text
-----BEGIN ML-KEM PUBLIC KEY-----
<Base64 STANDARD of public_key bytes>
-----END ML-KEM PUBLIC KEY-----
```

### JSON Public Key

```json
{
  "algorithm": "ML-KEM",
  "level": "ML-KEM-768",
  "public_key": "<Base64 STANDARD>"
}
```

### Encrypted PEM Secret Key

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD of: magic || version || nonce || ciphertext || tag>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

The internal blob format is an implementation detail — treat it as opaque. Decryption goes through `load_secret_key_pem` / `load_secret_key_raw` only.

## See Also

- [`KeyPair`](/api-reference/keypair/) — the underlying class with raw bytes and serialization methods
- [`MlKem`](/api-reference/mlkem/) — low-level KEM API with `load_public_key_b64`
- [Exceptions](/api-reference/exceptions/#keyserializationerror) — `KeySerializationError`, `DecryptionError` raised by these helpers

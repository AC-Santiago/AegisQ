---
title: AegisCipher
description: High-level hybrid encryption API — ML-KEM key encapsulation + AES-256-GCM authenticated encryption in one call.
---

`AegisCipher` is the **recommended API** for most users. It handles the entire hybrid KEM-DEM flow — ML-KEM key encapsulation followed by AES-256-GCM encryption — behind a simple, ergonomic interface.

The class also provides four extensions that cover most production scenarios:

- **[Context manager](#context-manager)** (`__enter__` / `__exit__`) — proactive zeroization for forward-compatible session APIs (v1.4.0).
- **[Streaming encryption](#streaming-encryption)** (`encrypt_stream` / `decrypt_stream`) — encrypt files of any size with bounded memory (v1.5.0).
- **[Async methods](#async-methods)** (`encrypt_async` / `decrypt_async`) — non-blocking variants for asyncio code paths (v1.4.0).

## Class Signature

```python
class AegisCipher:
    # Core one-shot API
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def generate_keypair(self) -> KeyPair
    def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    def decrypt(self, encrypted_package: bytes, secret_key: bytes) -> bytes

    # Streaming (v1.5.0)
    def encrypt_stream(
        self,
        recipient_public_key: bytes,
        plaintext_chunks: Iterable[bytes],
        chunk_size: int = 65536,
    ) -> Iterator[bytes]
    def decrypt_stream(
        self,
        secret_key: bytes,
        ciphertext_chunks: Iterable[bytes],
    ) -> Iterator[bytes]

    # Async (v1.4.0)
    async def encrypt_async(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    async def decrypt_async(self, encrypted_package: bytes, secret_key: bytes) -> bytes

    # Context manager (v1.4.0)
    def __enter__(self) -> Self
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool

    # Property
    @property
    def level(self) -> SecurityLevel
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

The `KeyPair` object returned by `generate_keypair()`. For full documentation see [KeyPair reference](/api-reference/keypair/).

### Properties

```python
class KeyPair:
    public_key: bytes   # Encryption key (share openly)
    secret_key: bytes   # Decapsulation key (keep private, zeroized on drop)
    level: SecurityLevel
```

### `__repr__` (v1.4.0 — safe fingerprint)

The repr intentionally **does not leak** raw bytes or key sizes. It returns:

```text
KeyPair(level=<SecurityLevel.ML_KEM_768>, fp=<16-hex>)
```

`<16-hex>` is the first 8 bytes of `SHA3-256(public_key)` — a stable, non-reversible fingerprint.

### Serialization methods (v1.3.0)

For file/network transport, `KeyPair` exposes:

| Method | Returns | Format |
|--------|---------|--------|
| `public_key_b64()` | `str` | Base64 URL-safe (RFC 4648 §5), no padding |
| `public_key_pem()` | `str` | PEM-like with `-----BEGIN ML-KEM PUBLIC KEY-----` envelope |
| `public_key_json()` | `str` | Self-describing JSON with `algorithm`, `level`, `public_key` |
| `export_secret_key_raw(password)` | `bytes` | Opaque AES-256-GCM-encrypted blob (HKDF-SHA3-256) |
| `export_secret_key_pem(password)` | `str` | PEM-like `-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----` envelope |

For file-based persistence helpers (`save_*` / `load_*`), see [Key Serialization](/api-reference/key-serialization/).

## Streaming Encryption

:::caution[v1.5.0]
`encrypt_stream` and `decrypt_stream` were introduced in v1.5.0.
:::

For payloads that don't fit in memory (videos, backups, large JSON), use the streaming API. Both methods are generator-based — pass an iterable of plaintext chunks, get back an iterable of ciphertext chunks.

```python
CHUNK = 65_536

with open("video.mp4", "rb") as src, open("video.aegisq", "wb") as out:
    plaintext_iter = iter(lambda: src.read(CHUNK), b"")
    for ct_chunk in cipher.encrypt_stream(keypair.public_key, plaintext_iter):
        out.write(ct_chunk)
```

The Transit Package in stream mode is self-delimiting:

```text
[ HEADER: capsule | base_nonce (12 B) | chunk_size (4 B BE) ]
[ FRAME 0: len (4 B BE) | ciphertext | tag (16 B) ]
[ FRAME 1: ... ]
[ EOF MARKER: len=0 | tag (16 B over empty plaintext) ]
```

Each chunk's AES-GCM nonce is derived from its index (`i.to_be_bytes() || base_nonce[4..12]`) and its AAD is the 4-byte big-endian chunk index — preventing chunk-reordering attacks.

Full documentation: [Streaming Encryption](/api-reference/streaming/).

## Async Methods

:::note[v1.4.0]
`encrypt_async` and `decrypt_async` were introduced in v1.4.0.
:::

Non-blocking variants of `encrypt()` / `decrypt()` for asyncio code. They run the synchronous implementation in the default `ThreadPoolExecutor`, so the event loop stays responsive even on large payloads.

```python
import asyncio
from aegisq import AegisCipher

async def main():
    cipher = AegisCipher()
    keypair = cipher.generate_keypair()

    package = await cipher.encrypt_async(b"secret", keypair.public_key)
    plaintext = await cipher.decrypt_async(package, keypair.secret_key)
    print(plaintext)  # b"secret"

asyncio.run(main())
```

Full documentation: [Async Methods](/api-reference/async-methods/).

## Context Manager

:::note[v1.4.0]
The `__enter__` / `__exit__` protocol was introduced in v1.4.0.
:::

`AegisCipher` can be used inside a `with` block. On exit, any Python-side buffer registered during the session is **overwritten with zeros in place**. Today's public API does not retain Python-side material, so this is a forward-compatible hook — but it costs nothing to use.

```python
from aegisq import AegisCipher

with AegisCipher() as cipher:
    keypair = cipher.generate_keypair()
    package = cipher.encrypt(b"hello", keypair.public_key)
# __exit__ zeroizes any registered buffer; exceptions still propagate.
```

`__repr__` reflects the session state:

```python
>>> repr(cipher)
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, inactive)'

>>> with cipher:
...     repr(cipher)
...
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, active)'
```

Full documentation: [Context Manager](/api-reference/context-manager/).

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

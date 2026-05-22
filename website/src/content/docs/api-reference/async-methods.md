---
title: Async Methods
description: Non-blocking encryption and decryption
---

## Overview

`AegisCipher` provides `encrypt_async()` and `decrypt_async()` methods that run in a `ThreadPoolExecutor` without blocking the event loop.

```python
import asyncio
from aegisq import AegisCipher, SecurityLevel

async def main():
    cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
    keypair = cipher.generate_keypair()

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

## API Reference

### `encrypt_async(plaintext, recipient_public_key)` {#encrypt_async}

```python
async def encrypt_async(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
```

Encrypts the plaintext using the hybrid scheme. Runs in a thread pool.

### `decrypt_async(encrypted_package, secret_key)` {#decrypt_async}

```python
async def decrypt_async(self, encrypted_package: bytes, secret_key: bytes) -> bytes
```

Decrypts the transit package. Runs in a thread pool.
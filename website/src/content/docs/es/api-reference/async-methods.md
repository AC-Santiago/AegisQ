---
title: Métodos Asíncronos
description: Cifrado y descifrado no bloqueantes
---

## Descripción General

`AegisCipher` provee los métodos `encrypt_async()` y `decrypt_async()` que corren en un `ThreadPoolExecutor` sin bloquear el event loop.

```python
import asyncio
from aegisq import AegisCipher, SecurityLevel

async def main():
    cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
    keypair = cipher.generate_keypair()

    # Cifrado no bloqueante
    package = await cipher.encrypt_async(
        b"Datos secretos",
        keypair.public_key,
    )

    # Descifrado no bloqueante
    plaintext = await cipher.decrypt_async(
        package,
        keypair.secret_key,
    )
    print(plaintext)  # b'Datos secretos'

asyncio.run(main())
```

## Referencia de la API

### `encrypt_async(plaintext, recipient_public_key)` {#encrypt_async}

```python
async def encrypt_async(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
```

Cifra el plaintext usando el esquema híbrido. Corre en un thread pool.

### `decrypt_async(encrypted_package, secret_key)` {#decrypt_async}

```python
async def decrypt_async(self, encrypted_package: bytes, secret_key: bytes) -> bytes
```

Descifra el Transit Package. Corre en un thread pool.

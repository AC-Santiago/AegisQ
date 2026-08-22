---
title: AegisCipher
description: API de alto nivel para cifrado híbrido — encapsulación de clave ML-KEM + cifrado autenticado AES-256-GCM en una sola llamada.
---

`AegisCipher` es la **API recomendada** para la mayoría de los usuarios. Maneja todo el flujo KEM-DEM híbrido — encapsulación ML-KEM seguida de cifrado AES-256-GCM — detrás de una interfaz simple y ergonómica.

La clase también proporciona cuatro extensiones que cubren la mayoría de escenarios de producción:

- **[Context Manager](#context-manager)** (`__enter__` / `__exit__`) — zeroización proactiva para APIs de sesión forward-compatibles (v1.4.0).
- **[Cifrado en Streaming](#cifrado-en-streaming)** (`encrypt_stream` / `decrypt_stream`) — cifrá archivos de cualquier tamaño con memoria acotada (v1.5.0).
- **[Métodos Asíncronos](#metodos-asincronos)** (`encrypt_async` / `decrypt_async`) — variantes no bloqueantes para code paths de asyncio (v1.4.0).

## Firma de la Clase

```python
class AegisCipher:
    # API one-shot principal
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

    # Asíncrono (v1.4.0)
    async def encrypt_async(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
    async def decrypt_async(self, encrypted_package: bytes, secret_key: bytes) -> bytes

    # Context manager (v1.4.0)
    def __enter__(self) -> Self
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool

    # Propiedad
    @property
    def level(self) -> SecurityLevel
```

## Constructor

```python
AegisCipher(level: SecurityLevel = SecurityLevel.ML_KEM_768)
```

Crea una nueva instancia de cipher con el nivel de seguridad especificado.

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `level` | `SecurityLevel` | `ML_KEM_768` | El nivel de seguridad ML-KEM a usar |

## Métodos

### `generate_keypair()`

Genera un nuevo keypair ML-KEM para el nivel de seguridad configurado.

**Retorna:** `KeyPair` — Un objeto con los atributos `public_key` (bytes) y `secret_key` (bytes).

```python
keypair = cipher.generate_keypair()
# keypair.public_key  → compartir abiertamente
# keypair.secret_key  → mantener privado, zeroizado al eliminar
# keypair.level       → el SecurityLevel usado
```

### `encrypt(plaintext, recipient_public_key)`

Cifra plaintext usando la clave pública del receptor. Internamente realiza la encapsulación ML-KEM para derivar un shared secret, luego cifra el plaintext con AES-256-GCM.

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `plaintext` | `bytes` | Los datos a cifrar |
| `recipient_public_key` | `bytes` | La clave pública ML-KEM del receptor |

**Retorna:** `bytes` — El Transit Package cifrado: `[Capsule | Nonce (12 B) | Auth Tag (16 B) | Ciphertext]`

**Lanza:**
- `InvalidParameterError` — Si el tamaño de la clave pública no coincide con el nivel de seguridad
- `RngError` — Si el CSPRNG del OS no está disponible

### `decrypt(encrypted_package, secret_key)`

Descifra un Transit Package cifrado usando la clave secreta del receptor. Internamente realiza la desencapsulación ML-KEM para recuperar el shared secret, luego descifra y verifica el ciphertext con AES-256-GCM.

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `encrypted_package` | `bytes` | El Transit Package cifrado proveniente de `encrypt()` |
| `secret_key` | `bytes` | La clave secreta ML-KEM del receptor |

**Retorna:** `bytes` — El plaintext original

**Lanza:**
- `DecryptionError` — Si la verificación del Auth Tag de AES-GCM falla (payload manipulado o clave incorrecta)
- `InvalidParameterError` — Si los tamaños del paquete o de la clave son incorrectos

## KeyPair

El objeto `KeyPair` retornado por `generate_keypair()`. Para documentación completa ver [referencia KeyPair](/api-reference/keypair/).

### Propiedades

```python
class KeyPair:
    public_key: bytes   # Clave de cifrado (compartir abiertamente)
    secret_key: bytes   # Clave de desencapsulación (mantener privada)
    level: SecurityLevel
```

### `__repr__` (v1.4.0 — fingerprint seguro)

El repr **no filtra** bytes crudos ni tamaños de claves. Retorna:

```text
KeyPair(level=<SecurityLevel.ML_KEM_768>, fp=<16-hex>)
```

`<16-hex>` son los primeros 8 bytes de `SHA3-256(public_key)` — un fingerprint estable y no reversible.

### Métodos de serialización (v1.3.0)

Para transporte por archivo/red, `KeyPair` expone:

| Método | Retorna | Formato |
|--------|---------|---------|
| `public_key_b64()` | `str` | Base64 URL-safe (RFC 4648 §5), sin padding |
| `public_key_pem()` | `str` | PEM-like con `-----BEGIN ML-KEM PUBLIC KEY-----` |
| `public_key_json()` | `str` | JSON auto-descriptivo con `algorithm`, `level`, `public_key` |
| `export_secret_key_raw(password)` | `bytes` | Blob opaco cifrado con AES-256-GCM (HKDF-SHA3-256) |
| `export_secret_key_pem(password)` | `str` | PEM-like `-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----` |

Para helpers de persistencia basada en archivos (`save_*` / `load_*`), ver [Serialización de Claves](/api-reference/key-serialization/).

## Cifrado en Streaming

:::caution[v1.5.0]
`encrypt_stream` y `decrypt_stream` fueron introducidos en v1.5.0.
:::

Para payloads que no caben en memoria (videos, backups, JSON grandes), usá la API de streaming. Ambos métodos están basados en generadores — pasás un iterable de chunks de plaintext y obtenés un iterable de chunks de ciphertext.

```python
CHUNK = 65_536

with open("video.mp4", "rb") as src, open("video.aegisq", "wb") as out:
    plaintext_iter = iter(lambda: src.read(CHUNK), b"")
    for ct_chunk in cipher.encrypt_stream(keypair.public_key, plaintext_iter):
        out.write(ct_chunk)
```

El Transit Package en modo stream se autodelimita:

```text
[ HEADER: capsule | base_nonce (12 B) | chunk_size (4 B BE) ]
[ FRAME 0: len (4 B BE) | ciphertext | tag (16 B) ]
[ FRAME 1: ... ]
[ EOF MARKER: len=0 | tag (16 B sobre plaintext vacío) ]
```

El nonce AES-GCM de cada chunk se deriva de su índice (`i.to_be_bytes() || base_nonce[4..12]`) y su AAD es el índice de chunk de 4 bytes en big-endian — previniendo ataques de reordenamiento de chunks.

Documentación completa: [Cifrado en Streaming](/api-reference/streaming/).

## Métodos Asíncronos

:::note[v1.4.0]
`encrypt_async` y `decrypt_async` fueron introducidos en v1.4.0.
:::

Variantes no bloqueantes de `encrypt()` / `decrypt()` para código asyncio. Ejecutan la implementación sincrónica en el `ThreadPoolExecutor` por defecto, así el event loop queda responsive incluso con payloads grandes.

```python
import asyncio
from aegisq import AegisCipher

async def main():
    cipher = AegisCipher()
    keypair = cipher.generate_keypair()

    package = await cipher.encrypt_async(b"secreto", keypair.public_key)
    plaintext = await cipher.decrypt_async(package, keypair.secret_key)
    print(plaintext)  # b"secreto"

asyncio.run(main())
```

Documentación completa: [Métodos Asíncronos](/api-reference/async-methods/).

## Context Manager

:::note[v1.4.0]
El protocolo `__enter__` / `__exit__` fue introducido en v1.4.0.
:::

`AegisCipher` puede usarse dentro de un bloque `with`. Al salir, cualquier buffer Python-side registrado durante la sesión es **sobrescrito con ceros in-place**. La API pública actual no retiene material Python-side, así que esto es un hook forward-compatible — pero no cuesta nada usarlo.

```python
from aegisq import AegisCipher

with AegisCipher() as cipher:
    keypair = cipher.generate_keypair()
    package = cipher.encrypt(b"hola", keypair.public_key)
# __exit__ zeroiza cualquier buffer registrado; las excepciones se propagan igual.
```

`__repr__` refleja el estado de la sesión:

```python
>>> repr(cipher)
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, inactive)'

>>> with cipher:
...     repr(cipher)
...
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, active)'
```

Documentación completa: [Context Manager](/api-reference/context-manager/).

## Ejemplo Completo

```python
from aegisq import AegisCipher, SecurityLevel

# 1. Bob (receptor) genera un keypair — la clave pública se comparte abiertamente
cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher_bob.generate_keypair()
public_key: bytes = keypair.public_key   # 1184 bytes — compartir con cualquiera
secret_key: bytes = keypair.secret_key   # 2400 bytes — NUNCA compartir, zeroizado al del

# 2. Alice (emisor) cifra usando la clave pública de Bob
cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
payload = b"Registros médicos ultra secretos"
encrypted_package: bytes = cipher_alice.encrypt(
    plaintext=payload,
    recipient_public_key=public_key,
)
# encrypted_package = [ ML-KEM Capsule (1088 B) | Nonce (12 B) | Tag (16 B) | Ciphertext ]
# Esto es lo ÚNICO que Alice envía a Bob por la red.

# 3. Bob descifra el paquete
decrypted_payload: bytes = cipher_bob.decrypt(
    encrypted_package=encrypted_package,
    secret_key=secret_key,
)
assert decrypted_payload == payload  # ✓
```

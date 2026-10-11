---
title: KeyPair
description: Clase KeyPair — propiedades, métodos de serialización (PEM, JSON, Base64) y exportación cifrada de la clave secreta.
sidebar:
  badge:
    text: v1.3.0
    variant: tip
---

La clase `KeyPair` encapsula un par de claves ML-KEM devuelto por [`AegisCipher.generate_keypair()`](/es/api-reference/aegiscipher/#generate_keypair) y [`MlKem.generate_keypair()`](/es/api-reference/mlkem/#generate_keypair). Expone el material público/secreto en crudo como `bytes` y métodos de conveniencia para serializarlos en formatos aptos para transporte.

## Firma de la Clase

```python
class KeyPair:
    # Propiedades
    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

    # Métodos de serialización (v1.3.0)
    def public_key_b64(self) -> str
    def public_key_pem(self) -> str
    def public_key_json(self) -> str
    def export_secret_key_raw(self, password: bytes) -> bytes
    def export_secret_key_pem(self, password: bytes) -> str
```

## Propiedades

### `public_key`

La clave pública ML-KEM como `bytes`. Compartila abiertamente.

| Nivel | Tamaño |
|-------|--------|
| ML-KEM-512 | 800 B |
| ML-KEM-768 | 1184 B |
| ML-KEM-1024 | 1568 B |

### `secret_key`

La clave secreta ML-KEM como `bytes`. **No la comparta ni la registre.** El getter crea una copia inmutable Python. El `KeyPair` expuesto a Python no zeroiza actualmente su buffer secreto Rust al destruirse, y eliminar un objeto `bytes` no garantiza su borrado. Consulte el [modelo de seguridad](/es/internals/security-model/).

| Nivel | Tamaño |
|-------|--------|
| ML-KEM-512 | 1632 B |
| ML-KEM-768 | 2400 B |
| ML-KEM-1024 | 3168 B |

### `level`

El `SecurityLevel` con el que se generó el keypair.

### `__repr__` (v1.4.0 — fingerprint seguro)

El repr omite los bytes de las claves y las longitudes explícitas de los buffers. Incluye el nivel (que determina los tamaños) y un fingerprint público. Ejemplo para ML-KEM-768:

```text
KeyPair(level=MlKem768, fp=<16-hex>)
```

`<16-hex>` son los primeros 8 bytes de `SHA3-256(public_key)` en hexadecimal. Es un identificador truncado estable, no una prueba de identidad; permite correlacionar el uso de la misma clave pública entre logs.

```python
>>> from aegisq import AegisCipher
>>> cipher = AegisCipher()
>>> kp = cipher.generate_keypair()
>>> repr(kp)
"KeyPair(level=MlKem768, fp=a3f1c0b27d4e9f12)"  # Fingerprint ilustrativo
```

## Métodos de Serialización de la Clave Pública

Estos métodos convierten los bytes crudos de `public_key` en strings aptos para transporte. Elegí el formato que mejor se adapte a tu canal.

### `public_key_b64() -> str`

Retorna la clave pública como **Base64 URL-safe sin padding** (RFC 4648 §5). Compacto, URL-safe, sin metadata.

```python
>>> b64 = kp.public_key_b64()
>>> b64
"6BDM8h...snip..."
>>> import base64
>>> roundtrip = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
>>> roundtrip == kp.public_key
True
```

Usalo cuando necesites embeber la clave en headers HTTP, JSON, variables de entorno, o URLs cortas.

### `public_key_pem() -> str`

Retorna la clave pública como un **sobre PEM-like**:

```text
-----BEGIN ML-KEM PUBLIC KEY-----
<Base64 STANDARD de public_key>
-----END ML-KEM PUBLIC KEY-----
```

El cuerpo usa Base64 STANDARD (no URL-safe). El nivel **no está codificado** en el PEM — el llamador debe saber para qué `SecurityLevel` se generó ese PEM. Use [`load_public_key(path, level=...)`](/es/api-reference/key-serialization/#load_public_key) cuando lo lea de vuelta.

### `public_key_json() -> str`

Retorna la clave pública como **JSON auto-descriptivo** con campos `algorithm`, `level` y `public_key` (**Base64 URL-safe sin padding**). El nivel usa el nombre del enum Python, como `ML_KEM_768`.

```json
{
  "algorithm": "ML-KEM",
  "level": "ML_KEM_768",
  "public_key": "6BDM8h...snip..."
}
```

## Métodos de Exportación de la Clave Secreta

:::caution[Los helpers cifran; el acceso crudo sigue disponible]
`export_secret_key_raw()` y `export_secret_key_pem()` cifran con **AES-256-GCM** mediante una clave derivada de `password` con **HKDF-SHA3-256**. Perder esa entrada impide recuperar la exportación cifrada. La propiedad `secret_key` sigue exponiendo bytes en texto plano.

HKDF no es una función de endurecimiento de contraseñas y no ralentiza ataques offline como Argon2 o scrypt. Use bytes secretos de alta entropía de un gestor de secretos o CSPRNG, no una contraseña humana débil. Proteja y conserve ese secreto por separado.
:::

### `export_secret_key_raw(password: bytes) -> bytes`

Retorna la clave secreta cifrada como **blob binario opaco** con un header interno de magic/version. Usalo cuando necesites almacenar la clave en formato binario (bases de datos, stores clave-valor, protocolos custom).

### `export_secret_key_pem(password: bytes) -> str`

Retorna la clave secreta cifrada como **sobre PEM-like**:

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD del blob cifrado>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

El cuerpo usa Base64 STANDARD. Use [`load_secret_key(path, password=...)`](/es/api-reference/key-serialization/#load_secret_key) para descifrar.

## Ejemplo Completo

```python
from aegisq import AegisCipher

cipher = AegisCipher()
keypair = cipher.generate_keypair()

# Bytes crudos (usados internamente)
pk_bytes: bytes = keypair.public_key
sk_bytes: bytes = keypair.secret_key

# Formatos de transporte para la clave pública
b64_string: str = keypair.public_key_b64()      # para headers HTTP / env vars
pem_string: str = keypair.public_key_pem()      # para archivos (.pem)
json_string: str = keypair.public_key_json()    # para archivo / interop

# Exportación cifrada de la clave secreta
import secrets
password: bytes = secrets.token_bytes(32)  # Conservar de forma segura para recuperarla
sk_pem: str = keypair.export_secret_key_pem(password)
sk_blob: bytes = keypair.export_secret_key_raw(password)

# Solo nivel y fingerprint público; considerar correlación entre logs
print(repr(keypair))
# KeyPair(level=MlKem768, fp=a3f1c0b27d4e9f12)
```

## Ver También

- [`AegisCipher.generate_keypair()`](/es/api-reference/aegiscipher/#generate_keypair) — cómo obtener un `KeyPair`
- [`MlKem.generate_keypair()`](/es/api-reference/mlkem/#generate_keypair) — lo mismo, vía la API de bajo nivel
- [Helpers de Serialización de Claves](/es/api-reference/key-serialization/) — `save_*` / `load_*` para persistencia basada en archivos
- [EphemeralSession](/es/api-reference/ephemeral-session/) — keypair de sesión auto-gestionado y límites de ciclo de vida

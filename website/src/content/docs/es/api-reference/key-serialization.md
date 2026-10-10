---
title: Serialización de Claves
description: Persistencia basada en archivos para claves ML-KEM — PEM, JSON y PEM cifrado con claves AES-256-GCM derivadas de contraseña.
sidebar:
  badge:
    text: v1.3.0
    variant: tip
---

El módulo `aegisq.keys` provee helpers de alto nivel para exportar/importar claves desde/hacia disco, variables de entorno y bytes en memoria, construidos sobre [`KeyPair`](/es/api-reference/keypair/).

El módulo es **v1.3.0** y vive en `aegisq/keys.py`. Cada función acepta tanto un string de ruta como un `pathlib.Path`.

## Referencia Rápida

| Función | Dirección | Formato | Cifrado |
|---|---|---|---|
| `save_public_key` | KeyPair → archivo | PEM (default) o JSON | Ninguno |
| `load_public_key` | archivo → bytes | Auto-detecta PEM/JSON | Ninguno |
| `save_secret_key` | KeyPair → archivo | PEM cifrado | AES-256-GCM (HKDF-SHA3-256) |
| `load_secret_key` | archivo → bytes | PEM cifrado | AES-256-GCM (HKDF-SHA3-256) |
| `public_key_to_pem` | KeyPair → str | PEM | Ninguno |
| `public_key_to_json` | KeyPair → str | JSON | Ninguno |
| `secret_key_to_pem` | KeyPair → str | PEM cifrado | AES-256-GCM (HKDF-SHA3-256) |

:::caution[Los helpers cifran; las claves crudas siguen accesibles]
`save_secret_key` y `secret_key_to_pem` cifran las exportaciones; `load_secret_key` devuelve `bytes` en texto plano. Todos requieren `password: bytes`, pero `KeyPair.secret_key` sigue disponible sin contraseña.

HKDF-SHA3-256 no endurece contraseñas. Use bytes secretos de alta entropía, no una contraseña humana débil, y consérvelos de forma segura para recuperar la clave. Los ejemplos usan `secrets.token_bytes(32)`; la aplicación debe guardar ese secreto separado de la clave cifrada.
:::

## Persistencia de Clave Pública

### `save_public_key`

```python
def save_public_key(keypair: KeyPair, path: str | Path, *, fmt: str = "pem") -> None
```

Escribe la clave pública en `path` en formato **PEM** (default) o **JSON**.

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `keypair` | `KeyPair` | — | Keypair fuente. |
| `path` | `str \| Path` | — | Archivo destino. Se recomienda extensión `.pem` para PEM o `.json` para JSON. |
| `fmt` | `str` | `"pem"` | `"pem"` o `"json"`. |

**Lanza:** `ValueError` si `fmt` no es `"pem"` ni `"json"`; `OSError` si no se puede escribir el archivo.

```python
from aegisq import AegisCipher
from aegisq.keys import save_public_key

cipher = AegisCipher()
keypair = cipher.generate_keypair()

# PEM (recomendado para almacenamiento de largo plazo)
save_public_key(keypair, "recipient.pem")

# JSON (auto-descriptivo, útil para interoperabilidad)
save_public_key(keypair, "recipient.json", fmt="json")
```

### `load_public_key`

```python
def load_public_key(path: str | Path, *, level: SecurityLevel | None = None) -> bytes
```

Lee una clave pública desde disco y la retorna como `bytes` (lista para pasar a `AegisCipher.encrypt()`).

**La detección de formato** es automática — la función inspecciona la primera línea no vacía del archivo:

- `-----BEGIN ML-KEM PUBLIC KEY-----` → PEM (el llamador **debe** proveer `level=`)
- `{` → JSON (el nivel se lee del campo `"level"` y el argumento `level` se ignora)

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `path` | `str \| Path` | — | Archivo fuente. |
| `level` | `SecurityLevel \| None` | `None` | Obligatorio para PEM. Ignorado para JSON. |

**Retorna:** `bytes` — la clave pública.

**Lanza:**
- `ValueError` — formato de archivo no reconocible, o archivo PEM sin `level=`
- `KeySerializationError` — PEM/JSON malformado
- `InvalidParameterError` — el tamaño decodificado no coincide con el nivel
- `OSError` — el archivo no se puede leer

```python
from aegisq import SecurityLevel
from aegisq.keys import load_public_key

# Archivo PEM — debés conocer el nivel
pk = load_public_key("recipient.pem", level=SecurityLevel.ML_KEM_768)

# Archivo JSON — el nivel se lee del archivo
pk = load_public_key("recipient.json")
```

## Persistencia de Clave Secreta (Cifrada)

### `save_secret_key`

```python
def save_secret_key(keypair: KeyPair, path: str | Path, *, password: bytes) -> None
```

Cifra la clave secreta con **AES-256-GCM** (clave derivada vía **HKDF-SHA3-256** desde tu `password`) y la escribe como **PEM cifrado**.

El archivo luce así:

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD del blob cifrado>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

El blob contiene `magic || version || level_id || salt (16 B) || nonce (12 B) || ciphertext || tag (16 B)`. El bridge usa `getrandom::fill` para generar salt y nonce frescos y propaga los fallos del RNG; las exportaciones son aleatorias, no garantizadamente distintas.

**Lanza:** `RngError` si el CSPRNG del OS no está disponible; `OSError` si no se puede escribir el archivo.

```python
from aegisq.keys import save_secret_key

import secrets
password = secrets.token_bytes(32)  # Conservar de forma segura para recuperarla
save_secret_key(keypair, "private.key", password=password)
```

### `load_secret_key`

```python
def load_secret_key(path: str | Path, *, password: bytes) -> bytes
```

Lee un archivo PEM cifrado, verifica el auth tag y retorna la clave secreta como `bytes`.

**Lanza:**
- `DecryptionError` — contraseña incorrecta o archivo corrupto
- `KeySerializationError` — header PEM, Base64, o magic/version inválidos
- `OSError` — el archivo no se puede leer

```python
from aegisq.keys import load_secret_key

sk = load_secret_key("private.key", password=password)
plaintext = cipher.decrypt(encrypted_package, sk)
```

:::note[Contraseña incorrecta vs. archivo manipulado]
En un blob estructuralmente válido, una contraseña incorrecta o un ciphertext/tag autenticado manipulado produce `DecryptionError`. Un sobre o header malformado puede producir `KeySerializationError`; no todo archivo corrupto llega a la autenticación.
:::

## Funciones de Conveniencia Solo-String

Estas tres funciones producen o consumen `str` en lugar de archivos, lo cual es útil cuando las claves viven en variables de entorno, secret managers o columnas de bases de datos.

### `public_key_to_pem`

```python
def public_key_to_pem(keypair: KeyPair) -> str
```

Equivalente a `keypair.public_key_pem()`, expuesto aquí para comodidad de import.

### `public_key_to_json`

```python
def public_key_to_json(keypair: KeyPair) -> str
```

Equivalente a `keypair.public_key_json()`, expuesto aquí para comodidad de import.

### `secret_key_to_pem`

```python
def secret_key_to_pem(keypair: KeyPair, *, password: bytes) -> str
```

Equivalente a `keypair.export_secret_key_pem(password)`, expuesto aquí para comodidad de import.

## Ejemplo End-to-End

```python
from aegisq import AegisCipher, SecurityLevel
from aegisq.keys import (
    save_public_key, load_public_key,
    save_secret_key, load_secret_key,
)

# Lado del receptor: generar y persistir
cipher = AegisCipher()
keypair = cipher.generate_keypair()
save_public_key(keypair, "alice.pub.pem", fmt="pem")
import secrets
password = secrets.token_bytes(32)  # Guardar por separado en un gestor de secretos
save_secret_key(keypair, "alice.sec.pem", password=password)

# Más tarde (o en otro proceso): cargar de vuelta
cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
pub = load_public_key("alice.pub.pem", level=SecurityLevel.ML_KEM_768)
sec = load_secret_key("alice.sec.pem", password=password)

# Usar normalmente
package = cipher.encrypt(b"mensaje secreto", pub)
plaintext = cipher.decrypt(package, sec)
assert plaintext == b"mensaje secreto"
```

## Referencia de Formatos

### PEM de Clave Pública

```text
-----BEGIN ML-KEM PUBLIC KEY-----
<Base64 STANDARD de los bytes de public_key>
-----END ML-KEM PUBLIC KEY-----
```

### JSON de Clave Pública

```json
{
  "algorithm": "ML-KEM",
  "level": "ML_KEM_768",
  "public_key": "<Base64 URL-safe sin padding>"
}
```

### PEM Cifrado de Clave Secreta

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD de: magic || version || level_id || salt || nonce || ciphertext || tag>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

El formato interno del blob es un detalle de implementación; trátelo como opaco. El descifrado público desde archivos usa `aegisq.keys.load_secret_key(path, password=...)`; el usuario no debe importar el bridge nativo directamente.

## Ver También

- [`KeyPair`](/es/api-reference/keypair/) — la clase subyacente con bytes crudos y métodos de serialización
- [`MlKem`](/es/api-reference/mlkem/) — API KEM de bajo nivel con `load_public_key_b64`
- [Excepciones](/es/api-reference/exceptions/#keyserializationerror) — `KeySerializationError`, `DecryptionError` lanzadas por estos helpers

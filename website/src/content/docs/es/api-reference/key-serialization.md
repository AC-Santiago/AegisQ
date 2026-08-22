---
title: Serialización de Claves
description: Persistencia basada en archivos para claves ML-KEM — PEM, JSON y PEM cifrado con claves AES-256-GCM derivadas de contraseña.
sidebar:
  badge:
    text: v1.3.0
    variant: tip
---

El módulo `aegisq.keys` provee helpers de alto nivel para exportar/importar claves desde/hacia disco, variables de entorno y bytes en memoria, construidos sobre [`KeyPair`](/api-reference/keypair/).

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

:::caution[Las claves secretas siempre están cifradas]
No hay API para guardar o exportar una clave secreta en texto plano. Las funciones `save_secret_key` / `load_secret_key` / `secret_key_to_pem` todas requieren un argumento `password: bytes` — perderlo significa perder la clave.
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

El cuerpo contiene un header magic/version, un nonce fresco de 12 bytes aleatorio, el ciphertext AES-GCM y un auth tag de 16 bytes. Se genera un nonce fresco por llamada vía `OsRng`, así que guardar el mismo keypair dos veces produce **salidas diferentes**.

**Lanza:** `RngError` si el CSPRNG del OS no está disponible; `OSError` si no se puede escribir el archivo.

```python
from aegisq.keys import save_secret_key

save_secret_key(keypair, "private.key", password=b"s3cr3t p@ssw0rd")
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

sk = load_secret_key("private.key", password=b"s3cr3t p@ssw0rd")
plaintext = cipher.decrypt(encrypted_package, sk)
```

:::note[Contraseña incorrecta vs. archivo manipulado]
Ambos se manifiestan como `DecryptionError`. La verificación del auth tag de AES-GCM es binaria — la única señal que recibe la biblioteca es "válido" o "inválido". Una contraseña incorrecta y un archivo corrupto se ven idénticos para el llamador, por diseño.
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
save_secret_key(keypair, "alice.sec.pem", password=b"hunter2")

# Más tarde (o en otro proceso): cargar de vuelta
cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
pub = load_public_key("alice.pub.pem", level=SecurityLevel.ML_KEM_768)
sec = load_secret_key("alice.sec.pem", password=b"hunter2")

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
  "level": "ML-KEM-768",
  "public_key": "<Base64 STANDARD>"
}
```

### PEM Cifrado de Clave Secreta

```text
-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
<Base64 STANDARD de: magic || version || nonce || ciphertext || tag>
-----END ENCRYPTED ML-KEM PRIVATE KEY-----
```

El formato del blob interno es un detalle de implementación — tratalo como opaco. El descifrado pasa solo por `load_secret_key_pem` / `load_secret_key_raw`.

## Ver También

- [`KeyPair`](/api-reference/keypair/) — la clase subyacente con bytes crudos y métodos de serialización
- [`MlKem`](/api-reference/mlkem/) — API KEM de bajo nivel con `load_public_key_b64`
- [Excepciones](/api-reference/exceptions/#keyserializationerror) — `KeySerializationError`, `DecryptionError` lanzadas por estos helpers

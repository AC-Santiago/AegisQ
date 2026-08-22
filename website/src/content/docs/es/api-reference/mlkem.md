---
title: MlKem
description: API ML-KEM de bajo nivel para operaciones crudas de encapsulación y desencapsulación de claves.
---

`MlKem` expone las operaciones ML-KEM crudas (FIPS 203) para usuarios avanzados que construyen protocolos custom. Si solo necesitás cifrar y descifrar datos, usá [`AegisCipher`](/api-reference/aegiscipher/) en su lugar.

## Firma de la Clase

```python
class MlKem:
    def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
    def generate_keypair(self) -> KeyPair
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]
    def decapsulate(self, capsule: bytes, secret_key: bytes) -> bytes
    def load_public_key_b64(self, b64: str, level: SecurityLevel | None = None) -> bytes
```

## Constructor

```python
MlKem(level: SecurityLevel = SecurityLevel.ML_KEM_768)
```

Crea una nueva instancia de ML-KEM con el nivel de seguridad especificado.

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `level` | `SecurityLevel` | `ML_KEM_768` | El nivel de seguridad ML-KEM a usar |

## Métodos

### `generate_keypair()`

Genera un nuevo keypair ML-KEM para el nivel de seguridad configurado.

**Retorna:** `KeyPair` — Un objeto con los atributos `public_key` (bytes) y `secret_key` (bytes).

### `encapsulate(public_key)`

Realiza la encapsulación ML-KEM: genera una capsule y un shared secret de 32 bytes usando la clave pública del receptor.

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `public_key` | `bytes` | La clave pública ML-KEM del receptor |

**Retorna:** `tuple[bytes, bytes]` — Una tupla `(capsule, shared_secret)`:
- `capsule` — La clave encapsulada (enviala al dueño de la clave)
- `shared_secret` — 32 bytes para usar como clave simétrica

**Lanza:**
- `InvalidParameterError` — Si el tamaño de la clave pública no coincide con el nivel de seguridad
- `RngError` — Si el CSPRNG del OS no está disponible

### `decapsulate(capsule, secret_key)`

Realiza la desencapsulación ML-KEM: recupera el shared secret de 32 bytes desde una capsule usando la clave secreta.

| Parámetro | Tipo | Descripción |
|-----------|------|-------------|
| `capsule` | `bytes` | La capsule proveniente de `encapsulate()` |
| `secret_key` | `bytes` | La clave secreta ML-KEM del receptor |

**Retorna:** `bytes` — El shared secret de 32 bytes

:::caution[Implicit Rejection]
`decapsulate()` **nunca lanza un error** por capsules inválidas. En su lugar, retorna una clave pseudoaleatoria (derivada del seed de rechazo `z` de la clave secreta). Este es el mecanismo de **implicit rejection** definido en FIPS 203 Algorithm 17 — previene ataques CCA2 vía queries de oracle.

Si estás usando `MlKem` directamente, debés manejar este comportamiento vos mismo. `AegisCipher` lo maneja automáticamente: una capsule inválida produce una clave incorrecta para AES-GCM, lo que causa `DecryptionError` en la verificación del tag.
:::

### `load_public_key_b64(b64, level=None)`

```python
def load_public_key_b64(self, b64: str, level: SecurityLevel | None = None) -> bytes
```

Carga una clave pública desde su representación Base64 URL-safe.

| Parámetro | Tipo | Default | Descripción |
|-----------|------|---------|-------------|
| `b64` | `str` | — | String Base64 URL-safe con o sin padding `=`. |
| `level` | `SecurityLevel \| None` | `None` | Nivel de seguridad ML-KEM esperado. Si es `None`, usa el nivel configurado en esta instancia de `MlKem`. |

**Retorna:** `bytes` — Los bytes de la clave pública decodificada.

**Lanza:**
- `AegisQError` — Si el string no es Base64 válido.
- `InvalidParameterError` — Si el tamaño decodificado no corresponde al nivel indicado.

Ejemplo:

```python
>>> kem = MlKem()
>>> keypair = kem.generate_keypair()
>>> b64 = keypair.public_key_b64()
>>> recovered = kem.load_public_key_b64(b64)
>>> recovered == keypair.public_key
True
```

## Ejemplo

```python
from aegisq import MlKem, SecurityLevel

kem = MlKem(level=SecurityLevel.ML_KEM_768)
keypair = kem.generate_keypair()

# Encapsular: produce una capsule + shared secret de 32 bytes
capsule, shared_secret = kem.encapsulate(keypair.public_key)
# capsule        → 1088 bytes — enviar al dueño de la clave
# shared_secret  → 32 bytes  — usar como clave simétrica

# Desencapsular: recupera el mismo shared secret de 32 bytes
recovered = kem.decapsulate(capsule, keypair.secret_key)
assert shared_secret == recovered
```

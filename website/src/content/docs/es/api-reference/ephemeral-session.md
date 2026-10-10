---
title: EphemeralSession
description: Keypairs de sesión auto-generados, cierre y límites de limpieza.
---

## Descripción General

`EphemeralSession` genera un keypair internamente, expone su clave pública y usa la privada para descifrar. Cerrar la sesión la marca como cerrada y descarta su referencia al keypair.

:::caution[Sin garantía de borrado seguro ni forward secrecy]
`close()` no garantiza que se borren todas las copias Rust/Python del secreto. Forward secrecy requiere un protocolo autenticado adecuado y la eliminación segura de claves anteriores; el helper de sesión por sí solo no lo proporciona. Consulte el [modelo de seguridad](/es/internals/security-model/).
:::

```python
from aegisq import EphemeralSession

with EphemeralSession() as session:
    # Solo necesitás la clave pública para cifrar
    package = session.encrypt(
        plaintext=b"Datos secretos",
        recipient_public_key=session.public_key,
    )
    # descifrar mensajes destinados a esta sesión
    plaintext = session.decrypt(package)

# Al salir se cierra la sesión y se descarta su referencia al keypair
```

## Referencia de la API

### Constructor

```python
def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
```

### Propiedades

### `public_key` {#public_key}

Clave pública de solo lectura. No existe un getter público de clave secreta; es encapsulación de API, no protección frente a inspección de código o memoria del proceso. El acceso después del cierre lanza `SessionExpiredError`.

```python
session = EphemeralSession()
print(session.public_key)  # bytes — compartir con el emisor
```

### Métodos

### `encrypt(plaintext, recipient_public_key)` {#encrypt}

```python
def encrypt(self, plaintext: bytes, recipient_public_key: bytes) -> bytes
```

Cifra datos usando el esquema híbrido ML-KEM + AES-256-GCM.

### `decrypt(encrypted_package)` {#decrypt}

```python
def decrypt(self, encrypted_package: bytes) -> bytes
```

Descifra un Transit Package usando la clave secreta efímera.

### `close()` {#close}

```python
def close(self) -> None
```

Marca la sesión como cerrada y descarta su referencia al keypair. Es idempotente. El acceso posterior a `public_key`, `encrypt()` o `decrypt()` lanza `SessionExpiredError`; `level` sigue siendo legible.

## Context Manager

`EphemeralSession` soporta el protocolo de context manager:

```python
with EphemeralSession() as session:
    package = session.encrypt(b"Datos secretos", session.public_key)
    plaintext = session.decrypt(package)
# Se cierra automáticamente la sesión; no se garantiza un borrado completo
```

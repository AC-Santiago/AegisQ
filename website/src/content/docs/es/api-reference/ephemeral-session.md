---
title: EphemeralSession
description: Forward secrecy vía keypairs auto-generados
---

## Descripción General

`EphemeralSession` provee forward secrecy generando un keypair internamente y destruyendo la clave secreta automáticamente al cerrar la sesión.

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

# Al salir del context manager, la clave privada es destruida
```

Esto provee **forward secrecy**: si alguien roba la clave privada guardada, no puede descifrar mensajes anteriores porque las claves efímeras fueron destruidas.

## Referencia de la API

### Constructor

```python
def __init__(self, level: SecurityLevel = SecurityLevel.ML_KEM_768) -> None
```

### Propiedades

### `public_key` {#public_key}

Clave pública de solo lectura. La clave secreta nunca se expone.

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

Cierra la sesión y destruye la clave secreta efímera. Es seguro llamarlo múltiples veces.

## Context Manager

`EphemeralSession` soporta el protocolo de context manager:

```python
with EphemeralSession() as session:
    package = session.encrypt(b"Datos secretos", session.public_key)
    plaintext = session.decrypt(package)
# La clave secreta se destruye automáticamente al salir
```

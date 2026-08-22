---
title: Excepciones
description: Jerarquía de excepciones de AegisQ — tipos de error, cuándo se lanzan y cómo manejarlas.
---

AegisQ define una jerarquía de excepciones que se mapean a modos de falla criptográficos específicos. Todas las excepciones se pueden importar desde el paquete top-level `aegisq`.

## Jerarquía de Excepciones

```text
AegisQError(Exception)                                Excepción base
├── DecapsulationError(AegisQError)                   Error estructural de ML-KEM (tamaño de buffer incorrecto)
├── DecryptionError(AegisQError)                      Falló el auth tag de AES-GCM (manipulado o clave incorrecta)
├── InvalidParameterError(AegisQError, ValueError)    Tamaños de parámetros incorrectos
├── KeySerializationError(AegisQError)                PEM / JSON / magic / version malformados
├── RngError(AegisQError)                             CSPRNG del OS no disponible
└── SessionExpiredError(AegisQError)                  Uso de una EphemeralSession cerrada
```

## Detalle de las Excepciones

### `AegisQError`

La excepción base para todos los errores de AegisQ. Atrapala para manejar cualquier error específico de AegisQ.

### `DecapsulationError`

Se lanza cuando la capsule ML-KEM tiene un tamaño de buffer incorrecto (error estructural). **No** se lanza para contenidos inválidos de la capsule — ver la nota sobre implicit rejection más abajo.

### `DecryptionError`

Se lanza cuando falla la verificación del authentication tag de AES-GCM. Esto significa que:
- El payload cifrado fue **manipulado** en tránsito
- Se usó la **clave secreta incorrecta** para descifrar
- La capsule era **inválida**, lo que causó que ML-KEM devolviera una clave pseudoaleatoria (implicit rejection), que a su vez hace fallar a AES-GCM

### `InvalidParameterError`

Se lanza cuando los tamaños de los parámetros no coinciden con los valores esperados para el nivel de seguridad (por ejemplo, proporcionar una clave pública de 768 bytes cuando ML-KEM-1024 espera 1568 bytes). Hereda tanto de `AegisQError` como de `ValueError`.

### `KeySerializationError`

Lanzada por los helpers de persistencia basados en archivos en [`aegisq.keys`](/api-reference/key-serialization/) cuando un PEM, JSON, magic o version header está malformado o ausente. Se distingue de `DecryptionError` (que se dispara cuando la contraseña es incorrecta): `KeySerializationError` significa que la **estructura** del archivo es inválida, independientemente de la corrección de la contraseña.

### `RngError`

Se lanza cuando el CSPRNG del sistema operativo (Cryptographically Secure Pseudo-Random Number Generator) no está disponible. Esto es extremadamente raro y típicamente indica un problema a nivel del sistema.

### `SessionExpiredError`

Lanzada por [`EphemeralSession`](/api-reference/ephemeral-session/) cuando se llama a `encrypt()` o `decrypt()` después de que la sesión ha sido cerrada (ya sea explícitamente vía `close()` o implícitamente al salir del context manager). La clave secreta efímera ha sido descartada en ese punto, así que la operación no puede proceder.

## Ejemplo de Manejo de Errores

```python
from aegisq import (
    AegisCipher,
    SecurityLevel,
    AegisQError,
    DecryptionError,
    InvalidParameterError,
)

cipher = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher.generate_keypair()

# Cifrar algunos datos
package = cipher.encrypt(b"Datos sensibles", keypair.public_key)

# --- Manejo de errores de descifrado ---
try:
    plaintext = cipher.decrypt(package, keypair.secret_key)
except DecryptionError:
    # Falló el auth tag de AES-GCM: payload manipulado o clave incorrecta
    print("Falló el descifrado: el chequeo de integridad de datos falló")
except InvalidParameterError:
    # Tamaño de clave/paquete incorrecto para este nivel de seguridad
    print("Parámetro inválido: verificá los tamaños de clave y paquete")
except AegisQError:
    # Catch-all para cualquier otro error de AegisQ
    print("Ocurrió un error criptográfico inesperado")
```

:::note[Implicit Rejection]
El `decapsulate()` de ML-KEM **nunca lanza una excepción** por *contenido* inválido de la capsule. En su lugar, devuelve silenciosamente una clave pseudoaleatoria (FIPS 203, Algorithm 17). Cuando se usa `AegisCipher`, esta clave pseudoaleatoria hace fallar al descifrado de AES-GCM, lo que se manifiesta como `DecryptionError`. Este diseño previene ataques de Chosen Ciphertext Attack (CCA) al no revelar si una capsule era válida o inválida.
:::

## Importar Excepciones

Todas las excepciones están disponibles desde el paquete top-level:

```python
from aegisq import (
    AegisQError,
    DecapsulationError,
    DecryptionError,
    InvalidParameterError,
    KeySerializationError,
    RngError,
    SessionExpiredError,
)
```

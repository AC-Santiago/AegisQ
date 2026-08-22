---
title: Context Manager
description: AegisCipher como context manager — zeroización proactiva de cualquier buffer Python-side de sesión al salir.
sidebar:
  badge:
    text: v1.4.0
    variant: tip
---

[`AegisCipher`](/api-reference/aegiscipher/) implementa el **protocolo de context manager** de Python (`__enter__` / `__exit__`). Cuando el bloque `with` termina, cualquier buffer Python-side que se haya registrado durante la sesión es **sobrescrito con ceros in-place** antes de que el objeto cipher retorne a su llamador.

Este es un **hook forward-compatible**: la API pública actual (`encrypt` / `decrypt` / `encrypt_stream` / `decrypt_stream`) no retiene material criptográfico Python-side — el shared secret vive en Rust, envuelto en `Zeroizing`, y se borra cuando cada llamada retorna. El context manager existe para que **futuras APIs con sesión** (por ejemplo, `bind_session`, cifrado multi-mensaje, streams de larga duración) puedan registrar cualquier buffer Python-side persistente y confiar en zeroización determinística al salir, no en el garbage collector.

## Uso Básico

```python
from aegisq import AegisCipher

with AegisCipher() as cipher:
    keypair = cipher.generate_keypair()
    package = cipher.encrypt(b"hola", keypair.public_key)
    plaintext = cipher.decrypt(package, keypair.secret_key)
# Al salir, __exit__ corre y zeroiza cualquier buffer registrado (ninguno hoy).
# Las excepciones dentro del bloque se propagan normalmente.
```

La sentencia `with`:

1. Llama a `__enter__()` — marca la sesión como activa y retorna `self`
2. Ejecuta el cuerpo
3. Llama a `__exit__(exc_type, exc_val, exc_tb)` — realiza la zeroización, luego propaga excepciones

## Comportamiento

| Aspecto | Garantía |
|---------|----------|
| Excepciones | **No se suprimen** — `__exit__` retorna `False`, así que cualquier error dentro del bloque se propaga al llamador después de que la zeroización corra |
| Idempotencia | Llamar a `__exit__` (o `_zeroize_session()`) más de una vez es seguro |
| Uso anidado | Cada `with AegisCipher() as c:` es una sesión fresca; los bloques anidados están permitidos pero cada uno registra buffers independientemente |
| Performance | La zeroización es `O(n)` en el número de buffers registrados y su tamaño total; negligible vs. una sola operación de AES-GCM |

## `__repr__`

`AegisCipher.__repr__` incluye el estado de la sesión:

```python
>>> cipher = AegisCipher()
>>> repr(cipher)
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, inactive)'

>>> with cipher:
...     repr(cipher)
...
'AegisCipher(level=<SecurityLevel.ML_KEM_768>, active)'
```

Esto facilita verificar en logs y `print()` que el cipher está actualmente dentro de una sesión.

## Hook Interno: `_register_session_buffer`

```python
def _register_session_buffer(self, buf: bytearray) -> bytearray
```

Registra un `bytearray` para zeroización proactiva cuando la sesión termina. El buffer se sobrescribe con ceros **in-place**, así que cualquier referencia externa al mismo bytearray también ve ceros — no solo la lista interna.

Esta es una **API interna** (prefijada con `_`). Se expone para que features de sesión futuras de AegisQ puedan registrar sus propios buffers sin esperar un rediseño de API pública.

```python
def _zeroize_session(self) -> None:
    """Sobrescribe todos los buffers registrados con ceros y limpia la lista."""
```

Este método es llamado por `__exit__` y también es seguro llamarlo manualmente (es idempotente).

## ¿Cuándo Importa?

### Hoy (v1.5.0)

Podés usar `with AegisCipher() as cipher:` puramente como un **hábito de documentación / forward-compatibility**. No hay diferencia observable vs. usar el cipher sin `with`. La lifetime del shared-secret ya está controlada por Rust `Zeroizing`.

### APIs de Sesión Futuras

Cuando AegisQ publique APIs que retengan material Python-side entre múltiples llamadas (por ejemplo, una clave de sesión ligada a un peer remoto, o un cipher de streaming cuyo estado de nonce vive en Python), esas APIs llamarán `_register_session_buffer()` internamente. Tus bloques `with` existentes entonces **automáticamente se beneficiarán** sin cambios de código — el buffer registrado se zeroiza al salir.

## Ejemplo Completo con Manejo de Errores

```python
from aegisq import AegisCipher, AegisQError, DecryptionError

cipher = AegisCipher()

# Fuera del with: cipher está "inactive"
print(repr(cipher))  # AegisCipher(level=..., inactive)

try:
    with cipher:  # entra a la sesión
        print(repr(cipher))  # AegisCipher(level=..., active)
        keypair = cipher.generate_keypair()
        # Supongamos que una API futura registra un buffer Python-side acá.
        # (Hoy: nada se registra.)
        package = cipher.encrypt(b"ultra secreto", keypair.public_key)
        plaintext = cipher.decrypt(package, keypair.secret_key)
except DecryptionError:
    # __exit__ corrió antes de que la excepción se propagara → buffers zeroizados
    print("descifrado falló — ya zeroizado")
except AegisQError:
    print("cualquier otro error de AegisQ — ya zeroizado")

# Fuera del with: cipher vuelve a "inactive"
print(repr(cipher))  # AegisCipher(level=..., inactive)
```

## Ver También

- [`AegisCipher`](/api-reference/aegiscipher/) — clase principal, ahora con `__enter__` / `__exit__`
- [`EphemeralSession`](/api-reference/ephemeral-session/) — usa su propio context manager para destruir su keypair efímero
- [Modelo de Seguridad](/internals/security-model/) — garantías más amplias de zeroización

---
title: Context Manager
description: AegisCipher como context manager — zeroización proactiva de cualquier buffer Python-side de sesión al salir.
sidebar:
  badge:
    text: v1.4.0
    variant: tip
---

[`AegisCipher`](/es/api-reference/aegiscipher/) implementa el **protocolo de context manager** de Python (`__enter__` / `__exit__`). Al salir, sobrescribe **con ceros in-place** los buffers mutables registrados con su hook privado, limpia la lista y marca el cipher como inactivo.

Los métodos públicos actuales no registran buffers con este hook. La limpieza del shared secret one-shot se realiza explícitamente en Rust, independientemente de `with`; `hybrid.rs` no usa un wrapper `Zeroizing`. Los generadores de streaming conservan estado nativo durante la iteración.

:::caution[No es un límite de borrado de secretos]
Salir del bloque no borra el `KeyPair` generado, los bytes `secret_key` del llamador, el plaintext ni un generador de streaming suspendido. Tampoco cierra el cipher ni impide nuevas llamadas. Consulte los límites de limpieza en el [modelo de seguridad](/es/internals/security-model/).
:::

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
| Uso anidado | Instancias diferentes tienen listas independientes. Reentrar en la misma instancia comparte su lista; la salida interior la limpia y marca la instancia como inactiva |
| Performance | El trabajo de limpieza escala con el número de buffers más su tamaño total en bytes; no se afirma un benchmark de tiempo |

## `__repr__`

`AegisCipher.__repr__` incluye el estado de la sesión:

```python
>>> cipher = AegisCipher()
>>> repr(cipher)
'AegisCipher(level=SecurityLevel.ML_KEM_768, inactive)'

>>> with cipher:
...     repr(cipher)
...
'AegisCipher(level=SecurityLevel.ML_KEM_768, active)'
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

### Comportamiento actual

`with AegisCipher() as cipher:` cambia el estado mostrado por `repr` e invoca el hook privado de limpieza al salir. No cambia el resultado criptográfico ni borra material del llamador. La limpieza Rust one-shot es independiente del context manager.

### APIs de Sesión Futuras

El hook privado de registro está disponible para uso interno. No es una API pública `bind_session` ni una promesa sobre comportamiento futuro.

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
    print("falló el descifrado — contexto finalizado")
except AegisQError:
    print("otro error de AegisQ — contexto finalizado")

# Fuera del with: cipher vuelve a "inactive"
print(repr(cipher))  # AegisCipher(level=..., inactive)
```

## Ver También

- [`AegisCipher`](/es/api-reference/aegiscipher/) — clase principal, ahora con `__enter__` / `__exit__`
- [`EphemeralSession`](/es/api-reference/ephemeral-session/) — cierra la sesión y descarta la referencia al keypair
- [Modelo de Seguridad](/es/internals/security-model/) — mecanismos y límites de limpieza

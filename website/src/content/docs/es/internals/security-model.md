---
title: Modelo de Seguridad
description: Garantías de seguridad de AegisQ, mecanismos de implementación y limitaciones conocidas.
---

## Garantías de Seguridad

| Propiedad | Garantía | Mecanismo de Implementación |
|-----------|----------|-----------------------------|
| **Seguridad IND-CCA2** | Prob. de ataque ≤ 2⁻¹²⁸ | Implicit rejection en ML-KEM Decaps |
| **Confidencialidad de Datos** | Secreto de payload resistente a quantum | ML-KEM + AES-256-GCM |
| **Integridad y Autenticidad** | Payload a prueba de manipulación | Tag de Autenticación de 128 bits de AES-GCM |
| **Inmunidad a Ataques de Timing** | Sin branches que dependan de secretos | `subtle::ConstantTimeEq`, reducción Barrett |
| **Limpieza de Memoria** | Claves secretas zeroizadas después de uso | `zeroize::Zeroize` en todas las structs sensibles |
| **Overflow de Enteros** | Toda aritmética verificada | `overflow-checks = true` en el perfil release |
| **Unicidad del Nonce** | Sin reuso de nonce | Nonce aleatorio de 96 bits vía `OsRng` por llamada |

## Seguridad IND-CCA2

AegisQ logra seguridad **IND-CCA2** (Indistinguishability under Adaptive Chosen Ciphertext Attack) mediante el mecanismo de implicit rejection de ML-KEM. Cuando la desencapsulación encuentra un ciphertext inválido, retorna una clave pseudoaleatoria derivada de la semilla de rechazo `z` de la clave secreta, en lugar de señalizar un error. Esto previene que los atacantes usen la desencapsulación como oracle.

## Inmunidad a Ataques de Timing

Todas las comparaciones que dependen de secretos usan `subtle::ConstantTimeEq` del crate `subtle`. La aritmética de campo usa reducción Barrett en lugar de división, eliminando variaciones de timing. **No hay branches que dependan de valores secretos** en ninguna parte del código criptográfico.

## Zeroización de Memoria

Todas las estructuras que contienen material secreto implementan `zeroize::Zeroize`:
- Las claves secretas se zeroizan al eliminarse
- Los shared secrets se zeroizan inmediatamente después de usarse en AES-GCM
- Los valores intermedios en las computaciones ML-KEM se zeroizan después de cada operación

Esto previene la recuperación de secretos desde la memoria del proceso después de que las claves ya no se necesitan.

## Protección contra Overflow de Enteros

El perfil release de Cargo establece `overflow-checks = true`, asegurando que toda la aritmética de enteros sea verificada incluso en builds release. Esto previene bugs sutiles en la aritmética de campo (ℤq donde q = 3329) que produzcan resultados incorrectos silenciosamente.

## Limitaciones Conocidas

:::caution[Sin Forward Secrecy por Default]
Si una clave secreta es comprometida, **todos los payloads cifrados con esa clave quedan comprometidos**. Esto es inherente a cualquier mecanismo de intercambio de claves estático.

**Mitigación:** Usá **keypairs efímeros** — generá un keypair nuevo por sesión o por mensaje, transmití la clave pública y descartá la clave secreta después del descifrado. Esto provee forward secrecy asegurando que la comprometida de una clave futura no afecta las sesiones pasadas.
:::

### Contraste del Comportamiento de Errores

Entender cómo se propagan los errores a través del sistema híbrido KEM-DEM es crítico para la seguridad:

| Escenario | ML-KEM Decaps | AES-GCM Decrypt |
|-----------|---------------|-----------------|
| Capsule inválida (bytes incorrectos) | Silencioso: retorna K pseudoaleatoria | N/A |
| Capsule correcta, clave AES incorrecta | N/A (la clave se deriva de la capsule) | Error: `DecryptionError` |
| Auth tag no coincide (payload manipulado) | N/A | Error: `DecryptionError` |
| Todo correcto | Retorna shared secret | Retorna plaintext |

La clave del asunto: el rechazo silencioso de ML-KEM combinado con el error explícito de AES-GCM crea un sistema donde **las capsules inválidas siempre se manifiestan como `DecryptionError`** (porque la clave pseudoaleatoria fallará la verificación del tag de AES-GCM), pero el mensaje de error no revela nada sobre *por qué* la desencapsulación falló.

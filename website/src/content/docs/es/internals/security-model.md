---
title: Modelo de Seguridad
description: Mecanismos de seguridad de AegisQ, supuestos y limitaciones conocidas.
---

## Mecanismos de Seguridad

AegisQ implementa ML-KEM y AES-256-GCM. Su seguridad depende de los supuestos criptográficos, la implementación correcta, la gestión de claves y el entorno de ejecución. Esta página no es una certificación ni una prueba de seguridad de la implementación.

| Propiedad | Mecanismo implementado | Límite |
|-----------|-----------------------|--------|
| Encapsulación de claves | ML-KEM con implicit rejection | No se afirma una probabilidad universal de ataque |
| Confidencialidad e integridad del payload | AES-256-GCM con tag de 128 bits | No autentica la identidad del emisor |
| Defensas de timing | Comparación de capsules y selección de clave en tiempo constante; reducción Barrett | No constituye una auditoría integral de canales laterales |
| Limpieza de memoria | Limpieza explícita del shared secret tras AES one-shot; `Zeroizing` en rutas Rust seleccionadas | No cubre todas las copias ni todas las rutas de error |
| Overflow de enteros | `overflow-checks = true` en release | Las operaciones wrapping intencionales son excepciones explícitas |
| Nonces one-shot | Nonce aleatorio fresco de 96 bits del SO por cifrado | El muestreo aleatorio no garantiza unicidad |

## Seguridad IND-CCA2

ML-KEM está diseñado para seguridad **IND-CCA2** (Indistinguishability under Adaptive Chosen Ciphertext Attack). Si el contenido de una capsule de tamaño correcto es inválido, la desencapsulación devuelve `J(z || c)`, una clave pseudoaleatoria de 32 bytes, en lugar de un error de validez. `J` es SHAKE256 con salida de 32 bytes. Los tamaños incorrectos de clave o capsule son errores estructurales y lanzan `InvalidParameterError` en la API actual.

## Defensas de Timing

`mlkem/decaps.rs` usa `subtle::ConstantTimeEq` para comparar capsules y `ConditionallySelectable` para seleccionar la clave sin una rama dependiente de su validez. La aritmética de campo usa reducción Barrett. Estos mecanismos no demuestran inmunidad de timing para todo el core Rust, el bridge FFI, Python, el compilador o el hardware.

## Zeroización de Memoria

`hybrid.rs` zeroiza explícitamente su buffer de shared secret después de que AES-GCM retorna, incluso ante un fallo de autenticación. Otras rutas Rust usan `Zeroizing`. No es una cobertura completa: por ejemplo, un fallo al generar el nonce en el cifrado one-shot ocurre antes de esa limpieza explícita.

El `KeyPair` expuesto a Python conserva el secreto en un `Vec<u8>` Rust sin zeroización al destruirse en el bridge actual. Su getter `secret_key` crea una copia inmutable Python `bytes`. Ni eliminar esa copia ni salir de `with AegisCipher()` garantiza su borrado. Los intermedios y las copias de ML-KEM también requieren una revisión de ciclo de vida independiente.

El context manager del cipher solo sobrescribe buffers mutables registrados mediante su hook privado. No borra claves del llamador, plaintext ni el estado Rust de un generador de streaming suspendido. Consulte [Context Manager](/es/api-reference/context-manager/).

## Protección contra Overflow de Enteros

El perfil release de Cargo establece `overflow-checks = true`, conservando las comprobaciones de overflow para operaciones ordinarias de enteros. Las operaciones wrapping explícitas evitan esas comprobaciones y deben revisarse por separado; esta opción no demuestra por sí sola la corrección aritmética.

## Limitaciones Conocidas

:::caution[Sin Forward Secrecy por Default]
Si una clave secreta es comprometida, **todos los payloads cifrados con esa clave quedan comprometidos**. Esto es inherente a cualquier mecanismo de intercambio de claves estático.

**Reducción de riesgo:** Use claves independientes por sesión o mensaje y evite conservar claves obsoletas. `EphemeralSession.close()` marca la sesión como cerrada y descarta su referencia al keypair; no garantiza su borrado físico. Forward secrecy requiere además un protocolo autenticado adecuado y la eliminación segura de claves anteriores. El helper de sesión por sí solo no ofrece esa garantía.
:::

Las claves públicas deben obtenerse mediante un canal confiable o autenticado. Cualquiera con una clave pública puede cifrar para su titular; verificar AES-GCM no demuestra la identidad del emisor. AegisQ tampoco proporciona protección contra replay, privacidad de metadatos ni una política de almacenamiento de claves persistentes.

### Contraste del Comportamiento de Errores

Entender cómo se propagan los errores a través del sistema híbrido KEM-DEM es crítico para la seguridad:

| Escenario | ML-KEM Decaps | AES-GCM Decrypt |
|-----------|---------------|-----------------|
| Contenido de capsule inválido, tamaño correcto | Retorna K pseudoaleatoria | Se espera que falle la verificación del tag |
| Tamaño incorrecto de clave/capsule o paquete demasiado corto | Error estructural (`InvalidParameterError`) | No se alcanza |
| Capsule correcta, clave AES incorrecta | N/A (la clave se deriva de la capsule) | Error: `DecryptionError` |
| Auth tag no coincide (payload manipulado) | N/A | Error: `DecryptionError` |
| Todo correcto | Retorna shared secret | Retorna plaintext |

Los fallos de autenticación de AES-GCM se manifiestan como `DecryptionError`, sin una señal independiente de validez de la capsule. Los errores estructurales siguen siendo distintos. Estos mecanismos no sustituyen la revisión del protocolo ni una auditoría de seguridad independiente.

---
title: Hybrid KEM-DEM
description: Cómo AegisQ combina la encapsulación de claves ML-KEM con el cifrado de datos AES-256-GCM.
---

AegisQ implementa una arquitectura **Hybrid KEM-DEM**. ML-KEM no puede cifrar payloads grandes directamente — solo produce un shared secret de 32 bytes. AegisQ lo combina con AES-256-GCM como mecanismo de encapsulación de datos (DEM).

## El Enfoque Híbrido

1. **ML-KEM (KEM):** Genera un shared secret de 32 bytes, resistente a quantum
2. **AES-256-GCM (DEM):** Usa ese secret de 32 bytes como clave simétrica para cifrar el payload real con cifrado autenticado (confidencialidad + integridad)

## Propiedades de AES-256-GCM

| Propiedad | Valor |
|-----------|-------|
| Tamaño de clave | 256 bits (32 bytes) — del shared secret de ML-KEM |
| Nonce (IV) | 96 bits (12 bytes) — aleatorio por operación vía `OsRng` |
| Authentication Tag | 128 bits (16 bytes) |
| Seguridad | IND-CPA + INT-CTXT (cifrado autenticado) |

Una vez que ML-KEM genera el shared secret `K` de 32 bytes, AegisQ lo alimenta directamente a AES-256-GCM como clave de cifrado simétrico. No se necesita un KDF adicional — la salida de 32 bytes de ML-KEM ya es uniformemente aleatoria y del tamaño correcto para AES-256.

## Manejo del Nonce — Regla Crítica

:::caution[Unicidad del Nonce]
Un nonce **NUNCA** debe reutilizarse con la misma clave. `encrypt()` one-shot genera un nonce aleatorio fresco de 96 bits mediante el wrapper local `OsRng`, respaldado por `getrandom::fill`. Los fallos del RNG se propagan. El muestreo aleatorio reduce el riesgo de colisión, pero no garantiza unicidad.

Para `n` nonces aleatorios independientes **bajo la misma clave**, la aproximación de cumpleaños es `n(n−1) / 2^97`; con `n = 2^32` resulta aproximadamente `1.16 × 10⁻¹⁰`. Cada llamada one-shot realiza una nueva encapsulación ML-KEM; este cálculo no afirma que las llamadas reutilicen una clave AES. Streaming usa otro esquema de nonces indexados; consulte [Cifrado en Streaming](/es/api-reference/streaming/).
:::

## Ensamblado del Transit Package

El módulo `hybrid.rs` en `aegisq-core` es responsable de ensamblar y parsear el Transit Package.

### Estructura del Transit Package

El array de bytes final `encrypted_package` tiene esta estructura fija:

```text
[ ML-KEM Capsule (var) | AES Nonce (12 bytes) | AES Auth Tag (16 bytes) | Ciphertext (var) ]
```

Donde el tamaño de `ML-KEM Capsule` depende del nivel de seguridad:
- ML-KEM-512: 768 bytes
- ML-KEM-768: 1088 bytes
- ML-KEM-1024: 1568 bytes

### Flujo de Cifrado

1. Llamar `kem::encapsulate(public_key, level)` → resultado con capsule y shared secret
2. Generar nonce aleatorio de 12 bytes vía `OsRng`
3. Llamar `aes_gcm::encrypt(key=shared_secret, nonce, plaintext)` → `(tag, ciphertext)`
4. **Zeroizar `shared_secret` inmediatamente**
5. Ensamblar y retornar: `capsule || nonce || tag || ciphertext`

### Flujo de Descifrado

1. Dividir el Transit Package por offsets conocidos (capsule_size, luego 12, 16, resto)
2. Llamar `kem::decapsulate(capsule, secret_key, level)` → `shared_secret_32B`
3. Llamar `aes_gcm::decrypt(key=shared_secret, nonce, tag, ciphertext)` → `plaintext` o `Err`
4. **Zeroizar `shared_secret` inmediatamente**
5. Si la verificación del tag falla → retornar `Err(AegisQError::DecryptionFailed)`

## Contraste del Comportamiento de Errores

| Escenario | ML-KEM Decaps | AES-GCM Decrypt |
|-----------|---------------|-----------------|
| Contenido inválido, tamaño de capsule correcto | Retorna K pseudoaleatoria | Se espera que falle la verificación del tag |
| Tamaño incorrecto de clave/capsule o paquete demasiado corto | Error estructural (`InvalidParameterError`) | No se alcanza |
| Capsule correcta, clave AES incorrecta | N/A (la clave se deriva de la capsule) | Error: `DecryptionError` |
| Auth tag no coincide (payload manipulado) | N/A | Error: `DecryptionError` |
| Todo correcto | Retorna shared secret | Retorna plaintext |

:::note
A diferencia del rechazo silencioso de ML-KEM, una falla en el auth tag de AES-GCM **siempre** lanza `DecryptionError`. Este es el comportamiento correcto — le dice al llamador que el payload fue manipulado o que se usó la clave incorrecta, sin revelar nada sobre el paso de desencapsulación ML-KEM.
:::

## API Interna de Rust

```rust
use aegisq_core::{hybrid, kem::SecurityLevel};

// Hybrid encrypt: ML-KEM encaps + AES-256-GCM
let encrypted_package: Vec<u8> = hybrid::encrypt(
    recipient_public_key,
    plaintext,
    SecurityLevel::MlKem768,
)?;

// Hybrid decrypt: ML-KEM decaps + AES-256-GCM verify + decrypt
let plaintext: Vec<u8> = hybrid::decrypt(
    &encrypted_package,
    secret_key,
    SecurityLevel::MlKem768,
)?;
```

:::note[OsRng]
`OsRng` es un wrapper local de `getrandom::fill`, no `rand_core::OsRng`. El llamador no pasa un RNG. `getrandom` selecciona el backend de la plataforma; sus fallos se convierten en `AegisQError::RngError`. La limpieza tras AES-GCM no implica el borrado completo de buffers ni de rutas de error temprano; consulte el [modelo de seguridad](/es/internals/security-model/).
:::

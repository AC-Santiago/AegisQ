---
title: Glosario
description: Glosario de términos criptográficos y específicos de AegisQ, más referencias a los estándares utilizados.
---

## Términos Criptográficos

| Término | Definición |
|---------|------------|
| **KEM** | Key Encapsulation Mechanism — establece un shared secret usando criptografía asimétrica. ML-KEM es el KEM resistente a quantum que se usa acá. |
| **DEM** | Data Encapsulation Mechanism — cifrado simétrico para el payload real. AES-256-GCM es el DEM que se usa acá. |
| **AEAD** | Authenticated Encryption with Associated Data — provee confidencialidad e integridad. AES-GCM es un esquema AEAD. |
| **AAD** | Additional Authenticated Data — input al cómputo del tag de AES-GCM que **no** se cifra pero **sí** se autentica. En el streaming de AegisQ, el AAD es el índice de chunk de 4 bytes big-endian. |
| **M-LWE** | Module Learning With Errors — el problema hard de retículos subyacente a la resistencia cuántica de ML-KEM. |
| **NTT** | Number Theoretic Transform — FFT sobre campos finitos para multiplicación polinomial en O(n log n). |
| **CBD** | Centered Binomial Distribution — se usa para muestrear términos de error pequeños en la generación de claves de ML-KEM. |
| **Implicit Rejection** | ML-KEM Decaps retorna una clave pseudoaleatoria (no un error) cuando la capsule es inválida. Previene ataques CCA vía oracle. |
| **Transit Package** | El array de bytes completo que se envía por la red: `[Capsule \| Nonce \| Tag \| Ciphertext]`. |
| **Zeroización** | Sobrescritura segura de memoria sensible (claves, secretos) con ceros antes de la desasignación. |
| **Auth Tag** | MAC criptográfico de 16 bytes de AES-GCM. Un mismatch de tag significa que el ciphertext fue manipulado. |
| **Forward Secrecy** | Propiedad de que la comprometida de un secreto de largo plazo no compromete las claves de sesión pasadas. La [`EphemeralSession`](/api-reference/ephemeral-session/) de AegisQ logra esto destruyendo cada clave efímera después de usarla. |

## Términos de Cifrado en Streaming (v1.5.0)

| Término | Definición |
|---------|------------|
| **Header** | Primer chunk del Transit Package en modo stream: `[capsule \| base_nonce (12 B) \| chunk_size (4 B BE u32)]`. |
| **Frame** | Sobre de un chunk en el Transit Package en modo stream: `[length (4 B BE u32) \| ciphertext \| tag (16 B)]`. |
| **base_nonce** | El nonce aleatorio de 12 bytes almacenado en el header del stream. Los nonces de cada chunk se derivan de este. |
| **chunk_size** | Tamaño máximo de ciphertext por chunk producido (1..=16 MiB; default 64 KiB). Codificado en el header. |
| **EOF Marker** | Frame especial con `length = 0` y un tag sobre plaintext vacío. Cierra el stream. |
| **Chunk Index** | Posición 0-based de un frame en el stream (uint32). Usado en la derivación del nonce y en el AAD. |

## Términos de Serialización de Claves (v1.3.0)

| Término | Definición |
|---------|------------|
| **PEM** | Sobre Privacy-Enhanced Mail: clave ASCII-armored con headers `-----BEGIN ... -----` / `-----END ... -----`. AegisQ usa una forma adaptada (RFC 7468). |
| **JSON Key** | Formato de clave auto-descriptivo con campos `algorithm`, `level` y `public_key`. Útil cuando el nivel no se puede transmitir fuera de banda. |
| **Base64 URL-safe** | Variante de Base64 que usa `-` y `_` en lugar de `+` y `/`, y omite el padding `=`. Adecuado para headers HTTP, URLs y variables de entorno. |
| **HKDF** | HMAC-based Key Derivation Function (RFC 5869). AegisQ usa HKDF-SHA3-256 para derivar una clave AES desde una contraseña provista por el usuario. |
| **Key Wrap** | Cifrar una clave bajo otra clave. AegisQ usa AES-256-GCM con una clave derivada vía HKDF-SHA3-256 desde una contraseña. |
| **Fingerprint** | Identificador estable y no reversible para una clave pública: primeros 8 bytes de `SHA3-256(public_key)` en hex. Usado por `KeyPair.__repr__` (v1.4.0) para loguear sin filtrar bytes crudos. |
| **Magic** | Secuencia de bytes interna que marca un blob de clave cifrada de AegisQ. Validada al cargar para detectar mismatch de formato. |

## Referencias

### Estándares y Librerías

| Documento | URL |
|-----------|-----|
| FIPS 203 (ML-KEM) | https://csrc.nist.gov/pubs/fips/203/final |
| NIST SP 800-38D (AES-GCM) | https://csrc.nist.gov/pubs/sp/800/38/d/final |
| RFC 5869 (HKDF) | https://www.rfc-editor.org/rfc/rfc5869 |
| RFC 4648 (Base64) | https://www.rfc-editor.org/rfc/rfc4648 |
| RFC 7468 (PEM) | https://www.rfc-editor.org/rfc/rfc7468 |
| CRYSTALS-Kyber spec v3.02 | https://pq-crystals.org/kyber/ |
| Crate aes-gcm de Rust | https://docs.rs/aes-gcm |
| Crate zeroize de Rust | https://docs.rs/zeroize |
| Crate subtle de Rust | https://docs.rs/subtle |
| PyO3 User Guide | https://pyo3.rs/latest/ |
| Documentación de Maturin | https://www.maturin.rs/ |
| Documentación de Starlight | https://starlight.astro.build/ |

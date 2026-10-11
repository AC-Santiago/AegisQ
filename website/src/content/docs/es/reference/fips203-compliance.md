---
title: Compliance FIPS 203
description: Referencias normativas, límites de implementación, dependencias y alcance de los vectores de prueba.
---

## Alcance de la implementación

AegisQ implementa ML-KEM para encapsular claves y AES-256-GCM para cifrado autenticado. Las versiones publicadas están en [PyPI](https://pypi.org/project/aegisq-pqc/); los manifiestos declaran la versión del checkout. El historial se mantiene en [CHANGELOG.md](https://github.com/AC-Santiago/AegisQ/blob/main/CHANGELOG.md).

:::caution[Implementación no significa certificación]
FIPS 203 especifica ML-KEM. Implementarlo y ejecutar tests de respuesta conocida no constituye una validación ACVP oficial, certificación FIPS 140 del módulo ni una auditoría independiente de AegisQ. El formato de frames de streaming y los sobres PEM-like de ML-KEM son formatos de AegisQ, no estándares definidos por las referencias siguientes.
:::

- [Fundamento matemático](/es/internals/mathematical-foundation/) explica las primitivas y parámetros de ML-KEM.
- [Híbrido KEM-DEM](/es/internals/hybrid-kem-dem/) describe el paquete de tránsito one-shot.
- [Serialización de claves](/es/api-reference/key-serialization/) y [streaming](/es/api-reference/streaming/) describen los formatos y derivación propios de AegisQ.
- [Modelo de seguridad](/es/internals/security-model/) distingue las defensas implementadas de las garantías que la biblioteca no ofrece.

## Cumplimiento de Estándares

| Estándar | Descripción |
|----------|-------------|
| [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) | ML-KEM — Module-Lattice-Based Key-Encapsulation Mechanism (NIST, 2024) |
| [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) | AES-GCM — Especificación de Galois/Counter Mode |
| [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) | HMAC-based Extract-and-Expand Key Derivation Function (HKDF) |
| [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648) | Encodings Base16, Base32, Base64 (usado para cuerpos PEM y claves Base64 URL-safe) |
| [RFC 7468](https://www.rfc-editor.org/rfc/rfc7468) | Encodings textuales de estructuras PKIX, PKCS y CMS (formato PEM adaptado para ML-KEM) |
| [PEP 561](https://peps.python.org/pep-0561/) | Distribución y empaquetado de información de tipos (AegisQ incluye `py.typed` + stubs `.pyi`) |

## Dependencias Rust

Las versiones son requisitos de los manifiestos actuales, no resoluciones exactas del lockfile ni un inventario de una versión publicada. Las declaraciones compartidas viven en `Cargo.toml`; PyO3 y Criterion están en los manifiestos del bridge/core. `Cargo.lock` registra las versiones resueltas.

| Crate | Versión | Propósito | `no_std` |
|-------|---------|-----------|----------|
| `aes-gcm` | 0.11 | AES-256-GCM cifrado autenticado (hardware AES-NI) | ✅ |
| `sha3` | 0.12 | SHA3-256/512 para ML-KEM | ✅ |
| `shake` | 0.1 | Variantes XOF movidas fuera de `sha3` upstream (RustCrypto/XOFs split) | ✅ |
| `zeroize` | 1.9 | Limpieza de buffers sensibles seleccionados | ✅ |
| `subtle` | 2.6 | Comparaciones en tiempo constante | ✅ |
| `getrandom` | 0.4 | Aleatoriedad del SO para nonces y keygen | ✅ |
| `base64` | 0.23 | Encoding del cuerpo PEM | ✅ |
| `thiserror` | 2.0 | Definiciones de tipos de error | ✅ |
| `pyo3` | 0.29 | Bindings Rust-Python FFI (`abi3-py311`) | — |
| `criterion` (dev) | 0.5 | Benchmarks para operaciones NTT y KEM | — |

Todos los crates criptográficos son compatibles con `no_std`. `pyo3` y `criterion` están excluidos — se usan solo en las capas de FFI y dev-dependency respectivamente.

## Vectores de Prueba NIST ACVP

AegisQ verifica su implementación de ML-KEM contra los vectores de prueba oficiales del NIST ACVP (Automated Cryptographic Validation Program):

- **KeyGen** — `tests/python/json-files/ML-KEM-keyGen-FIPS203/`
- **Encap/Decap** — `tests/python/json-files/ML-KEM-encapDecap-FIPS203/`

`tests/python/test_kat_vectors.py` compara explícitamente las salidas esperadas de KeyGen y encapsulación byte por byte. No invoca la desencapsulación ni verifica las salidas esperadas de desencapsulación/rechazo del corpus combinado. `tests/python/test_kem_api.py` comprueba roundtrips por separado y `tests/python/test_implicit_rejection.py` cubre contenido inválido de capsules. Esos tests no sustituyen los tests de respuesta conocida de desencapsulación.

Superar estos tests aporta evidencia de corrección para las entradas comprobadas, no una prueba de seguridad, cobertura exhaustiva ni certificación oficial. Cualquier afirmación de éxito debe referirse a una ejecución real con el código y la extensión nativa correspondientes.

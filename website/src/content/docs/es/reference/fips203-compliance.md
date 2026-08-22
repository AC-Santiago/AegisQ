---
title: Compliance FIPS 203
description: Roadmap de implementación, cumplimiento de estándares e inventario de dependencias Rust de AegisQ hasta v1.5.0.
---

## Roadmap de Implementación

AegisQ fue desarrollado en fases. Cada fase debía pasar todos sus tests antes de avanzar a la siguiente. La release estable actual es **v1.5.0**; `develop` está rastreando **v1.6.0-rc1** (la próxima prerelease).

### v1.0–v1.2 — Core FIPS 203 ML-KEM + Hybrid KEM-DEM

| Fase | Componente | Referencia | Estado |
|------|------------|------------|--------|
| 1 | Aritmética de campo (ℤq) y reducción Barrett | FIPS 203 §4.2 | ✅ |
| 2 | NTT y NTT inversa | FIPS 203 §4.3 | ✅ |
| 3 | Operaciones polinomiales | FIPS 203 §4.1 | ✅ |
| 4 | Compress / Decompress | FIPS 203 §4.2.1 | ✅ |
| 5 | Módulo de parámetros | FIPS 203 §5 | ✅ |
| 6 | Muestreo CBD y XOF | FIPS 203 §4.1, §4.2.2 | ✅ |
| 7 | KeyGen (Algorithm 15) | FIPS 203 Alg. 15 | ✅ |
| 8 | Encaps (Algorithm 16) | FIPS 203 Alg. 16 | ✅ |
| 9 | Decaps con implicit rejection | FIPS 203 Alg. 17 | ✅ |
| 10 | API pública KEM (`kem.rs`) | — | ✅ |
| 11 | AES-256-GCM Hybrid (`hybrid.rs`) | NIST SP 800-38D | ✅ |
| 12 | Tipos de error FFI | — | ✅ |
| 13 | Tipos PyO3 (KeyPair, SecurityLevel) | — | ✅ |
| 14 | Bindings PyO3 KEM | — | ✅ |
| 15 | Bindings PyO3 Hybrid | — | ✅ |
| 16 | Registro del módulo PyO3 | — | ✅ |
| 17 | Excepciones Python | — | ✅ |
| 18 | Stubs de tipo Python | PEP 561 | ✅ |
| 19 | API Python KEM (`MlKem`) | — | ✅ |
| 20 | API Python de alto nivel (`AegisCipher`) | — | ✅ |
| 21 | Exports del paquete Python | — | ✅ |
| 22 | Tests del bridge KEM | — | ✅ |
| 23 | Tests del bridge Hybrid | — | ✅ |
| 24 | Tests end-to-end de AegisCipher | — | ✅ |
| 25 | Tests API KEM + vectores NIST KAT | — | ✅ |
| 26 | GitHub Actions CI/CD | — | ✅ |
| 27 | Archivos JSON con vectores NIST ACVP KAT | vectores NIST | ✅ |
| 27b | Tests de verificación de vectores KAT | vectores NIST | ✅ |
| 28 | EphemeralSession (forward secrecy) | — | ✅ |
| 29 | Soporte async (`encrypt_async`, `decrypt_async`) | — | ✅ |

### v1.3.0 — KDF, Key Wrap y Serialización de Claves

| Fase | Componente | Referencia | Estado |
|------|------------|------------|--------|
| 30 | HKDF-SHA3-256 + AES-256-GCM key wrap (`kdf.rs`, `key_wrap.rs`) | RFC 5869, NIST SP 800-38D | ✅ |
| 31 | Serialización de claves: PEM, JSON, PEM cifrado (`key_io_bindings.rs`, `aegisq/keys.py`) | RFC 7468 (adaptado) | ✅ |

### v1.4.0 — Safe Repr, Context Manager, Cobertura de Implicit Rejection

| Fase | Componente | Referencia | Estado |
|------|------------|------------|--------|
| 32 | `KeyPair.__repr__` con fingerprint + context manager de `AegisCipher` + suite de regresión de `__repr__` de 25 casos + suite de regresión de implicit-rejection de 25 casos (FIPS 203 §7.3) | FIPS 203 §7.3 | ✅ |

### v1.5.0 — Streaming + Benchmarks

| Fase | Componente | Referencia | Estado |
|------|------------|------------|--------|
| 33a | Cifrado/descifrado en streaming (`stream.rs`, `stream_bindings.rs`, `encrypt_stream` / `decrypt_stream`) | NIST SP 800-38D §5.2 (AEAD basado en frames) | ✅ |
| 33b | Benchmarks de Criterion para NTT y KEM (`benches/ntt.rs`, `benches/kem.rs`) | — | ✅ |

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

Las versiones reflejan la release **v1.5.0**. Las declaraciones del workspace viven en `Cargo.toml`.

| Crate | Versión | Propósito | `no_std` |
|-------|---------|-----------|----------|
| `aes-gcm` | 0.11 | AES-256-GCM cifrado autenticado (hardware AES-NI) | ✅ |
| `sha3` | 0.12 | SHA3-256/512 y SHAKE-128/256 para ML-KEM | ✅ |
| `shake` | 0.1 | Variantes XOF movidas fuera de `sha3` upstream (RustCrypto/XOFs split) | ✅ |
| `zeroize` | 1.9 | Borrado seguro de memoria de secretos | ✅ |
| `subtle` | 2.6 | Comparaciones en tiempo constante | ✅ |
| `getrandom` | 0.4 | CSPRNG a nivel del SO (`OsRng`) para nonces y keygen | ✅ |
| `base64` | 0.23 | Encoding del cuerpo PEM | ✅ |
| `thiserror` | 2.0 | Definiciones de tipos de error | ✅ |
| `pyo3` | 0.29 | Bindings Rust-Python FFI (`abi3-py311`) | — |
| `criterion` (dev) | 0.5 | Benchmarks para operaciones NTT y KEM | — |

Todos los crates criptográficos son compatibles con `no_std`. `pyo3` y `criterion` están excluidos — se usan solo en las capas de FFI y dev-dependency respectivamente.

## Vectores de Prueba NIST ACVP

AegisQ verifica su implementación de ML-KEM contra los vectores de prueba oficiales del NIST ACVP (Automated Cryptographic Validation Program):

- **KeyGen** — `tests/python/json-files/ML-KEM-keyGen-FIPS203/`
- **Encap/Decap** — `tests/python/json-files/ML-KEM-encapDecap-FIPS203/`

El test runner `tests/python/test_kat_vectors.py` parsea cada vector JSON y verifica igualdad bit-a-bit entre la salida de la implementación y los bytes esperados. Esta es la señal de correctitud más fuerte posible — correr AegisQ contra los mismos vectores que NIST usa para certificar implementaciones de referencia.

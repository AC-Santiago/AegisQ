# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

---

## [Unreleased]

---

<<<<<<< HEAD
## [1.4.0] - 2026-08-19

### Added
- **`AegisCipher` como context manager** — Implementa `__enter__` /
  `__exit__` con zeroización proactiva de cualquier buffer Python-side
  registrado durante la sesión. Hook interno
  `_register_session_buffer(buf)` disponible para futuras APIs que
  retengan material criptográfico Python-side (binding de sesión,
  streaming). `__repr__` ahora muestra estado `active` / `inactive`.
- **`KeyPair.__repr__` seguro** — Muestra solo el nivel de seguridad
  y un fingerprint público de la clave (primeros 8 bytes de
  `SHA3-256(public_key)` en hex). Nunca expone bytes crudos ni
  tamaños de claves (los tamaños facilitaban ataques de correlación
  entre instancias).
- **`public_key_fingerprint(public_key)` en `aegisq_core::kem`** —
  Nueva función pública Capa 1 que computa `SHA3-256(pk)[:8]`. Útil
  para logging y debugging sin filtrar material criptográfico.

### Tests
- **Cobertura explícita de Implicit Rejection (FIPS 203 §7.3)** —
  `tests/python/test_implicit_rejection.py` agrega 25 nuevas
  aserciones cubriendo: nunca lanza al flipar cualquier byte del
  capsule (3 niveles), independencia estadística de 64 tamperings
  distintos, determinismo (mismo input → mismo output), wrong secret
  key, y el path vía `AegisCipher` (Transit Package manipulado solo
  levanta `DecryptionError` del tag AES-GCM, nunca `DecapsulationError`).
- **Cobertura de `KeyPair.__repr__`** —
  `tests/python/test_keypair_repr.py` agrega 25 nuevas aserciones
  verificando formato, fingerprint determinístico, no-leaks de bytes
  crudos del secret_key ni del public_key, no-leaks de Base64 ni de
  las formas serializadas (PEM, JSON), y tamaño del repr acotado.

---

=======
>>>>>>> origin/main
## [1.3.1] - 2026-08-19

### Changed
- **Dependencias Rust actualizadas (rust-crypto group)**:
  - `pyo3` 0.29.0 → 0.29.2 (fix de regresión PyPy 3.11 + leaks de refcount).
  - `zeroize` 1.8.2 → 1.9.0.
  - `sha3` 0.11.0 → 0.12.0. **Breaking interno:** SHAKE-128/256 se
    separaron del crate `sha3` al nuevo crate `shake` 0.1.0 mantenido
    bajo [RustCrypto/XOFs](https://github.com/RustCrypto/XOFs). El
    código AegisQ de `mlkem/sampling.rs` se migró a
    `use shake::{Shake128, Shake256}`; la API de `.default()` /
    `.update()` / `.finalize_xof()` / `.read()` no cambia.
  - `aes-gcm` 0.10.3 → 0.11.0. `Nonce::from_slice` deprecado en favor
    de `Nonce::try_from(...).map_err(...)?`; los 4 sitios en
    `hybrid.rs` y `key_wrap.rs` se actualizaron.
  - `thiserror` 2.0.18 → 2.0.19 (bump transitivo de `syn`).
  - `base64` 0.22.1 → 0.23.1. Sin cambios de código: `simd-unsafe`
    queda off porque seguimos con `default-features = false` +
    `features = ["alloc"]`.

### Fixed
- **SIGILL del runner Ubuntu en `clippy-driver`** — `target-cpu=native`
  causaba que rustc 1.96 emitiera instrucciones que el microcode del
  nuevo image `ubuntu-24.04 / 20260810.271` rechaza. Reemplazado por
  `target-cpu=x86-64-v3`, nivel estable de microarquitectura que
  incluye exactamente AES-NI, PCLMULQDQ, AVX2, BMI2 y SSE4.2 (lo que
  AegisQ necesita). El crate `aes` sigue acelerando AES-GCM en runtime
  via `cpufeatures`, así que no se pierde rendimiento por hardware.
- **Governance de CI** — `.github/workflows/ci.yml` ahora también
  dispara en PRs contra `develop` (antes solo contra `main`). Cierra
  el hueco que dejó pasar 24 diffs de `rustfmt` en `develop` desde
  v1.3.0 sin que CI se enterara.
- **`cargo fmt --all -- --check`** vuelve a estar limpio en `develop`
  (los archivos de v1.3.0 fueron re-formateados al estilo de
  `rustfmt` 1.9.0; sin cambios de semántica).

---

## [1.3.0] - 2026-06-26

### Added
- **Serializacion de llaves** — Exportar/importar llaves en formatos estandar:
  - Llave publica: PEM-like (`-----BEGIN ML-KEM PUBLIC KEY-----`) y JSON
    (con campos `algorithm`/`level`/`public_key`).
  - Llave privada: blob binario cifrado con contrasena, opcionalmente envuelto en
    PEM ENCRYPTED (`-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----`).
- **Cifrado de llaves secretas**: AES-256-GCM con clave derivada via HKDF-SHA3-256
  (HMAC-SHA3-256 manual, block size 136 bytes per NIST SP 800-185).
- **Modulo `aegisq.keys`** — API de alto nivel para persistencia:
  `save_public_key`, `load_public_key`, `save_secret_key`, `load_secret_key`,
  `public_key_to_pem/json`, `secret_key_to_pem`.
- **Excepcion `KeySerializationError`** — Para PEM/JSON/blob malformados.
- **Tests pytest**: 19 nuevos tests en `tests/python/test_key_serialization.py`
  cubriendo roundtrip en los 3 niveles, deteccion de formato, errores de
  parsing, y verificacion critica de seguridad (secret_key raw NO aparece en PEM).
- **`deny.toml`** — Configuracion de `cargo-deny` (gate de licencias, bans,
  sources, advisories en CI).

### Changed
- **`pyo3` 0.28.3 → 0.29.0** — Fix de RUSTSEC-2026-0177 (missing `Sync` bound
  en `PyCFunction::new_closure`).
- **`aegisq-pyo3` agrega `getrandom` y `base64` como deps directas** —
  necesarias para generar salt/nonce (Capa 2) y codificar Base64 STANDARD
  (formato PEM).

### Security
- **Llaves secretas NUNCA se exportan en texto plano** — siempre cifradas
  con AES-256-GCM (clave derivada via HKDF-SHA3-256).
- **HMAC-SHA3-256 implementado manualmente** — block size correcto = 136 bytes
  (rate del sponge Keccak), verificado contra Python `hashlib.sha3_256` stdlib.
- **Wrong password en `unwrap_secret_key`** retorna `DecryptionFailed`
  (indistinguible de blob corrupto — anti side-channel).
- **`cargo-deny` como gate en CI** — bloquea licenses no aprobadas (GPL/LGPL/AGPL),
  crates prohibidos (`ring`, `openssl`, `openssl-sys`), y sources fuera de crates.io.

---

## [1.2.0] - 2026-05-21

### Added
- **`deny.toml`** — Configuración de `cargo-deny` para auditoria continua de dependencias:
  - Lista explícita de licencias permitidas
  - Baneo de crates problemáticos (openssl, native-tls, unknown-registry)
  - Skip entries para dependencias WASM transitivas inevitables
- **`MlKem.load_public_key_b64(b64, level=None)`** — Carga de llave pública desde string Base64 URL-safe
- **`KeyPair.public_key_b64()`** — Método que serializa la llave pública a Base64 URL-safe (sin padding)
- Serialización Base64 URL-safe (RFC 4648 §5) para llaves públicas ML-KEM en los tres niveles de seguridad

### Changed
- **`cargo-audit`** → `actions-rust-lang/audit@v1` en CI (mejora rendimiento macOS)
- **GitHub Actions** actualizadas:
  - `actions/checkout`: v5 → v6
  - `actions/upload-artifact`: v4 → v7
  - `actions/download-artifact`: v4 → v8
- **Dependencias Rust** actualizadas:
  - `sha3`: 0.10 → 0.11
  - `pyo3`: 0.28.2 → 0.28.3
  - Dependencias transitivas menores actualizadas

### Security
- Auditoría de dependencias via `cargo-deny` en CI (bans, licenses, sources)
- Configuración de `publish = false` y `license = "MIT"` explícitas en ambos crates Rust

---

## [1.1.0] - 2026-04-29

### Added
- `EphemeralSession` — Clase de sesiones efímeras con forward secrecy integrado.
  Genera un keypair internamente, expone solo `public_key`, y destruye la clave
  privada al cerrar la sesión (via context manager o `close()`).
- `encrypt_async()` / `decrypt_async()` — Métodos asíncronos en `AegisCipher`
  que ejecutan operaciones de cifrado/descifrado en un ThreadPoolExecutor sin
  bloquear el event loop.
- Sistema de skills locales en `.agents/skills/` con skills para Rust, Python,
  FFI, y auditoría de seguridad.
- `SessionExpiredError` — Nueva excepción para operaciones sobre sesiones cerradas.

### Changed
- `rand_core` eliminado; migrado a `getrandom` 0.4 (mejoras de seguridad y rendimiento).
- `getrandom` actualizado 0.3 → 0.4 (mejor soporte para plataformas).
- Classifier de PyPI: "Development Status :: 3 - Alpha" → "Development Status :: 4 - Beta".

---

## [1.0.0] - 2026-04-11

### Added
- Implementación completa de ML-KEM (FIPS 203) en los tres niveles de seguridad:
  - `ML_KEM_512`  (AES-128 equivalente)
  - `ML_KEM_768`  (AES-192 equivalente) — nivel por defecto
  - `ML_KEM_1024` (AES-256 equivalente)
- `MlKem` — API de bajo nivel para operaciones KEM crudas (`generate_keypair`, `encapsulate`, `decapsulate`)
- `AegisCipher` — API de alto nivel con cifrado híbrido ML-KEM + AES-256-GCM (FIPS 197)
- `KeyPair` — Tipo que encapsula clave pública y secreta con zeroización automática al salir de scope (via `zeroize`)
- `SecurityLevel` — Enum con los tres niveles FIPS 203: `ML_KEM_512`, `ML_KEM_768`, `ML_KEM_1024`
- Jerarquía de excepciones Python con mapeo 1:1 a errores Rust:
  - `AegisQError` (base)
  - `DecapsulationError`
  - `DecryptionError`
  - `InvalidParameterError`
  - `RngError`
- Bindings Python/Rust via PyO3 0.28 con ABI estable (`abi3-py311`)
- Soporte de wheels para Linux (x86_64, aarch64), Windows (x86_64) y macOS (x86_64, aarch64)
- CI/CD con GitHub Actions: build multiplataforma + publicación OIDC a TestPyPI y PyPI
- Vectores KAT (Known Answer Tests) de NIST para validación de correctitud
- Tipado estático completo (`py.typed`, PEP 561)

### Security
- Implementación de `implicit rejection` (FIPS 203 §7.3) en decapsulación: ante un ciphertext
  inválido se devuelve un shared secret derivado de material interno en lugar de lanzar error,
  previniendo ataques de oráculo (CCA2)
- Zeroización de material criptográfico sensible en memoria al liberar estructuras Rust
- Sin dependencias de red en tiempo de ejecución

---

## Tipos de cambio

| Tipo | Descripción |
|---|---|
| `Added` | Funcionalidades nuevas |
| `Changed` | Cambios en funcionalidad existente |
| `Deprecated` | Funcionalidad que será eliminada en versiones futuras |
| `Removed` | Funcionalidad eliminada |
| `Fixed` | Corrección de bugs |
| `Security` | Correcciones de seguridad o cambios relevantes para la seguridad |

<<<<<<< HEAD
[Unreleased]: https://github.com/AC-Santiago/AegisQ/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/AC-Santiago/AegisQ/compare/v1.3.1...v1.4.0
=======
[Unreleased]: https://github.com/AC-Santiago/AegisQ/compare/v1.3.1...HEAD
>>>>>>> origin/main
[1.3.1]: https://github.com/AC-Santiago/AegisQ/compare/v1.3.0...v1.3.1
[1.2.0]: https://github.com/AC-Santiago/AegisQ/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/AC-Santiago/AegisQ/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AC-Santiago/AegisQ/releases/tag/v1.0.0

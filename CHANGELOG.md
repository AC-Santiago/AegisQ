# Changelog

Todos los cambios notables de este proyecto se documentan en este archivo.

El formato sigue [Keep a Changelog](https://keepachangelog.com/es-ES/1.1.0/),
y este proyecto adhiere a [Semantic Versioning](https://semver.org/lang/es/).

---

## [Unreleased]

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

[Unreleased]: https://github.com/AC-Santiago/AegisQ/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/AC-Santiago/AegisQ/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/AC-Santiago/AegisQ/releases/tag/v1.0.0

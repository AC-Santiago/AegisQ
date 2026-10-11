---
title: Arquitectura
description: La arquitectura de tres capas de AegisQ — núcleo en Rust, bridge FFI y API Python.
---

AegisQ enforce separación estricta entre tres capas arquitectónicas. **Violar los límites de capa es un bug de seguridad crítico.** Cada capa solo depende de la que está debajo.

## El Modelo de Tres Capas

```text
╔═══════════════════════════════════════════════════════════════╗
║  CAPA 3: API Python (aegisq/)                                 ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  AegisCipher — encrypt / decrypt / stream / async / ctx │  ║
║  │  EphemeralSession — ciclo de vida del keypair de sesión │  ║
║  │  MlKem — KEM crudo para usuarios avanzados             │  ║
║  │  aegisq.keys — persistencia en archivos PEM/JSON/cifrado│  ║
║  │  Jerarquía de excepciones + stubs de tipo PEP 561       │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════╣
║  CAPA 2: Bridge FFI (crates/aegisq-pyo3/)                     ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  Bindings de PyO3 (#[pyfunction], #[pyclass])           │  ║
║  │  Entradas prestadas; salidas Python bytes copiadas      │  ║
║  │  Liberación del GIL (py.detach) para operaciones crypto │  ║
║  │  SIN lógica criptográfica — capa pura de traducción     │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╠═══════════════════════════════════════════════════════════════╣
║  CAPA 1: Núcleo en Rust (crates/aegisq-core/)                 ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  ML-KEM FIPS 203 (KeyGen, Encaps, Decaps + matemática)   │  ║
║  │  AES-256-GCM cifrado autenticado                        │  ║
║  │  HKDF-SHA3-256 + wrap cifrado de clave secreta          │  ║
║  │  Transit Package (formatos one-shot + streaming)        │  ║
║  │  #![no_std] + alloc — subtle — zeroización acotada      │  ║
║  │  SIN conocimiento de Python ni de FFI                   │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════╝
```

## Responsabilidades por Capa

### Capa 1: Núcleo en Rust (`crates/aegisq-core/`)

Implementa toda la matemática criptográfica en Rust puro con compatibilidad `no_std`. **No tiene conocimiento de Python**.

- Algoritmos ML-KEM de FIPS 203 (KeyGen, Encaps, Decaps con implicit rejection)
- Aritmética de campo en ℤq (q = 3329) con reducción Barrett
- Number Theoretic Transform (NTT)
- AES-256-GCM cifrado autenticado
- HKDF-SHA3-256 + wrap de clave con AES-256-GCM para exportación cifrada de clave secreta
- Ensamblado del Transit Package (modos one-shot + streaming)
- Operaciones en tiempo constante vía `subtle::ConstantTimeEq`
- Zeroización de memoria vía `zeroize::Zeroize`

### Capa 2: Bridge FFI (`crates/aegisq-pyo3/`)

Traduce tipos de Rust a tipos de Python vía PyO3 y libera el GIL durante operaciones costosas.

- Bindings `#[pyfunction]` y `#[pyclass]`
- Entradas prestadas como `&[u8]`; `PyBytes::new` copia las salidas nativas y los resultados de los getters de claves
- Liberación del GIL vía `py.detach()` para operaciones criptográficas
- Clases nativas de streaming con métodos explícitos (`encrypt_chunk`, `finalize`, `decrypt_chunk`, `process_eof`) usadas por los generadores Python
- Tipos PyO3 `KeyPair` y `SecurityLevel`; el repr del keypair contiene nivel y fingerprint público truncado, no bytes secretos
- **Sin lógica criptográfica** — capa pura de traducción

### Capa 3: API Python (`aegisq/`)

Provee las clases Python ergonómicas con las que interactúan los usuarios finales.

- `AegisCipher` — API de alto nivel de encrypt/decrypt/streaming/async/context-manager
- `EphemeralSession` — Keypair de sesión auto-gestionado; el cierre descarta su referencia sin garantizar un borrado seguro completo
- `MlKem` — Operaciones KEM crudas para usuarios avanzados
- `aegisq.keys` — Persistencia de claves basada en archivos (PEM, JSON, PEM cifrado)
- `SecurityLevel` — Enum para conjuntos de parámetros ML-KEM
- Jerarquía de excepciones (`AegisQError` y subclases)
- Stubs de tipo PEP 561 para autocompletado en el IDE

## Estructura Canónica de Archivos

```text
aegisq/
├── Cargo.toml                      # Workspace manifest
├── pyproject.toml                  # Maturin build config
├── deny.toml                       # cargo-deny 0.20.2 policy
│
├── crates/
│   ├── aegisq-core/                # Capa 1: Cripto pura en Rust (no_std)
│   │   ├── Cargo.toml
│   │   ├── benches/                # Benchmarks de Criterion
│   │   │   ├── ntt.rs              # NTT forward/inverse/multiply
│   │   │   └── kem.rs              # KeyGen/Encaps/Decaps en los 3 niveles
│   │   └── src/
│   │       ├── lib.rs              # Raíces de módulos + re-exports
│   │       ├── error.rs            # Variantes de AegisQError (thiserror)
│   │       ├── kem.rs              # API pública KEM (traits + structs)
│   │       ├── hybrid.rs           # AES-256-GCM + Transit Package one-shot
│   │       ├── stream.rs           # StreamEncryptor/StreamDecryptor (v1.5.0)
│   │       ├── kdf.rs              # HKDF-SHA3-256 (v1.3.0)
│   │       ├── key_wrap.rs         # Wrap AES-256-GCM con clave HKDF (v1.3.0)
│   │       └── mlkem/
│   │           ├── mod.rs
│   │           ├── params.rs       # Parámetros por nivel de seguridad
│   │           ├── keygen.rs       # FIPS 203 Alg. 15
│   │           ├── encaps.rs       # FIPS 203 Alg. 16
│   │           ├── decaps.rs       # FIPS 203 Alg. 17 (implicit rejection)
│   │           ├── sampling.rs     # CBD + rejection sampling + SHAKE
│   │           └── math/
│   │               ├── mod.rs
│   │               ├── field.rs    # Aritmética en ℤq, reducción Barrett
│   │               ├── ntt.rs       # NTT forward / inverse
│   │               ├── poly.rs      # Operaciones polinomiales en Rq
│   │               └── compress.rs  # FIPS 203 §4.2.1
│   │
│   └── aegisq-pyo3/                # Capa 2: Bridge FFI
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs              # Registro del #[pymodule] _aegisq_core
│           ├── types.rs            # #[pyclass] KeyPair, SecurityLevel
│           ├── error.rs            # AegisQError → mapeo a PyException
│           ├── kem_bindings.rs     # #[pyfunction] operaciones KEM
│           ├── hybrid_bindings.rs  # #[pyfunction] encrypt_hybrid/decrypt_hybrid
│           ├── key_io_bindings.rs  # load/save PEM/JSON (v1.3.0)
│           └── stream_bindings.rs  # StreamEncryptor/StreamDecryptor PyO3 (v1.5.0)
│
├── aegisq/                         # Capa 3: Paquete Python
│   ├── __init__.py                 # Re-exports de la API pública
│   ├── _aegisq_core.pyi            # Stubs de tipo (PEP 561)
│   ├── _aegisq_core.abi3.so        # Extensión PyO3 compilada (artefacto)
│   ├── cipher.py                   # AegisCipher — API principal de alto nivel
│   ├── kem.py                      # MlKem — operaciones KEM crudas
│   ├── keys.py                     # Persistencia de claves basada en archivos (v1.3.0)
│   ├── session.py                  # EphemeralSession — ciclo de vida
│   ├── exceptions.py               # Jerarquía AegisQError (+ SessionExpiredError)
│   └── py.typed                    # Marcador PEP 561
│
├── tests/
│   ├── python/
│   │   ├── conftest.py
│   │   ├── test_cipher_api.py
│   │   ├── test_cipher_async.py
│   │   ├── test_cipher_context_manager.py
│   │   ├── test_hybrid_bindings.py
│   │   ├── test_implicit_rejection.py
│   │   ├── test_kat_vectors.py
│   │   ├── test_kem_api.py
│   │   ├── test_kem_bindings.py
│   │   ├── test_kem_serialization.py
│   │   ├── test_keypair_repr.py
│   │   ├── test_key_serialization.py
│   │   ├── test_session.py
│   │   ├── test_stream.py
│   │   └── json-files/             # Vectores NIST ACVP KAT
│   │       ├── ML-KEM-keyGen-FIPS203/
│   │       └── ML-KEM-encapDecap-FIPS203/
│   └── rust/                       # Tests unitarios en Rust (dentro de cada crate vía #[cfg(test)])
│
└── website/                        # Este sitio de documentación (Astro + Starlight)
```

## Reglas de Boundary entre Capas (No Negociables)

| Si ves… | En capa… | Es un bug |
|---------|----------|-----------|
| `use pyo3` | `aegisq-core` | ❌ El core no debe conocer Python |
| Aritmética de retículos | `aegisq-pyo3` | ❌ El FFI no debe implementar crypto |
| `import _aegisq_core` | código de usuario final | ❌ Los usuarios deben usar la API pública `aegisq` |
| `use aegisq_core::mlkem::math` (re-export público) | `aegisq-pyo3` | ❌ Los tipos internos de math deben permanecer internos |
| `println!` / `eprintln!` | `aegisq-core` | ❌ `no_std` + potencial fuga por canal lateral |

## ¿Por qué Tres Capas?

- **Testeabilidad** — Cada capa se puede probar en aislamiento. Los tests Rust viven en módulos `#[cfg(test)]` sin Python. El bridge y la API Python tienen tests de integración y end-to-end en `tests/python/`.
- **Auditabilidad** — La revisión criptográfica se enfoca en la Capa 1. La revisión de correctitud del FFI se enfoca en la Capa 2. La revisión de ergonomía se enfoca en la Capa 3.
- **Portabilidad** — La Capa 1 es `no_std` + `alloc`. Un futuro binding de Node.js / Go / WASM es una reescritura de la Capa 2, no de la Capa 1.
- **Performance** — Las entradas prestadas evitan copias innecesarias y `py.detach()` permite ejecutar otros threads Python durante trabajo nativo costoso. Las salidas siguen requiriendo asignaciones Python; la arquitectura no constituye un benchmark ni garantiza escalabilidad multi-core.

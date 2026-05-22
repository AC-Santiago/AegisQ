# AGENTS.md — AegisQ: Motor de Criptografía Post-Cuántica

> **⚠️ LEE ESTE ARCHIVO COMPLETO ANTES DE GENERAR CUALQUIER CÓDIGO.**
> Este documento es la fuente de verdad del proyecto. Cualquier decisión que contradiga
> lo aquí escrito es incorrecta, sin importar cuánto "sentido" parezca tener en el momento.
>
> **Estado del Proyecto:** 29/29 fases completadas — v1.2.0 listo para release

---

## Skills Index

Skills instalados **localmente** en `.agents/skills/` (fuente de verdad del proyecto):

| Prioridad | Contexto | Skill | Uso | Path |
|----------|----------|-------|-----|------|
| Alta | Rust safety / FFI | `unsafe-checker` | unsafe, raw pointers, extern, UB, bindgen, SAFETY | `.agents/skills/unsafe-checker/SKILL.md` |
| Alta | Rust core | `rust-engineer` | ownership, borrowing, lifetimes, async, clippy | `.agents/skills/rust-engineer/SKILL.md` |
| Alta | Rust ↔ Python FFI | `rust-ffi` | bindgen, cbindgen, safe wrappers, extern "C" | `.agents/skills/rust-ffi/SKILL.md` |
| Media | Seguridad | `security-auditor` | threat modeling, crypto review, DevSecOps | `.agents/skills/security-auditor/SKILL.md` |
| Alta | Python testing (recomendado) | `python-testing-patterns` | pytest, fixtures, mocking, async tests, TDD | `.agents/skills/python-testing-patterns/SKILL.md` |
| Baja | Python testing (fallback) | `python-testing` | pytest/TDD liviano, casos simples | `.agents/skills/python-testing/SKILL.md` |

> Preferí `python-testing-patterns` para trabajo nuevo; `python-testing` queda como fallback liviano.

### Agregar nuevos skills

```bash
# Buscar skills
npx skills find "query"

# Instalar localmente en el proyecto (sin -g)
npx skills add owner/repo@skill-name --copy -y
```

> Mantenimiento: si agregás o quitás skills, regenerá `.atl/skill-registry.md` y actualizá `.agents/skills/index.md`.

---

## 1. Identidad del Proyecto

**AegisQ** es un motor de criptografía post-cuántica de uso **privado/empresarial**.
Implementa una **arquitectura híbrida KEM-DEM** que combina:

- **ML-KEM** (Module Lattice-based Key Encapsulation Mechanism), estandarizado por NIST como **FIPS 203**, para el establecimiento seguro de claves contra computadoras cuánticas.
- **AES-256-GCM** (Advanced Encryption Standard — Galois/Counter Mode), para el cifrado autenticado del payload real del usuario.

### ¿Por qué híbrido? (KEM-DEM)

ML-KEM **no cifra datos directamente** — es estrictamente un mecanismo de encapsulación de claves. Solo genera 32 bytes de secreto compartido. AES-256-GCM usa ese secreto para cifrar el payload real (PDFs, JSON, video) a velocidad de hardware. Esta combinación es el estándar de la industria para PQC aplicada.

**Objetivo de usuario final:** Un desarrollador web (FastAPI, Django) debe poder proteger
datos con PQC usando 3 líneas de Python. El usuario final **nunca** interactúa con
Rust, PyO3, retículos matemáticos, ni material criptográfico raw.

### Parámetros ML-KEM por nivel de seguridad

| Variante        | Nivel NIST  | pk size  | sk size  | ct size  | ss size |
|-----------------|-------------|----------|----------|----------|---------|
| ML-KEM-512      | 1           | 800 B    | 1632 B   | 768 B    | 32 B    |
| ML-KEM-768      | 3 ✅ defecto | 1184 B   | 2400 B   | 1088 B   | 32 B    |
| ML-KEM-1024     | 5           | 1568 B   | 3168 B   | 1568 B   | 32 B    |

### Estructura del Paquete de Tránsito (Transit Package)

El `encrypted_package` que viaja por la red tiene esta estructura **fija y canónica**.
No la modifiques. El orden importa para el parsing:

```
[ ML-KEM Capsule (variable*) | AES Nonce (12 bytes) | AES Auth Tag (16 bytes) | Ciphertext (variable) ]

* Capsule size: 768 B (ML-KEM-512) | 1088 B (ML-KEM-768) | 1568 B (ML-KEM-1024)
```

El módulo `hybrid.rs` es responsable de ensamblar y parsear esta estructura.

---

## 2. Arquitectura de Capas — LA REGLA MÁS IMPORTANTE

El proyecto tiene **tres capas herméticas**. Violar esta separación es el error más grave
que puedes cometer. Memorízala:

```
┌──────────────────────────────────────────────────────────────────────┐
│  CAPA 3: Python API  →  aegisq/                                      │
│  Clase AegisCipher, type hints, docstrings, manejo de errores        │
│  Abstrae ML-KEM + AES-GCM en un único .encrypt() / .decrypt()       │
│  ✅ Puede importar: Capa 2 (nunca directamente Capa 1)               │
├──────────────────────────────────────────────────────────────────────┤
│  CAPA 2: FFI Bridge  →  crates/aegisq-pyo3/                          │
│  Traducción de tipos Rust↔Python, GIL management                    │
│  Expone: generate_keypair, encrypt_hybrid, decrypt_hybrid            │
│  ✅ Puede importar: aegisq-core                                      │
│  ❌ NUNCA implementa matemáticas o lógica criptográfica              │
├──────────────────────────────────────────────────────────────────────┤
│  CAPA 1: Rust Core   →  crates/aegisq-core/                          │
│  ML-KEM puro (FIPS 203) + AES-256-GCM (hybrid.rs)                   │
│  no_std compatible, zeroize, subtle, aes-gcm                          │
│  ❌ NUNCA importa pyo3, nunca sabe que Python existe                 │
└──────────────────────────────────────────────────────────────────────┘
```

**Regla de oro:** Si ves `use pyo3` en `aegisq-core`, es un bug. Si ves matemáticas de
retículos en `aegisq-pyo3`, es un bug. Si ves `import _aegisq_core` en código de usuario
final, es un bug.

---

## 3. Estructura de Carpetas Canónica

```
aegisq/                              ← Raíz del repositorio (workspace Cargo)
│
├── AGENTS.md                        ← Este archivo
├── DOCUMENTATION.md                 ← Documentación técnica para LLMs y auditores
├── Cargo.toml                       ← Workspace manifest (NO es un crate)
├── pyproject.toml                   ← Build con Maturin + metadatos Python
├── ruff.toml                        ← Configuración de Ruff (linter Python)
├── .cargo/
│   └── config.toml                  ← Flags de compilación globales
├── .agents/                         ← Índice local de agentes y skills
│   ├── README.md                    ← Hub local de agentes
│   └── skills/
│       ├── index.md                 ← Catálogo humano de skills instaladas
│       └── <skill-name>/SKILL.md     ← Skills instaladas en scope proyecto
├── .atl/                            ← Registry máquina para delegación (ignorado por git)
│   └── skill-registry.md            ← Índice generado para sub-agentes
│
├── crates/
│   ├── aegisq-core/                 ← CAPA 1: Rust puro, no_std
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── error.rs
│   │       ├── kem.rs               ← API pública del crate (traits + structs KEM)
│   │       ├── hybrid.rs            ← ★ NUEVO: Integración AES-256-GCM + ensamblado del Transit Package
│   │       └── mlkem/
│   │           ├── mod.rs
│   │           ├── params.rs        ← Parámetros por nivel (k, eta1, eta2, du, dv)
│   │           ├── math/
│   │           │   ├── mod.rs
│   │           │   ├── field.rs     ← Aritmética Z_q (q=3329), reducción Barrett
│   │           │   ├── ntt.rs      ← Number Theoretic Transform
│   │           │   ├── poly.rs     ← Polinomios en R_q = Z_q[X]/(X^256+1)
│   │           │   └── compress.rs ← Compresión FIPS 203 §4.2.1
│   │           ├── sampling.rs     ← CBD y rejection sampling (SHAKE-256)
│   │           ├── keygen.rs        ← ML-KEM.KeyGen (FIPS 203 Alg. 15)
│   │           ├── encaps.rs        ← ML-KEM.Encaps (FIPS 203 Alg. 16)
│   │           └── decaps.rs        ← ML-KEM.Decaps con implicit rejection (Alg. 17)
│   │
│   └── aegisq-pyo3/                 ← CAPA 2: FFI Bridge
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs               ← #[pymodule] _aegisq_core
│           ├── types.rs             ← #[pyclass] KeyPair, SecurityLevel
│           ├── error.rs             ← AegisQError → PyException mapping
│           ├── kem_bindings.rs      ← #[pyfunction] generate_keypair (+ deterministic)
│           └── hybrid_bindings.rs   ← #[pyfunction] encrypt_hybrid, decrypt_hybrid
│
├── aegisq/                          ← CAPA 3: Python package
│   ├── __init__.py
│   ├── _aegisq_core.pyi             ← Type stubs (autocompletado IDE)
│   ├── cipher.py                    ← ★ NUEVO: Clase AegisCipher (API de alto nivel)
│   ├── kem.py                       ← Clase MlKem (operaciones KEM crudas, uso avanzado)
│   ├── exceptions.py               ← Jerarquía de excepciones
│   └── py.typed                     ← Marker PEP 561
│
├── tests/
│   ├── python/
│   │   ├── conftest.py
│   │   ├── test_kem_bindings.py     ← Tests del bridge PyO3 (KEM)
│   │   ├── test_hybrid_bindings.py  ← Tests del bridge PyO3 (híbrido)
│   │   ├── test_cipher_api.py       ← Tests de AegisCipher end-to-end
│   │   ├── test_kem_api.py         ← Tests de la API Python MlKem
│   │   ├── test_kat_vectors.py     ← ✅ NUEVO: Tests KAT vectors NIST
│   │   └── json-files/             ← ✅ NUEVO: Vectores KAT NIST ACVP
│   │       ├── ML-KEM-keyGen-FIPS203/
│   │       └── ML-KEM-encapDecap-FIPS203/
│   └── rust/                        ← (Tests en #[cfg(test)] dentro de cada crate)
│
├── .github/
│   ├── workflows/
│   │   ├── ci.yml                   ← CI/CD con GitHub Actions
│   │   └── release.yml              ← Release workflow
│   └── dependabot.yml               ← Actualización automática de dependencias
│
├── website/                          ← Documentación con Astro + Starlight
│   ├── package.json
│   └── src/content/docs/
│       ├── getting-started/
│       │   └── installation.mdx
│       └── internals/
│           ├── architecture.md
│           ├── mathematical-foundation.md
│           ├── security-model.md
│           └── hybrid-kem-dem.md
│
├── CHANGELOG.md                     ← Registro de cambios
├── deny.toml                    ← cargo-deny config (bans, licenses, sources)
├── SECURITY.md                      ← Política de seguridad
├── LICENSE                          ← MIT License
├── README.md                        ← Documentación general
├── docs/
│   └── DOCUMENTATION.md             ← Documentación técnica detallada
└── .python-version                  ← Versión de Python requerida (3.11+)
```

---

## 4. Archivos de Configuración — Valores Canónicos

> **No cambies estos valores sin consenso explícito del equipo.**

### `Cargo.toml` (raíz — workspace)

```toml
[workspace]
members  = ["crates/aegisq-core", "crates/aegisq-pyo3"]
resolver = "2"

[workspace.dependencies]
zeroize   = { version = "1.8",  features = ["derive", "zeroize_derive"] }
subtle    = { version = "2.6",  default-features = false }
sha3      = { version = "0.11", default-features = false }
getrandom = { version = "0.4",  default-features = false }
aes-gcm   = { version = "0.10", default-features = false, features = ["aes", "alloc"] }
thiserror = { version = "2.0", default-features = false }

[profile.release]
opt-level       = 3
lto             = "fat"
codegen-units   = 1
overflow-checks = true   # ← NUNCA cambiar a false. Jamás.
strip           = false
```

### `crates/aegisq-pyo3/Cargo.toml`

```toml
[lib]
name       = "_aegisq_core"   # ← Nombre exacto del .so que importa Python
crate-type = ["cdylib"]

[dependencies]
pyo3 = { version = "0.28", features = ["extension-module", "abi3-py311"] }
```

> `abi3-py311`: el `.so` compilado una vez corre en Python 3.11 → 3.13+.

### `pyproject.toml`

```toml
[tool.maturin]
manifest-path = "crates/aegisq-pyo3/Cargo.toml"
python-source = "."
module-name   = "aegisq._aegisq_core"   # ← El .so vive DENTRO del paquete
features      = ["pyo3/extension-module"]
```

---

## 5. Reglas de Seguridad — NO NEGOCIABLES

Estas reglas aplican a **todo** el código que generes. No hay excepciones.

### 5.1 — Prohibiciones Absolutas en Rust

```rust
// ❌ PROHIBIDO — panic en producción, fuga de información en timing
.unwrap()
.expect("cualquier mensaje")

// ❌ PROHIBIDO — comportamiento undefined en overflow aritmético
a.wrapping_add(b)  // solo si es intencional y documentado con // SAFETY:

// ❌ PROHIBIDO — comparaciones no-constantes de material criptográfico
if secret_a == secret_b { ... }   // usa subtle::ConstantTimeEq
if decapsulated_key == expected { ... }

// ❌ PROHIBIDO — nonce fijo o secuencial en AES-GCM
let nonce = [0u8; 12];   // CATASTRÓFICO: nonce reuse destruye la confidencialidad
```

### 5.2 — Obligatorio para Material Criptográfico Sensible

```rust
// ✅ OBLIGATORIO — borrar memoria al salir de scope
#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; 2400]);

// ✅ OBLIGATORIO — comparaciones en tiempo constante
use subtle::ConstantTimeEq;
let keys_match: bool = key_a.ct_eq(&key_b).into();

// ✅ OBLIGATORIO — nonce aleatorio fresco en CADA operación de cifrado AES-GCM
use rand_core::{RngCore, OsRng};
let mut nonce = [0u8; 12];
OsRng.fill_bytes(&mut nonce);   // 96 bits de entropía del OS en cada llamada

// ✅ OBLIGATORIO — liberar GIL en operaciones costosas en PyO3
py.detach(|| {
    aegisq_core::hybrid::encrypt(public_key, payload, level)
})
```

### 5.3 — Paso de Bytes entre Rust y Python (Zero-Copy)

```rust
// ✅ CORRECTO — zero-copy entrada: Python bytes → slice Rust sin copiar
#[pyfunction]
fn encrypt_hybrid<'py>(
    py: Python<'py>,
    recipient_public_key: &[u8],     // Sin copia
    plaintext: &[u8],                  // Sin copia
    level: SecurityLevel,
) -> PyResult<Py<PyBytes>> {
    py.detach(|| {
        aegisq_core::hybrid::encrypt(recipient_public_key, plaintext, level)
    })
    .map(|pkg| PyBytes::new(py, &pkg).into())
    .map_err(|e| PyErr::from(e))
}

// ❌ INCORRECTO — copia innecesaria en entrada
let pk_vec: Vec<u8> = recipient_public_key.to_vec();  // Allocación evitable
```

### 5.4 — Implicit Rejection en Decaps (FIPS 203 §7.3)

`ML-KEM Decaps` **NUNCA** debe lanzar excepción cuando el ciphertext es inválido.
Devuelve silenciosamente una clave derivada de `z || H(c)`. Esto previene ataques CCA.
Si ves un `return Err(...)` en la ruta de validación del ciphertext en `decaps.rs`, es un
**bug de seguridad crítico**.

### 5.5 — Manejo de Errores AES-GCM (Diferente de ML-KEM Decaps)

AES-GCM SÍ debe propagar errores cuando la verificación del Auth Tag falla. Un tag inválido
significa que el ciphertext fue **manipulado o corrompido** y el plaintext recuperado sería
basura peligrosa. La excepción correcta es `DecryptionError` (ver §6.3).

```rust
// ✅ CORRECTO en hybrid.rs — propagar error de tag AES-GCM
aes_gcm_cipher.decrypt(&nonce.into(), payload)
    .map_err(|_| AegisQError::DecryptionFailed)?;
// Nota: el error de aes-gcm no revela información útil al atacante,
// solo indica "tag inválido". Es seguro propagarlo como excepción.
```

---

## 6. Convenciones de Código

### Naming — SecurityLevel (ESTÁNDAR ÚNICO)

```python
# ✅ CORRECTO — UPPER_CASE, convención Python para enums/constantes
SecurityLevel.ML_KEM_512
SecurityLevel.ML_KEM_768   # ← default
SecurityLevel.ML_KEM_1024

# ❌ INCORRECTO — mezclar estilos
SecurityLevel.MlKem768
SecurityLevel.MLKEM768
```

En Rust, el enum interno usa PascalCase (`MlKem768`) pero el `#[pyclass]` lo renombra a
UPPER_CASE via `#[pyo3(name = "ML_KEM_768")]` para respetar la convención Python.

### Rust (`aegisq-core`)

- Todos los módulos internos deben compilar con `#![no_std]` + `alloc` (sin `std`)
- `aes-gcm` v0.10 con `default-features = false` es compatible con `no_std`
- Nombra las constantes de params con el prefijo del nivel: `K_768`, `ETA1_768`, etc.
- Los algoritmos del FIPS 203 deben tener un comentario `// FIPS 203 Alg. X` exacto
- Tests unitarios en el mismo archivo (`#[cfg(test)]`) con KAT vectors del NIST
- El módulo `hybrid.rs` vive al mismo nivel que `kem.rs`, no dentro de `mlkem/`

### Rust (`aegisq-pyo3`)

- Todas las funciones `#[pyfunction]` retornan `PyResult<T>`, nunca hacen `.unwrap()`
- El mapeo de errores usa `map_err(|e| PyErr::from(e))` con conversión automática
- Las excepciones customizadas de AegisQ se registran en `lib.rs` como subclases de `PyException`
- `kem_bindings.rs` expone operaciones KEM crudas (generate_keypair, encapsulate, decapsulate)
- `hybrid_bindings.rs` expone operaciones híbridas (encrypt_hybrid, decrypt_hybrid)

### Python (`aegisq/`)

- Type hints completos en todas las funciones públicas
- Docstrings en formato Google Style
- **`AegisCipher`** en `cipher.py` es la clase principal de alto nivel para usuarios finales
- **`MlKem`** en `kem.py` es la clase de operaciones KEM crudas para usuarios avanzados
- `__init__.py` exporta: `AegisCipher`, `MlKem`, `SecurityLevel`, y todas las excepciones
- El usuario nunca debe necesitar importar desde `aegisq._aegisq_core` directamente

### 6.3 — Jerarquía de Excepciones Python

```python
AegisQError(Exception)                   ← Base, siempre catcheable
├── DecapsulationError(AegisQError)      ← ML-KEM: error estructural (tamaño incorrecto)
│                                        ← NOTA: ciphertext inválido NO lanza esto (implicit rejection)
├── DecryptionError(AegisQError)         ← ★ NUEVO: AES-GCM tag verification failed
│                                        ← Indica payload manipulado o clave incorrecta
├── InvalidParameterError(AegisQError, ValueError)  ← Tamaños de buffer incorrectos, nivel inválido
└── RngError(AegisQError)                ← CSPRNG del OS no disponible
```

### 6.4 — API de Alto Nivel `AegisCipher` (cipher.py)

```python
from aegisq import AegisCipher, SecurityLevel

# Receptor genera su keypair
cipher_bob = AegisCipher(level=SecurityLevel.ML_KEM_768)
keypair = cipher_bob.generate_keypair()

# Emisor cifra payload con la clave pública del receptor
cipher_alice = AegisCipher(level=SecurityLevel.ML_KEM_768)
package: bytes = cipher_alice.encrypt(
    plaintext=b"Datos secretos",
    recipient_public_key=keypair.public_key
)
# package = [ ML-KEM Capsule | Nonce (12B) | Auth Tag (16B) | Ciphertext ]

# Receptor descifra
plaintext: bytes = cipher_bob.decrypt(
    encrypted_package=package,
    secret_key=keypair.secret_key
)
```

#### KeyPair Properties and Methods

```python
keypair.public_key   # bytes — clave pública ML-KEM (800/1184/1568 bytes según nivel)
keypair.secret_key   # bytes — clave secreta (solo el receptor la tiene)
keypair.level        # SecurityLevel — nivel de seguridad del keypair

def public_key_b64(self) -> str:
    """Serializa la clave pública a Base64 URL-safe (sin padding)."""
```

### 6.5 — Serialización Base64 URL-safe

```python
# Serializar clave pública a Base64 URL-safe (sin padding)
b64 = keypair.public_key_b64()

# Cargar clave pública desde Base64 URL-safe
kem = MlKem(level=SecurityLevel.ML_KEM_768)
public_key_bytes = kem.load_public_key_b64(b64)
```

La serialización Base64 permite transmitir claves públicas ML-KEM como strings
texto (ej: en JSON, environment variables, headers HTTP) sin necesidad de
transmitir los bytes raw de 800/1184/1568 bytes.

El formato usado es URL-safe sin padding (RFC 4648 §5), compatible con el
estándar NIST para intercambio de claves.

## 7. Comandos de Desarrollo

```bash
# ── Compilación ──────────────────────────────────────────────────────────
maturin develop                          # Debug, para ciclo de desarrollo
maturin develop --release                # Release, para benchmarks

# ── Testing ──────────────────────────────────────────────────────────────
cargo test --workspace                   # Todos los tests Rust
cargo test -p aegisq-core               # Solo tests del core criptográfico
pytest tests/python/ -v                  # Todos los tests Python
pytest tests/python/test_cipher_api.py  # Solo tests AegisCipher

# ── Calidad de Código ─────────────────────────────────────────────────────
cargo clippy --workspace -- -D warnings  # Linter (warnings = errores)
cargo fmt --all                          # Formato Rust
ruff check aegisq/           # Linter Python (reemplaza flake8 + isort)
ruff format --check aegisq/  # Formato Python (reemplaza black)

# ── Seguridad ─────────────────────────────────────────────────────────────
cargo audit                              # Auditoría de dependencias
cargo tree -p aegisq-core               # Verificar árbol de deps (no_std compliance)
```

> **Regla para el agente:** Después de generar código Rust, **siempre** verifica con
> `cargo clippy --workspace -- -D warnings`. Si clippy se queja, corrige antes de presentar.

---

## 8. Parámetros Matemáticos de ML-KEM

Estos son los valores del FIPS 203. **No los cambies, no los "optimices".**

```
q       = 3329          ← Módulo primo del campo Z_q
n       = 256           ← Grado del polinomio (X^256 + 1)
zeta    = 17            ← Raíz primitiva 256-ésima de la unidad en Z_q

             k    eta1  eta2  du   dv
ML-KEM-512:  2    3     2    10    4
ML-KEM-768:  3    2     2    10    4
ML-KEM-1024: 4    2     2    11    5

Shared secret (salida ML-KEM) = 32 bytes  (para los 3 niveles)
AES-256-GCM key = 32 bytes = shared_secret  (1:1, sin KDF adicional)
AES-256-GCM nonce = 12 bytes (96 bits, aleatorio por OsRng en cada encrypt)
AES-256-GCM auth tag = 16 bytes (128 bits)
```

---

## 9. Orden de Implementación (Hoja de Ruta)

Implementa **estrictamente en este orden**. No saltes fases.
Cada fase debe tener sus tests pasando antes de avanzar a la siguiente.

| Fase | Módulo destino                            | Descripción                                           | Estado       |
|------|-------------------------------------------|-------------------------------------------------------|--------------|
| 1    | `aegisq-core/mlkem/math/field.rs`         | Aritmética Z_{3329}, reducción Barrett, tiempo const. | ✅ Completo |
| 2    | `aegisq-core/mlkem/math/ntt.rs`           | NTT, NTT inversa, raíces precalculadas                | ✅ Completo |
| 3    | `aegisq-core/mlkem/math/poly.rs`          | Operaciones sobre polinomios en R_q                   | ✅ Completo |
| 4    | `aegisq-core/mlkem/math/compress.rs`      | Compress_d / Decompress_d (FIPS 203 §4.2.1)           | ✅ Completo |
| 5    | `aegisq-core/mlkem/params.rs`             | Struct de parámetros por nivel de seguridad           | ✅ Completo |
| 6    | `aegisq-core/mlkem/sampling.rs`           | CBD, rejection sampling, XOF (SHAKE-128/256)          | ✅ Completo |
| 7    | `aegisq-core/mlkem/keygen.rs`             | ML-KEM.KeyGen (FIPS 203 Alg. 15)                     | ✅ Completo |
| 8    | `aegisq-core/mlkem/encaps.rs`             | ML-KEM.Encaps (FIPS 203 Alg. 16)                     | ✅ Completo |
| 9    | `aegisq-core/mlkem/decaps.rs`             | ML-KEM.Decaps con implicit rejection (Alg. 17)        | ✅ Completo |
| 10   | `aegisq-core/kem.rs`                      | API pública KEM del crate (traits + structs)          | ✅ Completo |
| 11   | `aegisq-core/hybrid.rs`                   | ★ AES-256-GCM + ensamblado Transit Package            | ✅ Completo |
| 12   | `aegisq-pyo3/error.rs`                    | Mapeo de errores Rust → PyException                   | ✅ Completo |
| 13   | `aegisq-pyo3/types.rs`                    | #[pyclass] KeyPair, SecurityLevel                     | ✅ Completo |
| 14   | `aegisq-pyo3/kem_bindings.rs`             | #[pyfunction] generate_keypair, encapsulate, decaps   | ✅ Completo |
| 15   | `aegisq-pyo3/hybrid_bindings.rs`          | ★ #[pyfunction] encrypt_hybrid, decrypt_hybrid        | ✅ Completo |
| 16   | `aegisq-pyo3/lib.rs`                      | Registro del módulo Python _aegisq_core               | ✅ Completo |
| 17   | `aegisq/exceptions.py`                    | Jerarquía de excepciones Python (incl. DecryptionError)| ✅ Completo |
| 18   | `aegisq/_aegisq_core.pyi`                 | Type stubs para IDE (KEM + híbrido)                   | ✅ Completo |
| 19   | `aegisq/kem.py`                           | Clase MlKem (operaciones KEM crudas, uso avanzado)    | ✅ Completo |
| 20   | `aegisq/cipher.py`                        | ★ Clase AegisCipher (API híbrida de alto nivel)       | ✅ Completo |
| 21   | `aegisq/__init__.py`                      | Exports públicos del paquete                          | ✅ Completo |
| 22   | `tests/python/test_kem_bindings.py`       | Tests del bridge PyO3 (KEM) con pytest                | ✅ Completo |
| 23   | `tests/python/test_hybrid_bindings.py`    | ★ Tests del bridge PyO3 (híbrido)                    | ✅ Completo |
| 24   | `tests/python/test_cipher_api.py`         | ★ Tests AegisCipher end-to-end                       | ✅ Completo |
| 25   | `tests/python/test_kem_api.py`            | Tests KAT vectors NIST + roundtrip                   | ✅ Completo |
| 26   | `.github/workflows/ci.yml`                | CI/CD con GitHub Actions                             | ✅ Completo |
| 27   | `tests/python/json-files/`               | Vectores KAT NIST ACVP para ML-KEM                  | ✅ Completo |
| 27b  | `tests/python/test_kat_vectors.py`       | Tests de verificación con KAT vectors                | ✅ Completo |
| 28   | `aegisq/session.py`                      | EphemeralSession con forward secrecy                | ✅ Completo |
| 29   | `aegisq/cipher.py` + `test_cipher_async.py` | Soporte async (encrypt_async/decrypt_async)       | ✅ Completo |

---

## 10. Decisiones de Diseño Fijas (No Reabrir)

| Decisión | Elección | Razón |
|----------|----------|-------|
| Build system | Maturin | Estándar de facto para PyO3, abi3, wheels, editable installs |
| FFI | PyO3 0.28+ | API moderna, safe Rust, free-threading ready, manejo automático de GIL |
| Python mínimo | 3.11 | abi3-py311 cubre la base instalada empresarial relevante |
| Hash/XOF | sha3 crate (SHAKE-128/256) | no_std, auditado, FIPS 203 requerido |
| Cifrado simétrico | aes-gcm crate v0.10 | no_std, AEAD autenticado, hardware AES-NI vía crate `aes` |
| Nonce AES-GCM | 96 bits aleatorios por OsRng | Probabilidad de colisión negligible, sin estado compartido |
| Zeroización | zeroize crate | Borrado de memoria sensible resistente a optimizaciones |
| Tiempo constante | subtle crate | Operaciones CT certificadas, no_std compatible |
| Nivel por defecto | ML-KEM-768 | Balance óptimo seguridad/rendimiento, recomendado por NIST |
| Naming Python | UPPER_CASE para SecurityLevel | PEP 8: constantes en UPPER_CASE; via `#[pyo3(name)]` |
| Arquitectura de errores | Rust thiserror → PyO3 PyErr | Stack traces con sentido en Python, errores tipados en Rust |
| AES-GCM auth tag fail | Lanza DecryptionError (NO silencioso) | Diferente a ML-KEM implicit rejection; tag fail = tampering |
| API de usuario final | Clase AegisCipher | Abstrae KEM+DEM en una sola interfaz ergonómica |

---

## 11. Lo que el Agente NUNCA Debe Hacer

- ❌ Agregar dependencias a `aegisq-core` sin aprobación (rompe la compatibilidad no_std)
- ❌ Usar `rand` (el crate completo) — solo `rand_core` con `OsRng` para mantener no_std
- ❌ Usar un nonce fijo, hardcodeado, o secuencial en AES-GCM — **destruye la confidencialidad**
- ❌ Reutilizar el mismo nonce con la misma clave en AES-GCM — **catastrófico**
- ❌ Silenciar el error de tag AES-GCM (≠ ML-KEM implicit rejection) — debe lanzar `DecryptionError`
- ❌ Implementar su propia aritmética modular sin los tests KAT del NIST primero
- ❌ Cambiar los tamaños de buffer definidos en la sección 8 de este documento
- ❌ Retornar `Err` en la ruta de ciphertext inválido de ML-KEM `decaps` (ver §5.4)
- ❌ Mover el archivo `.so` fuera de `aegisq/` — debe vivir en `aegisq._aegisq_core`
- ❌ Exponer tipos internos de `mlkem/math/` a través del `pub use` en `lib.rs`
- ❌ Generar código sin type hints en Python
- ❌ Agregar `println!` o logs a `aegisq-core` (no_std y potencial fuga de información)
- ❌ Usar `SecurityLevel.MlKem768` — el naming canónico es `SecurityLevel.ML_KEM_768`
- ❌ Exponer el shared secret de 32 bytes directamente al usuario Python en el flujo `AegisCipher`

---

## 12. Nomenclatura de Paquete y Versionado

| Atributo | Valor | Notas |
|----------|-------|-------|
| PyPI package name | `aegisq-pqc` | Nombre para `pip install` |
| Python import name | `aegisq` | Nombre para `import aegisq` |
| Módulo interno | `aegisq._aegisq_core` | El `.so` compilado por Maturin |
| Versión actual | `1.2.0` | Sincronizado con `pyproject.toml` |
| Siguiente versión | `1.3.0` | Por definir según roadmap de features |

> ⚠️ **Nota:** No confundas el nombre del paquete PyPI (`aegisq-pqc`) con el nombre
> del módulo Python (`aegisq`). Ambos son el mismo paquete; PyPI usa guiones
> porque no permite guiones bajos en los nombres de paquetes.
>
> ```bash
> # Instalación (desde PyPI o git)
> pip install aegisq-pqc
>
> # Uso en Python (import siempre con guiones bajos)
> from aegisq import AegisCipher, SecurityLevel
> ```

---

## 13. Referencias Normativas

| Documento | URL |
|-----------|-----|
| FIPS 203 (ML-KEM estándar oficial) | https://csrc.nist.gov/pubs/fips/203/final |
| NIST KAT vectors ML-KEM | https://csrc.nist.gov/projects/post-quantum-cryptography |
| PyO3 User Guide | https://pyo3.rs/latest/ |
| Maturin Docs | https://www.maturin.rs/ |
| aes-gcm crate | https://docs.rs/aes-gcm |
| zeroize crate | https://docs.rs/zeroize |
| subtle crate | https://docs.rs/subtle |
| NIST SP 800-38D (AES-GCM spec) | https://csrc.nist.gov/pubs/sp/800/38/d/final |

---

*Última actualización: v1.2.0 — Todas las fases completadas. 29/29. Listo para release.*

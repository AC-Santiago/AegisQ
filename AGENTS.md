# AGENTS.md — Guía de mantenimiento de AegisQ

Lee esta guía completa antes de generar código. Conserva las reglas de
arquitectura, seguridad y entrega; no es un registro de fases completadas.

## 1. Fuentes de verdad

- [README.md](README.md): entrada al proyecto y ejemplos básicos.
- [Documentación pública](https://docs.aegisq.dev/): guías y referencia bilingües.
  Su fuente canónica es [website/src/content/docs/](website/src/content/docs/).
- [CHANGELOG.md](CHANGELOG.md): historial de releases; no duplicarlo en las guías.
- [SECURITY.md](SECURITY.md): reporte privado y compromisos de soporte.
- `pyproject.toml` y los manifiestos de ambos crates: versión del checkout.
  PyPI identifica las versiones publicadas; no inferirlas desde una rama.
- `Cargo.toml`, manifiestos de crates y lockfiles: dependencias y configuración
  vigentes. No copiar inventarios antiguos como valores canónicos.
- [website/README.md](website/README.md): desarrollo, verificaciones y publicación.
- [PRODUCT.md](PRODUCT.md) y [DESIGN.md](DESIGN.md): contrato de producto y diseño.

AegisQ declara estado Beta. La implementación de algoritmos estandarizados y
los tests no equivalen a certificación FIPS, validación ACVP oficial o auditoría
independiente. No inventar garantías, cifras de rendimiento ni soporte de versiones.

## 2. Skills locales

Consultar [.agents/skills/index.md](.agents/skills/index.md) antes del trabajo
especializado. Las skills están en `.agents/skills/`, con scope de proyecto.

| Contexto | Skill |
| --- | --- |
| Rust core, ownership, clippy | `rust-engineer` |
| Unsafe, punteros, ABI, FFI | `unsafe-checker` + `rust-ffi` |
| Seguridad y revisión criptográfica | `security-auditor` |
| Tests Python nuevos | `python-testing-patterns` |
| Tests Python simples, fallback | `python-testing` |

Si se agregan o retiran skills, actualizar `.agents/skills/index.md` y regenerar
el registry local `.atl/skill-registry.md` (ignorado por Git). No instalar skills
globales como parte del mantenimiento del proyecto.

## 3. Arquitectura de tres capas

AegisQ combina ML-KEM para establecer un secreto compartido de 32 bytes y
AES-256-GCM para cifrar el payload. ML-KEM no cifra datos de usuario directamente.

| Capa | Ubicación | Responsabilidad |
| --- | --- | --- |
| Rust core | `crates/aegisq-core/` | ML-KEM, híbrido, KDF, key wrap y streaming; `no_std` + `alloc` |
| Bridge FFI | `crates/aegisq-pyo3/` | Conversión Rust/Python, errores, GIL; importa el core |
| API Python | `aegisq/` | API pública, validación y ergonomía; usa el bridge |

- El core nunca importa PyO3 ni conoce Python.
- El bridge no implementa matemáticas de retículos ni lógica criptográfica.
- El usuario final importa desde `aegisq`, no desde `aegisq._aegisq_core`.
- No exponer tipos internos de `mlkem/math/` como API pública del crate.
- `hybrid.rs` vive al mismo nivel que `kem.rs`, no dentro de `mlkem/`.

Las guías de [arquitectura](website/src/content/docs/internals/architecture.md),
[híbrido](website/src/content/docs/internals/hybrid-kem-dem.md) y
[streaming](website/src/content/docs/api-reference/streaming.md) describen los formatos.

## 4. Parámetros y formatos inmutables

No cambiar parámetros FIPS 203 ni formatos canónicos para una optimización.

| Variante | Nivel NIST | pk | sk | Capsule | k | eta1 | eta2 | du | dv |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| ML-KEM-512 | 1 | 800 B | 1632 B | 768 B | 2 | 3 | 2 | 10 | 4 |
| ML-KEM-768 (defecto) | 3 | 1184 B | 2400 B | 1088 B | 3 | 2 | 2 | 10 | 4 |
| ML-KEM-1024 | 5 | 1568 B | 3168 B | 1568 B | 4 | 2 | 2 | 11 | 5 |

`q = 3329`, `n = 256`, `zeta = 17`. El secreto compartido y la clave AES-256-GCM
tienen 32 bytes. El nonce tiene 12 bytes y el tag 16 bytes.

Paquete one-shot, ensamblado y parseado por `hybrid.rs`:

```text
[ ML-KEM Capsule | AES Nonce (12 B) | AES Auth Tag (16 B) | Ciphertext ]
```

El flujo one-shot usa directamente el secreto ML-KEM como clave AES, sin KDF
adicional. No confundirlo con la derivación usada por key wrap y streaming.
Streaming tiene un framing propio: no reinterpretarlo como un paquete one-shot.

## 5. Reglas de seguridad

- No usar `.unwrap()` ni `.expect()` en rutas de producción. Propagar errores.
- Mantener `overflow-checks = true` en el perfil release. La aritmética
  `wrapping_*` requiere intención explícita y justificación documentada con
  `SAFETY`; no es, por sí misma, comportamiento indefinido de Rust.
- Comparar material criptográfico y seleccionar claves con operaciones de
  tiempo constante (`subtle`), no con igualdad ordinaria ni ramas sobre secretos.
- Zeroizar material sensible nuevo al salir de scope, incluyendo rutas de error.
  No afirmar que el código existente borra todas las copias Rust/Python.
- One-shot: nonce aleatorio fresco de 96 bits en cada cifrado; nunca fijo,
  secuencial ni reutilizado bajo la misma clave. Usar el RNG actual respaldado
  por `getrandom::fill`, no reintroducir `rand` ni `rand_core::OsRng`.
  Streaming conserva su esquema de nonces por frame; no sustituirlo por el
  esquema one-shot. La aleatoriedad reduce colisiones, no garantiza unicidad.
- Propagar fallos del CSPRNG. No usar fallback determinista en producción.
- No agregar dependencias al core sin aprobación; conservar `no_std` + `alloc`.
- No agregar logs ni `println!` al core ni registrar claves o secretos en ninguna capa.
- Los cambios matemáticos requieren tests con vectores NIST y regresiones.

### Rechazo implícito frente a errores estructurales

Para una capsule de tamaño correcto cuyo contenido no verifica, ML-KEM Decaps
devuelve silenciosamente `J(z || c)`; no debe generar un error de validez.
Los tamaños incorrectos de claves o capsules sí generan `InvalidParameterError`.
No eliminar estas comprobaciones estructurales.

AES-GCM es distinto: un tag inválido debe producir `DecryptionError`, nunca
plaintext no autenticado. No silenciarlo como si fuera rechazo implícito ML-KEM.
No exponer el secreto compartido de 32 bytes en el flujo público `AegisCipher`.

`EphemeralSession.close()` limita el ciclo de vida del objeto, pero no garantiza
borrado completo ni forward secrecy de un protocolo. Autenticación de identidad,
gestión de claves y protección contra replay requieren controles de la aplicación.
Consultar el [modelo de seguridad](website/src/content/docs/internals/security-model.md).

## 6. Convenciones del bridge y la API

- Funciones `#[pyfunction]`: retornar `PyResult<T>`, liberar el GIL con
  `py.detach()` en operaciones costosas y mapear errores mediante
  `core_error_to_pyerr` en `crates/aegisq-pyo3/src/error.rs`.
- Entradas bytes prestadas: evitar copias innecesarias a `Vec`. Las salidas
  Python y getters de claves sí crean copias; no prometer zero-copy de extremo a extremo.
- `SecurityLevel.ML_KEM_512`, `.ML_KEM_768`, `.ML_KEM_1024` son los nombres Python;
  no usar `MlKem768` ni `MLKEM768` en ejemplos públicos.
- Type hints completos en funciones públicas Python; docstrings Google Style.
- Mantener `AegisCipher` como API principal y `MlKem` para operaciones avanzadas.
  Exportar clases y excepciones públicas desde `aegisq/__init__.py`.
- Consultar `aegisq/exceptions.py` y el bridge para la jerarquía real. No atribuir
  herencia de `ValueError` a `InvalidParameterError` ni usar `DecapsulationError`
  para describir los errores de tamaño actuales.
- Constantes de parámetros: prefijos por nivel (`K_768`, `ETA1_768`, etc.).
  Anotar los algoritmos con la referencia FIPS 203 correspondiente.
- Conservar el módulo nativo `aegisq._aegisq_core` dentro de `aegisq/`, el nombre
  de lib `_aegisq_core`, `cdylib`, Maturin y `abi3-py311`.
  Python mínimo: 3.11; la ABI no prueba compatibilidad con todo runtime futuro
  o free-threaded. No cambiar estas decisiones sin consenso explícito.

## 7. Desarrollo y verificaciones

Con un entorno Python de desarrollo preparado:

```bash
maturin develop
maturin develop --release
cargo test --workspace
pytest tests/python/ -v
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
ruff check aegisq/
ruff format --check aegisq/
cargo audit
cargo deny check bans licenses sources
cargo tree -p aegisq-core
```

Tras generar Rust, ejecutar siempre Clippy y corregir advertencias antes de
presentar el cambio. Los tests unitarios Rust viven en los módulos; los tests
Python y corpus NIST están en `tests/python/`. No retirar fixtures como si fueran
documentación histórica. Una afirmación de tests pasando exige una ejecución real.

Para la web, seguir `website/README.md`: Astro check, build, contratos y pruebas
de hosting. La CI web valida; no publica automáticamente.

## 8. Documentación y diseño

- Mantener fuentes canónicas EN/ES en `website/src/content/docs/` y su carpeta `es/`.
- Actualizar ambas versiones cuando cambia un contrato o ejemplo público.
- Evitar duplicar referencias completas de API, fases terminadas o tablas de
  versiones del checkout en guías de mantenimiento. El historial va en el changelog.
- Preservar rutas públicas, búsqueda Pagefind y controles nativos Starlight.
- Conservar licencias y atribuciones de fuentes; los reportes locales de QA no
  se sirven ni se versionan como contenido público.
- Distinguir objetivos de accesibilidad de evidencia verificada. No inventar
  certificaciones o auditorías para respaldar el diseño.

## 9. Hosting

`aegisq.dev` aloja la portada y `docs.aegisq.dev` la documentación, mediante dos
Workers Static Assets con Custom Domains. Cloudflare administra DNS y TLS;
la VPS no es un origin. No agregar SSR, bindings o servicios de pago al hosting.

La publicación es manual y requiere aprobación independiente: contenido revisado
en `main`, cuenta/zona correctas, Workers Free y ausencia de conflictos DNS/domains.
Credenciales fuera de Git; nunca solicitarlas por chat. Publicar docs primero,
verificar y luego home. Detenerse ante un fallo parcial; consultar el runbook.
Un merge documental no requiere tags de PyPI ni autoriza un despliegue.

## 10. Cambios que requieren aprobación

No modificar decisiones criptográficas, parámetros, formatos de tránsito,
arquitectura de capas, dependencias del core, configuración de compilación,
versión mínima Python o esquema de errores como parte de una limpieza documental.
Una discrepancia entre guía e implementación se verifica, no se corrige cambiando
silenciosamente la implementación. No redefinir soporte en `SECURITY.md` sin una
decisión explícita de mantenimiento.

## 11. Identidad del paquete

Instalación: `pip install aegisq-pqc`. Importación: `from aegisq import AegisCipher`.
El nombre de la distribución PyPI y el módulo Python son distintos identificadores.
Consultar versiones en manifiestos/PyPI, no mantener una segunda versión fija aquí.

## 12. Entrega mediante GitFlow

### 12.1 Ramas y PRs

Trabajo desde `develop`, con prefijos `feature/`, `fix/`, `chore/`, `docs/`,
`refactor/` o `test/`, y PR contra `develop`. Nombres descriptivos en kebab-case;
referenciar el issue si existe. Releases: `release/vX.Y.Z` desde `develop` hacia
`main`. Hotfixes: desde el tag estable afectado, `hotfix/vX.Y.Z`, hacia `main`
y llevar también el arreglo a `develop`.

### 12.2 Merge y protección

Solo squash merge mediante PR. Nunca commits directos, force-push, merge commits
ni rebase merge en `main`/`develop`. Si GitHub rechaza un push, respetar las reglas,
no intentar forzarlo. No revertir cambios ajenos ni tocar ediciones locales del usuario.

### 12.3 Mensajes

Conventional Commits para commits y títulos de PR (`feat`, `fix`, `docs`, `style`,
`refactor`, `perf`, `test`, `chore`, `ci`, `build`, `revert`). Marcar cambios
incompatibles con `!` y explicar `BREAKING CHANGE`. No añadir atribución de IA
ni `Co-Authored-By`.

### 12.4 Versiones de desarrollo

Después de un release, `develop` debe avanzar a la siguiente prerelease mediante
un PR de bump aislado en `pyproject.toml` y los manifiestos de ambos crates,
manteniendo los lockfiles coherentes. No mezclar cambios funcionales ni asumir que
la rama `main` o su versión de checkout siempre coinciden con el último PyPI.

### 12.5 TestPyPI antes de producción

1. Verificar que versión de manifiestos y tag RC corresponden; publicar el RC
   desde `develop` mediante `vX.Y.ZrcN` y esperar a que TestPyPI termine correctamente.
2. Preparar `release/vX.Y.Z`, actualizar los tres manifiestos y el changelog,
   ejecutar las verificaciones y abrir PR contra `main`.
3. Tras squash merge, crear/pushear el tag estable autorizado `vX.Y.Z` en `main`.
   **El tag, no el merge por sí solo, dispara `.github/workflows/release.yml`.**
4. Verificar publicación PyPI, instalación y GitHub Release antes de dar el release
   por terminado. La misma regla RC previa aplica a hotfixes.
5. Llevar diferencias del release a `develop` mediante PR si hay diferencias de
   contenido, y preparar la siguiente prerelease. No crear PRs de sync vacíos
   porque los hashes difieran después de squash; comparar árboles completos.

El job `check-branch`, step `verify-rc`, exige que exista un tag RC de la misma
versión base. No comprueba que TestPyPI haya publicado correctamente: esa
verificación sigue siendo responsabilidad del mantenedor. No saltarse el RC ni
crear tags/publicaciones como efecto secundario de cambios de documentación.

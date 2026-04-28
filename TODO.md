# Tech Debt - Actualizar rand_core a 0.10.x

**Creado:** 2026-04-28
**Estado:** Pending

---

## Tarea: Actualizar rand_core de 0.6.x a 0.10.x

### Descripción

Actualizar la dependencia `rand_core` de la versión actual `0.6.4` a la última disponible `0.10.1`.

### Contexto

- **Versión actual:** `rand_core 0.6.4` (bloqueada por constraint `version = "0.6"`)
- **Última versión:** `rand_core 0.10.1`
- **Estado:** No es urgent, pero mantener las dependencias actualizadas evita problemas de compatibilidad futuros

### Consideraciones

⚠️ **Importante:** Las versiones mayores en Rust pueden tener breaking API changes. No actualizar de golpe.

### Posibles approaches:

1. **Incremental:** 0.6 → 0.7 → 0.8 → ... → 0.10 (ir probando cada salto menor)
2. **Revisar migration guide:** Buscar si existe guía de migración oficial
3. **Evaluar alternatives:** Verificar si hay una crate alternativa más moderna que ya soporte rand_core 0.10

### Pasos a seguir:

1. Investigar cambios de API entre 0.6.x y 0.10.x
2. Hacer backup del estado actual
3. Intentar actualización incremental o directa
4. Correr `cargo build` para ver errores de compilación
5. Corregir errores de API si los hay
6. Ejecutar tests: `cargo test --workspace && pytest tests/python/`
7. Verificar: `cargo audit`

### Archivos a modificar

- `Cargo.toml` (workspace.dependencies.rand_core)
- `Cargo.lock` (se actualiza solo con `cargo update`)

---

## Otras tareas de Tech Debt pendientes

- [ ] Evaluar actualizar `aes-gcm` de 0.10.x a 0.11.x (verificar breaking changes)
- [ ] Integrar `cargo audit` en CI/CD workflow

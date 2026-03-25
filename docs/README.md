# Documentación de AegisQ

Este directorio contiene la documentación técnica del proyecto.

## Estructura de Documentación

```
docs/
├── README.md              ← Este archivo
└── DOCUMENTATION.md       ← Documentación técnica detallada
```

## Archivos en la Raíz

| Archivo | Descripción |
|---------|-------------|
| `AGENTS.md` | **Fuente de verdad del proyecto** — Reglas de arquitectura, fases de implementación, convenciones |
| `README.md` | Documentación para usuarios finales — Instalación, API básica, ejemplos |
| `pyproject.toml` | Configuración del proyecto Python |
| `Cargo.toml` | Workspace manifest de Rust |

## Navegación de Documentación

### Para Desarrolladores
1. **Comenzar aquí:** `../AGENTS.md` — Lee las reglas del proyecto antes de hacer cambios
2. **Referencia técnica:** `DOCUMENTATION.md` — Detalles de implementación, decisiones de diseño

### Para Usuarios
1. **Comenzar aquí:** `../README.md` — Instalación y uso básico
2. **API Reference:** Ver `../aegisq/` para la API Python

## Fases del Proyecto

| Estado | Fases |
|--------|-------|
| ✅ Completado | 1-26: Core criptográfico, bindings PyO3, API Python, CI/CD |
| ✅ Completado | 27-27b: KAT Vectors NIST para validación |
| 🔲 Pendiente | 28: EphemeralSession para Forward Secrecy |
| 🔲 Pendiente | 29: Métodos asíncronos |

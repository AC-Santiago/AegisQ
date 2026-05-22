# Política de Seguridad

## Versiones soportadas

| Versión | Soporte de seguridad |
|---|---|
| 1.2.x | ✅ Activo |
| 1.1.x | ✅ Activo |
| 1.0.x | ✅ Mantenimiento (parches de seguridad únicamente) |

## Reporte de vulnerabilidades

**Por favor, no reportes vulnerabilidades de seguridad como Issues públicos de GitHub.**

AegisQ implementa primitivas criptográficas post-cuánticas. Un reporte público de una
vulnerabilidad antes de que esté parcheada puede poner en riesgo a usuarios del paquete.

### Cómo reportar

Usa el canal de **reporte privado de vulnerabilidades** de GitHub:

1. Ve a la pestaña [Security](https://github.com/AC-Santiago/AegisQ/security) del repositorio
2. Haz clic en **"Report a vulnerability"**
3. Completa el formulario con la mayor cantidad de detalle posible

Recibirás una respuesta en un plazo máximo de **72 horas**.

### Qué incluir en el reporte

Para acelerar la evaluación, incluye:

- **Descripción**: Descripción clara de la vulnerabilidad y su impacto potencial
- **Componente afectado**: Módulo, clase o función específica (`MlKem`, `AegisCipher`, etc.)
- **Pasos para reproducir**: Código mínimo que demuestre el problema
- **Versión afectada**: Versión de `aegisq-pqc` donde se reproduce
- **Impacto estimado**: Confidencialidad, integridad, disponibilidad
- **Posible mitigación**: Si tienes sugerencias de cómo corregirlo

### Proceso de respuesta

```
Reporte recibido → Confirmación (≤72h) → Evaluación (≤7 días) → Parche + CVE → Disclosure público
```

1. **Confirmación** (≤ 72 horas): Acuse de recibo y asignación de severidad preliminar
2. **Evaluación** (≤ 7 días): Reproducción, análisis de impacto y plan de mitigación
3. **Parche**: Desarrollo y revisión del fix, coordinar embargo con el reportador
4. **CVE**: Solicitud de CVE si aplica
5. **Disclosure**: Publicación coordinada del advisory y release del parche

### Reconocimiento

Los investigadores que reporten vulnerabilidades válidas serán reconocidos en el
`CHANGELOG.md` de la versión que incluya el parche, salvo que prefieran permanecer anónimos.

---

## Consideraciones de seguridad del diseño

### Qué protege AegisQ

- **Confidencialidad** del shared secret y del payload cifrado
- **Autenticidad** del ciphertext via AES-256-GCM (tag de 128 bits)
- **Resistencia post-cuántica** del intercambio de claves (ML-KEM, FIPS 203)

### Qué NO protege AegisQ

- **Gestión de claves a largo plazo**: AegisQ no almacena ni gestiona claves persistentes.
  La seguridad de las claves generadas depende de cómo el usuario las almacene.
- **Anonimato o privacidad de metadatos**: AegisQ no oculta quién se comunica con quién.
- **Autenticación de identidad**: ML-KEM es un KEM, no un esquema de firma.
  Para autenticación de origen usa un esquema de firma post-cuántica (ej: ML-DSA / FIPS 204).

### Dependencias criptográficas (Rust)

| Crate | Propósito | Auditoría |
|---|---|---|
| `aegisq-core` (in-tree) | ML-KEM FIPS 203 — implementación propia, sin crate externo `ml-kem` | N/A (in-tree) |
| `aes-gcm` | AES-256-GCM FIPS 197 | RustCrypto — auditado |
| `zeroize` | Zeroización de memoria sensible | RustCrypto — auditado |
| `getrandom` | CSPRNG del sistema operativo | RustCrypto — auditado |

### Nivel de madurez

AegisQ es un proyecto en estado **Beta (v1.2.0)**. La implementación criptográfica
es FIPS 203 compliant y ha pasado los vectores KAT de NIST. Se han realizado revisiones
de seguridad internas del código Rust y los bindings FFI. Se recomienda auditoría
independiente antes de uso en sistemas de alto riesgo.

# Política de Seguridad

## Versiones soportadas

| Línea de versiones | Soporte de seguridad |
|---|---|
| Última línea estable publicada en PyPI | Recibe correcciones de seguridad |
| Líneas estables anteriores | Sin nuevos parches; actualizar a la línea soportada |
| Prereleases (`rc`, alpha, beta) | Para evaluación; sin compromiso de soporte estable |

Una línea estable corresponde a `major.minor.x`. El soporte se concentra en
la línea de la versión estable más reciente publicada en
[PyPI](https://pypi.org/project/aegisq-pqc/), no en la versión del checkout ni en
una prerelease. Dentro de esa línea, use el último patch disponible: los arreglos
se entregan mediante nuevas versiones, no modificando paquetes ya publicados.

Al publicarse una línea estable posterior, la anterior deja de recibir nuevos
parches. No se mantienen backports a líneas anteriores. Esta política sustituye
los compromisos de soporte anteriores; los usuarios de esas líneas deben
actualizar para recibir correcciones de seguridad.

El canal privado de reporte siguiente sigue disponible, pero un reporte sobre
una línea sin soporte no implica el compromiso de publicar un parche para ella.
Consulte [CHANGELOG.md](CHANGELOG.md) para el historial de releases.

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
- **Forward secrecy o borrado completo de secretos**: `EphemeralSession.close()`
  descarta la referencia al keypair, pero no garantiza la zeroización de todas
  sus copias Rust/Python. El context manager de `AegisCipher` solo sobrescribe
  buffers mutables registrados mediante su hook privado.
- **Protección contra replay**: debe implementarse en el protocolo de la aplicación.

### Dependencias criptográficas (Rust)

| Crate | Propósito | Alcance |
|---|---|---|
| `aegisq-core` (in-tree) | Implementación propia de ML-KEM según FIPS 203 | No se presenta una auditoría independiente de AegisQ |
| `aes-gcm` | AES-256-GCM según NIST SP 800-38D; AES según FIPS 197 | RustCrypto; una auditoría upstream no certifica esta integración |
| `zeroize` | Sobrescritura de buffers sensibles seleccionados | No cubre automáticamente todas las copias Rust/Python |
| `getrandom` | Aleatoriedad del sistema operativo | Los errores del SO deben propagarse |

### Nivel de madurez

AegisQ declara estado **Beta** en `pyproject.toml`. Implementa ML-KEM según FIPS 203
y contiene tests con vectores NIST ACVP: el runner Python compara resultados
esperados de KeyGen y encapsulación; otros tests comprueban roundtrips y rechazo
implícito. La presencia de tests no acredita el resultado de una ejecución actual,
una validación ACVP oficial ni una certificación FIPS 140 de AegisQ.

No se presenta aquí evidencia de una auditoría independiente de la implementación
completa. Se recomienda realizarla antes del uso en sistemas de alto riesgo.
Los mecanismos y límites se detallan en el
[modelo de seguridad](website/src/content/docs/es/internals/security-model.md).

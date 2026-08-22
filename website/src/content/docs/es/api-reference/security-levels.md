---
title: Niveles de Seguridad
description: Niveles de seguridad ML-KEM — tamaños de clave, tamaños de capsule y overhead de paquete para ML-KEM-512, 768 y 1024.
---

AegisQ soporta los tres niveles de seguridad ML-KEM definidos en FIPS 203. El default es **ML-KEM-768** (NIST Nivel 3), que provee un balance óptimo de seguridad y rendimiento para la mayoría de las aplicaciones.

## Comparación de Niveles de Seguridad

| Nivel | Valor del Enum | NIST Level | Clave Pública | Clave Secreta | Capsule | Overhead del Paquete |
|-------|----------------|------------|---------------|---------------|---------|----------------------|
| ML-KEM-512 | `SecurityLevel.ML_KEM_512` | 1 | 800 B | 1632 B | 768 B | 796 B |
| ML-KEM-768 | `SecurityLevel.ML_KEM_768` | 3 (default) | 1184 B | 2400 B | 1088 B | 1116 B |
| ML-KEM-1024 | `SecurityLevel.ML_KEM_1024` | 5 | 1568 B | 3168 B | 1568 B | 1596 B |

**Overhead del paquete** = capsule + AES nonce (12 B) + AES auth tag (16 B). El tamaño total del paquete cifrado es overhead + longitud del plaintext.

## Niveles de Seguridad NIST Explicados

- **Nivel 1** — Al menos tan difícil de romper como AES-128. Adecuado para protección de datos de corto plazo.
- **Nivel 3** — Al menos tan difícil de romper como AES-192. Recomendado para la mayoría de las aplicaciones. **(Default)**
- **Nivel 5** — Al menos tan difícil de romper como AES-256. Máxima seguridad para los datos más sensibles.

## Uso

```python
from aegisq import AegisCipher, SecurityLevel

# Default: ML-KEM-768 (NIST Nivel 3)
cipher = AegisCipher()

# Selección explícita del nivel
cipher_512 = AegisCipher(level=SecurityLevel.ML_KEM_512)    # Más rápido, claves más pequeñas
cipher_768 = AegisCipher(level=SecurityLevel.ML_KEM_768)    # Recomendado (default)
cipher_1024 = AegisCipher(level=SecurityLevel.ML_KEM_1024)  # Máxima seguridad
```

## Parámetros del Núcleo (FIPS 203)

Estos son los parámetros internos de ML-KEM para cada nivel de seguridad:

| Nivel | k | η₁ | η₂ | dᵤ | dᵥ | pk size | sk size | ct size | ss size |
|-------|---|----|----|----|----|---------|---------|---------|---------|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 B | 3168 B | 1568 B | 32 B |

Donde:
- **k** — Dimensión del módulo (número de vectores de polinomios)
- **η₁, η₂** — Parámetros de muestreo CBD para los términos de error
- **dᵤ, d�** — Anchos de bits de compresión
- **pk** — Clave pública, **sk** — Clave secreta, **ct** — Ciphertext (capsule), **ss** — Shared secret

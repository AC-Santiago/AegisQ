---
title: Niveles de Seguridad
description: Niveles de seguridad ML-KEM — tamaños de clave, tamaños de capsule y overhead de paquete para ML-KEM-512, 768 y 1024.
---

AegisQ admite los tres conjuntos de parámetros ML-KEM de FIPS 203. El predeterminado es **ML-KEM-768** (categoría NIST 3). Seleccione parámetros según su protocolo, modelo de amenazas y requisitos de interoperabilidad; una categoría no certifica esta implementación.

## Comparación de Niveles de Seguridad

| Nivel | Valor del Enum | NIST Level | Clave Pública | Clave Secreta | Capsule | Overhead del Paquete |
|-------|----------------|------------|---------------|---------------|---------|----------------------|
| ML-KEM-512 | `SecurityLevel.ML_KEM_512` | 1 | 800 B | 1632 B | 768 B | 796 B |
| ML-KEM-768 | `SecurityLevel.ML_KEM_768` | 3 (default) | 1184 B | 2400 B | 1088 B | 1116 B |
| ML-KEM-1024 | `SecurityLevel.ML_KEM_1024` | 5 | 1568 B | 3168 B | 1568 B | 1596 B |

**Overhead del paquete one-shot** = capsule + AES nonce (12 B) + AES auth tag (16 B). El tamaño total one-shot es overhead + longitud del plaintext. Streaming usa otro formato de header/frames.

## Niveles de Seguridad NIST Explicados

- **Categoría 1** — Usa la búsqueda exhaustiva de claves AES-128 como objetivo de comparación NIST.
- **Categoría 3** — Usa la búsqueda exhaustiva de claves AES-192 como objetivo de comparación. **Predeterminado de AegisQ.**
- **Categoría 5** — Usa la búsqueda exhaustiva de claves AES-256 como objetivo de comparación.

Son categorías de seguridad del algoritmo, no garantías de un período de retención ni equivalencias literales de seguridad en bits para todo ataque. Los tres modos híbridos usan **AES-256-GCM** para el payload.

## Uso

```python
from aegisq import AegisCipher, SecurityLevel

# Default: ML-KEM-768 (NIST Nivel 3)
cipher = AegisCipher()

# Selección explícita del nivel
cipher_512 = AegisCipher(level=SecurityLevel.ML_KEM_512)    # Categoría 1, claves más pequeñas
cipher_768 = AegisCipher(level=SecurityLevel.ML_KEM_768)    # Categoría 3 (predeterminado)
cipher_1024 = AegisCipher(level=SecurityLevel.ML_KEM_1024)  # Categoría 5, claves más grandes
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
- **dᵤ, dᵥ** — Anchos de bits de compresión
- **pk** — Clave pública, **sk** — Clave secreta, **ct** — Ciphertext (capsule), **ss** — Shared secret

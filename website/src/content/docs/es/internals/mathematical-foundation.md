---
title: Fundamentos Matemáticos
description: Fundamento matemático de ML-KEM — M-LWE, NTT y los tres algoritmos centrales de FIPS 203.
---

ML-KEM se basa en el problema **Module Learning With Errors (M-LWE)**. La aritmética polinomial se realiza en el anillo:

```text
Rq = Zq[X] / (X^256 + 1)    donde q = 3329
```

## Parámetros del Núcleo por Nivel de Seguridad

| Nivel | k | η₁ | η₂ | dᵤ | dᵥ | pk size | sk size | ct size | ss size |
|-------|---|----|----|----|----|---------|---------|---------|---------|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 B | 3168 B | 1568 B | 32 B |

Donde:
- **k** — Dimensión del módulo (número de vectores de polinomios)
- **η₁, η₂** — Parámetros de muestreo CBD para los términos de error
- **dᵤ, dᵥ** — Anchos de bits de compresión para los componentes del ciphertext
- **pk** — Clave pública, **sk** — Clave secreta, **ct** — Ciphertext (capsule), **ss** — Shared secret (siempre 32 bytes)

## Number Theoretic Transform (NTT)

La NTT es la transformada discreta de Fourier sobre campos finitos. Permite multiplicación polinomial en O(n log n) en lugar de O(n²).

En ML-KEM, `ζ = 17` es una raíz primitiva 256-ésima de la unidad en ℤq. La transformada representa un polinomio mediante 128 residuos de grado uno módulo los factores de `X^256 + 1`, con potencias de `ζ` en orden de bits invertidos. No es una evaluación escalar de 256 puntos; la multiplicación opera sobre pares de coeficientes en el dominio NTT.

AegisQ implementa la NTT usando la **butterfly de Cooley-Tukey** para la transformada directa y la **butterfly de Gentleman-Sande** para la transformada inversa, siguiendo FIPS 203 §4.3.

## Los Tres Algoritmos Centrales (FIPS 203)

Los siguientes resúmenes describen los algoritmos internos (15–17). Las operaciones públicas aleatorias obtienen sus semillas/mensajes del SO. Se abrevia la codificación, compresión y validación; FIPS 203 contiene los algoritmos normativos.

### ML-KEM.KeyGen_internal (Algoritmo 15)

Genera una clave pública para cifrar y una clave secreta para desencapsular.

```text
Input:  d, z (semillas aleatorias independientes de 32 bytes), k (dimensión del módulo)
Output: (pk, sk)

1. (ρ, σ) := G(d || byte(k))    # G es SHA3-512
2. A_hat := SampleMatrix(ρ, k)
3. s := SampleCBD(σ, η₁, k)
4. e := SampleCBD(σ, η₁, k)
5. s_hat := NTT(s); e_hat := NTT(e)
6. t_hat := A_hat · s_hat + e_hat
7. pk := ByteEncode12(t_hat) || ρ
8. sk := ByteEncode12(s_hat) || pk || H(pk) || z
```

**Puntos clave:**
- `G` (SHA3-512) divide la semilla en una semilla pública `ρ` (para la generación de la matriz) y una semilla privada `σ` (para el muestreo de secretos/errores)
- La matriz `A_hat` se genera determinísticamente desde `ρ` usando SHAKE-128
- `s` y `e` son polinomios de error pequeños muestreados desde la distribución binomial centrada (CBD)
- La clave secreta incluye una copia de la clave pública y un hash `H(pk)` para uso en la desencapsulación
- `z` es una semilla de rechazo aleatoria de 32 bytes usada para el implicit rejection en Decaps

### ML-KEM.Encaps_internal (Algoritmo 16)

Produce una clave encapsulada (capsule) y un shared secret.

```text
Input:  pk (clave pública), m (mensaje aleatorio fresco de 32 bytes)
Output: (K, c)  donde K es el shared_secret (32 bytes), c es la capsule

1. (K, r) := G(m || H(pk))
2. c := K-PKE.Encrypt(pk, m, r)    # Incluye compresión y codificación
3. return (K, c)
```

**Puntos clave:**
- `m` es un mensaje aleatorio fresco (no es el plaintext del usuario — es interno a ML-KEM)
- La aleatoriedad `r` para el cifrado se deriva determinísticamente desde `m` y `H(pk)`, permitiendo re-cifrado durante la verificación de desencapsulación
- `K` son los primeros 32 bytes de `G(m || H(pk))`; no se aplica un `KDF(K || H(c))` adicional

### ML-KEM.Decaps_internal (Algoritmo 17) — Implicit Rejection

Recupera el shared secret desde una capsule. El **contenido inválido de tamaño correcto** activa implicit rejection. Los tamaños incorrectos de clave/capsule son errores estructurales en AegisQ.

```text
Input:  c (capsule), sk (clave secreta)
Output: K (shared secret de 32 bytes; sin error de validez por contenido de capsule)

1. Parsear sk como (dk_pke, pk, h, z)
2. m' := K-PKE.Decrypt(dk_pke, c)
3. (K', r') := G(m' || h)
4. K_reject := J(z || c)              # SHAKE256, salida de 32 bytes
5. c' := K-PKE.Encrypt(pk, m', r')
6. return ct_select(ct_eq(c, c'), K', K_reject)
```

:::caution[Propiedad de Seguridad Crítica]
Para entradas de tamaño correcto, el contenido inválido devuelve una **clave pseudoaleatoria** en lugar de una excepción de validez. Es la defensa de ML-KEM contra oráculos de validez de capsules, no una afirmación de inmunidad integral a canales laterales ni una certificación.
:::

**Puntos clave:**
- El paso 5 vuelve a cifrar `m'` con la aleatoriedad derivada; una capsule válida coincide con `c'`
- El paso 6 usa `subtle::ConstantTimeEq` y `ConditionallySelectable`, no un `if` ordinario dependiente de secretos
- La clave de rechazo depende de `z` y de la capsule completa `c`, no de `H(c)`, y es determinística para esas entradas

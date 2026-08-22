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

```text
NTT(f) = [f(ζ^(2i+1)) mod q] para i = 0..127
```

Donde `ζ = 17` es una raíz primitiva 256-ésima de la unidad en ℤq.

AegisQ implementa la NTT usando la **butterfly de Cooley-Tukey** para la transformada directa y la **butterfly de Gentleman-Sande** para la transformada inversa, siguiendo FIPS 203 §4.3.

## Los Tres Algoritmos Centrales (FIPS 203)

### ML-KEM.KeyGen (Algorithm 15)

Genera una clave pública para cifrar y una clave secreta para desencapsular.

```text
Input:  d (semilla aleatoria de 32 bytes)
Output: (pk, sk)

1. (ρ, σ) := G(d)              # G es SHA3-512
2. A_hat := SampleMatrix(ρ, k)
3. s := SampleCBD(σ, η₁, k)
4. e := SampleCBD(σ, η₁, k)
5. t_hat := NTT(A_hat · s + e)
6. pk := (t_hat || ρ)
7. sk := (s || pk || H(pk) || z)   # z son 32 bytes aleatorios
```

**Puntos clave:**
- `G` (SHA3-512) divide la semilla en una semilla pública `ρ` (para la generación de la matriz) y una semilla privada `σ` (para el muestreo de secretos/errores)
- La matriz `A_hat` se genera determinísticamente desde `ρ` usando SHAKE-128
- `s` y `e` son polinomios de error pequeños muestreados desde la distribución binomial centrada (CBD)
- La clave secreta incluye una copia de la clave pública y un hash `H(pk)` para uso en la desencapsulación
- `z` es una semilla de rechazo aleatoria de 32 bytes usada para el implicit rejection en Decaps

### ML-KEM.Encaps (Algorithm 16)

Produce una clave encapsulada (capsule) y un shared secret.

```text
Input:  pk (clave pública)
Output: (K, c)  donde K es el shared_secret (32 bytes), c es la capsule

1. m := random(32)
2. (K_bar, r) := G(m || H(pk))
3. (u, v) := Encrypt(pk, m, r)
4. c := Compress(u, v)
5. K := KDF(K_bar || H(c))         # Shared secret final de 32 bytes
```

**Puntos clave:**
- `m` es un mensaje aleatorio fresco (no es el plaintext del usuario — es interno a ML-KEM)
- La aleatoriedad `r` para el cifrado se deriva determinísticamente desde `m` y `H(pk)`, permitiendo re-cifrado durante la verificación de desencapsulación
- El shared secret final `K` se deriva vía KDF, vinculándolo al hash del ciphertext `H(c)`

### ML-KEM.Decaps (Algorithm 17) — Implicit Rejection

Recupera el shared secret desde una capsule. **Nunca retorna un error por ciphertext inválido.**

```text
Input:  c (capsule), sk (clave secreta)
Output: K (shared secret — ¡NUNCA un error por ciphertext inválido!)

1. Parsear sk como (s, pk, h, z)
2. m' := Decrypt(c, s)
3. (K_bar', r') := G(m' || h)
4. c' := Encaps_internal(pk, m', r')
5. if ct_eq(c, c'):                  # Comparación en TIEMPO CONSTANTE (subtle::ConstantTimeEq)
       return KDF(K_bar' || H(c))
   else:                              # IMPLICIT REJECTION — sin excepción, sin oracle
       return KDF(z || H(c))         # Clave pseudoaleatoria derivada de z
```

:::caution[Propiedad de Seguridad Crítica]
Un ciphertext inválido retorna una **clave pseudoaleatoria** en lugar de lanzar una excepción. Esto previene **Chosen Ciphertext Attacks (CCA)** vía queries de oracle. Un atacante no puede distinguir entre una desencapsulación válida e inválida, porque ambas producen salidas de 32 bytes que se ven uniformemente aleatorias.
:::

**Puntos clave:**
- El paso 4 re-cifra el mensaje descifrado `m'` usando la misma aleatoriedad determinística — si el ciphertext era válido, el re-cifrado `c'` coincidirá con el `c` original
- El paso 5 usa **comparación en tiempo constante** (`subtle::ConstantTimeEq`) para prevenir canales laterales de timing
- La rama de rechazo deriva una clave desde `z` (la semilla de rechazo secreta almacenada en `sk`) — esto asegura que la clave pseudoaleatoria sea determinística para los mismos inputs, previniendo ataques multi-query

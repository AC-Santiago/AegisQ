---
title: Mathematical Foundation
description: ML-KEM mathematical foundation — M-LWE, NTT, and the three core FIPS 203 algorithms.
---

ML-KEM is based on the **Module Learning With Errors (M-LWE)** problem. Polynomial arithmetic is performed in the ring:

```text
Rq = Zq[X] / (X^256 + 1)    where q = 3329
```

## Core Parameters by Security Level

| Level | k | η₁ | η₂ | dᵤ | dᵥ | pk size | sk size | ct size | ss size |
|-------|---|----|----|----|----|---------|---------|---------|---------|
| ML-KEM-512 | 2 | 3 | 2 | 10 | 4 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 2 | 2 | 10 | 4 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 4 | 2 | 2 | 11 | 5 | 1568 B | 3168 B | 1568 B | 32 B |

Where:
- **k** — Module dimension (number of polynomial vectors)
- **η₁, η₂** — CBD sampling parameters for error terms
- **dᵤ, dᵥ** — Compression bit-widths for ciphertext components
- **pk** — Public key, **sk** — Secret key, **ct** — Ciphertext (capsule), **ss** — Shared secret (always 32 bytes)

## Number Theoretic Transform (NTT)

The NTT is the discrete Fourier transform over finite fields. It allows polynomial multiplication in O(n log n) instead of O(n²).

For ML-KEM, `ζ = 17` is a primitive 256th root of unity in ℤq. The transform represents a polynomial as 128 degree-one residues modulo factors of `X^256 + 1`, using bit-reversed powers of `ζ`. It is not a 256-point scalar evaluation transform; multiplication uses paired coefficients in the NTT domain.

AegisQ implements the NTT using the **Cooley-Tukey butterfly** for the forward transform and the **Gentleman-Sande butterfly** for the inverse transform, following FIPS 203 §4.3.

## The Three Core Algorithms (FIPS 203)

The summaries below describe the internal algorithms (15–17). The randomized public operations obtain their seeds/messages from the OS. Encoding, compression, and validation are abbreviated; consult FIPS 203 for the normative algorithms.

### ML-KEM.KeyGen_internal (Algorithm 15)

Generates a public key for encryption and a secret key for decapsulation.

```text
Input:  d, z (independent 32-byte random seeds), k (module dimension)
Output: (pk, sk)

1. (ρ, σ) := G(d || byte(k))    # G is SHA3-512
2. A_hat := SampleMatrix(ρ, k)
3. s := SampleCBD(σ, η₁, k)
4. e := SampleCBD(σ, η₁, k)
5. s_hat := NTT(s); e_hat := NTT(e)
6. t_hat := A_hat · s_hat + e_hat
7. pk := ByteEncode12(t_hat) || ρ
8. sk := ByteEncode12(s_hat) || pk || H(pk) || z
```

**Key points:**
- `G` (SHA3-512) splits the seed into a public seed `ρ` (for matrix generation) and a private seed `σ` (for secret/error sampling)
- The matrix `A_hat` is generated deterministically from `ρ` using SHAKE-128
- `s` and `e` are small error polynomials sampled from the Centered Binomial Distribution (CBD)
- The secret key includes a copy of the public key and a hash `H(pk)` for use in decapsulation
- `z` is a random 32-byte rejection seed used for implicit rejection in Decaps

### ML-KEM.Encaps_internal (Algorithm 16)

Produces an encapsulated key (capsule) and a shared secret.

```text
Input:  pk (public key), m (fresh random 32-byte message)
Output: (K, c)  where K is shared_secret (32 bytes), c is the capsule

1. (K, r) := G(m || H(pk))
2. c := K-PKE.Encrypt(pk, m, r)    # Includes compression and encoding
3. return (K, c)
```

**Key points:**
- `m` is a fresh random message (not the user's plaintext — this is internal to ML-KEM)
- The randomness `r` for encryption is derived deterministically from `m` and `H(pk)`, enabling re-encryption during decapsulation verification
- `K` is the first 32 bytes of `G(m || H(pk))`; no additional `KDF(K || H(c))` is applied

### ML-KEM.Decaps_internal (Algorithm 17) — Implicit Rejection

Recovers the shared secret from a capsule. Invalid **contents of the correct size** trigger implicit rejection. Incorrect key/capsule sizes are structural errors in AegisQ.

```text
Input:  c (capsule), sk (secret key)
Output: K (32-byte shared secret; no validity error for capsule contents)

1. Parse sk as (dk_pke, pk, h, z)
2. m' := K-PKE.Decrypt(dk_pke, c)
3. (K', r') := G(m' || h)
4. K_reject := J(z || c)              # SHAKE256, 32-byte output
5. c' := K-PKE.Encrypt(pk, m', r')
6. return ct_select(ct_eq(c, c'), K', K_reject)
```

:::caution[Critical Security Property]
For correctly sized inputs, invalid capsule contents return a **pseudorandom key** instead of a validity exception. This is ML-KEM's defense against capsule-validity oracles, not a claim of complete side-channel immunity or certification.
:::

**Key points:**
- Step 5 re-encrypts `m'` with the derived randomness; a valid capsule matches `c'`
- Step 6 uses `subtle::ConstantTimeEq` and `ConditionallySelectable`, not an ordinary secret-dependent `if`
- The rejection key depends on `z` and the complete capsule `c`, not `H(c)`, and is deterministic for those inputs

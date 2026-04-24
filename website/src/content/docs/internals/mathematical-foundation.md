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

```text
NTT(f) = [f(ζ^(2i+1)) mod q] for i = 0..127
```

Where `ζ = 17` is a primitive 256th root of unity in ℤq.

AegisQ implements the NTT using the **Cooley-Tukey butterfly** for the forward transform and the **Gentleman-Sande butterfly** for the inverse transform, following FIPS 203 §4.3.

## The Three Core Algorithms (FIPS 203)

### ML-KEM.KeyGen (Algorithm 15)

Generates a public key for encryption and a secret key for decapsulation.

```text
Input:  d (32-byte random seed)
Output: (pk, sk)

1. (ρ, σ) := G(d)              # G is SHA3-512
2. A_hat := SampleMatrix(ρ, k)
3. s := SampleCBD(σ, η₁, k)
4. e := SampleCBD(σ, η₁, k)
5. t_hat := NTT(A_hat · s + e)
6. pk := (t_hat || ρ)
7. sk := (s || pk || H(pk) || z)   # z is random 32 bytes
```

**Key points:**
- `G` (SHA3-512) splits the seed into a public seed `ρ` (for matrix generation) and a private seed `σ` (for secret/error sampling)
- The matrix `A_hat` is generated deterministically from `ρ` using SHAKE-128
- `s` and `e` are small error polynomials sampled from the Centered Binomial Distribution (CBD)
- The secret key includes a copy of the public key and a hash `H(pk)` for use in decapsulation
- `z` is a random 32-byte rejection seed used for implicit rejection in Decaps

### ML-KEM.Encaps (Algorithm 16)

Produces an encapsulated key (capsule) and a shared secret.

```text
Input:  pk (public key)
Output: (K, c)  where K is shared_secret (32 bytes), c is the capsule

1. m := random(32)
2. (K_bar, r) := G(m || H(pk))
3. (u, v) := Encrypt(pk, m, r)
4. c := Compress(u, v)
5. K := KDF(K_bar || H(c))         # Final 32-byte shared secret
```

**Key points:**
- `m` is a fresh random message (not the user's plaintext — this is internal to ML-KEM)
- The randomness `r` for encryption is derived deterministically from `m` and `H(pk)`, enabling re-encryption during decapsulation verification
- The final shared secret `K` is derived via KDF, binding it to the ciphertext hash `H(c)`

### ML-KEM.Decaps (Algorithm 17) — Implicit Rejection

Recovers the shared secret from a capsule. **Never returns an error for invalid ciphertext.**

```text
Input:  c (capsule), sk (secret key)
Output: K (shared secret — NEVER an error for invalid ciphertext!)

1. Parse sk as (s, pk, h, z)
2. m' := Decrypt(c, s)
3. (K_bar', r') := G(m' || h)
4. c' := Encaps_internal(pk, m', r')
5. if ct_eq(c, c'):                  # CONSTANT-TIME comparison (subtle::ConstantTimeEq)
       return KDF(K_bar' || H(c))
   else:                              # IMPLICIT REJECTION — no exception, no oracle
       return KDF(z || H(c))         # Pseudorandom key derived from z
```

:::caution[Critical Security Property]
Invalid ciphertext returns a **pseudorandom key** instead of throwing an exception. This prevents **Chosen Ciphertext Attacks (CCA)** via oracle queries. An attacker cannot distinguish between a valid and invalid decapsulation, because both produce uniformly random-looking 32-byte outputs.
:::

**Key points:**
- Step 4 re-encrypts the decrypted message `m'` using the same deterministic randomness — if the ciphertext was valid, the re-encryption `c'` will match the original `c`
- Step 5 uses **constant-time comparison** (`subtle::ConstantTimeEq`) to prevent timing side channels
- The rejection branch derives a key from `z` (the secret rejection seed stored in `sk`) — this ensures the pseudorandom key is deterministic for the same inputs, preventing multi-query attacks

//! Number Theoretic Transform (NTT) sobre Z_q.
//!
//! Implementa la NTT y su inversa para multiplicacion eficiente
//! de polinomios en R_q = Z_q[X]/(X^256 + 1).
//!
//! La NTT transforma un polinomio de 256 coeficientes del dominio
//! normal al dominio NTT, permitiendo multiplicacion punto-a-punto
//! en O(n) en lugar de convolucion en O(n^2).
//!
//! FIPS 203 §4.3 — Number Theoretic Transform.
//!
//! Fase 2 de la hoja de ruta.

use crate::mlkem::math::field::FieldElement;
use crate::mlkem::params::N;

// ---------------------------------------------------------------------------
// Precomputed constants
// ---------------------------------------------------------------------------

/// Precomputed zeta powers in bit-reversed order for NTT.
///
/// `ZETAS[i] = zeta^{BitRev_7(i)} mod q` where zeta = 17, q = 3329.
///
/// BitRev_7 is the 7-bit reversal function. These values are used as
/// twiddle factors in the Cooley-Tukey (NTT) and Gentleman-Sande (INTT)
/// butterfly operations.
///
/// FIPS 203 §4.3.
const ZETAS: [u16; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

/// Inverse of 128 in Z_q: 128^{-1} mod 3329 = 3303.
///
/// Used to scale the output of the inverse NTT.
/// The ML-KEM NTT is a 128-point transform (operating on pairs of
/// coefficients in the quotient ring), so the scaling factor is 128,
/// not 256.
/// Verification: 128 * 3303 = 422784, and 422784 mod 3329 = 1.
const N_INV: u16 = 3303;

// ---------------------------------------------------------------------------
// NTT (forward transform)
// ---------------------------------------------------------------------------

/// Forward Number Theoretic Transform (in-place).
///
/// Transforms a polynomial from the coefficient domain to the NTT domain.
/// Uses the Cooley-Tukey butterfly algorithm with precomputed zeta powers.
///
/// FIPS 203 Algorithm 9 (NTT).
///
/// Input:  f = [f_0, f_1, ..., f_255] in coefficient domain
/// Output: f_hat = NTT(f), in-place modification
///
/// After NTT, the polynomial is represented as 128 pairs of elements,
/// where each pair corresponds to evaluation at (zeta^(2*brv(i)+1), zeta^(-(2*brv(i)+1))).
pub fn ntt(coeffs: &mut [FieldElement; N]) {
    let mut k: usize = 1;
    let mut len: usize = 128;

    while len >= 2 {
        let mut start: usize = 0;
        while start < N {
            let zeta = FieldElement::new(ZETAS[k]);
            k += 1;

            let mut j = start;
            while j < start + len {
                let t = zeta.mul(coeffs[j + len]);
                coeffs[j + len] = coeffs[j].sub(t);
                coeffs[j] = coeffs[j].add(t);
                j += 1;
            }

            start += 2 * len;
        }
        len >>= 1;
    }
}

// ---------------------------------------------------------------------------
// Inverse NTT
// ---------------------------------------------------------------------------

/// Inverse Number Theoretic Transform (in-place).
///
/// Transforms a polynomial from the NTT domain back to the coefficient domain.
/// Uses the Gentleman-Sande butterfly algorithm, walking the zetas table
/// in reverse with negated twiddle factors.
///
/// FIPS 203 Algorithm 10 (NTT^{-1}).
///
/// Input:  f_hat in NTT domain
/// Output: f = NTT^{-1}(f_hat), in-place modification, scaled by 128^{-1}
pub fn ntt_inverse(coeffs: &mut [FieldElement; N]) {
    let mut k: usize = 127;
    let mut len: usize = 2;

    while len <= 128 {
        let mut start: usize = 0;
        while start < N {
            // Use the NEGATION of zetas[k] for the inverse transform.
            // This is equivalent to using zeta^{-(brv(k)+1)} as specified
            // in FIPS 203 Algorithm 10.
            let zeta = FieldElement::new(ZETAS[k]).neg();
            k = k.wrapping_sub(1);
            let mut j = start;
            while j < start + len {
                let t = coeffs[j];
                coeffs[j] = t.add(coeffs[j + len]);
                coeffs[j + len] = zeta.mul(t.sub(coeffs[j + len]));
                j += 1;
            }

            start += 2 * len;
        }
        len <<= 1;
    }

    // Scale all coefficients by 128^{-1} mod q.
    // The ML-KEM NTT is a 128-point transform (on degree-1 polynomial pairs).
    let n_inv = FieldElement::new(N_INV);
    for coeff in coeffs.iter_mut() {
        *coeff = coeff.mul(n_inv);
    }
}

// ---------------------------------------------------------------------------
// Basemul — multiplication in NTT domain
// ---------------------------------------------------------------------------

/// Base case multiplication of two degree-1 polynomials in the NTT domain.
///
/// Given `(a0, a1)` and `(b0, b1)` representing polynomials in
/// `Z_q[X]/(X^2 - gamma)`, computes their product `(c0, c1)` where:
///
///   c0 = a0*b0 + a1*b1*gamma
///   c1 = a0*b1 + a1*b0
///
/// FIPS 203 Algorithm 11 (BaseCaseMultiply).
///
/// `gamma` is the appropriate power of zeta for this pair.
#[inline]
pub fn basemul(
    a0: FieldElement,
    a1: FieldElement,
    b0: FieldElement,
    b1: FieldElement,
    gamma: FieldElement,
) -> (FieldElement, FieldElement) {
    let c0 = a0.mul(b0).add(a1.mul(b1).mul(gamma));
    let c1 = a0.mul(b1).add(a1.mul(b0));
    (c0, c1)
}

/// Multiply two polynomials in NTT domain, producing the NTT domain result.
///
/// Each polynomial is 256 FieldElements in NTT representation (128 pairs).
/// The i-th pair uses `gamma = zetas[64 + i/2]` (the twiddle factor for
/// the leaf-level butterfly).
///
/// This is the entry point for polynomial multiplication in NTT domain.
/// Both inputs must already be in NTT domain. The output is also in NTT domain.
pub fn ntt_multiply(a: &[FieldElement; N], b: &[FieldElement; N], result: &mut [FieldElement; N]) {
    // 128 pairs of basemul operations
    // Pair i uses coefficients (2i, 2i+1) with gamma = zetas[64 + i]
    for i in 0..64 {
        // First pair in the block
        let gamma_pos = FieldElement::new(ZETAS[64 + i]);
        let (c0, c1) = basemul(a[4 * i], a[4 * i + 1], b[4 * i], b[4 * i + 1], gamma_pos);
        result[4 * i] = c0;
        result[4 * i + 1] = c1;

        // Second pair in the block uses -gamma
        let gamma_neg = gamma_pos.neg();
        let (c0, c1) = basemul(
            a[4 * i + 2],
            a[4 * i + 3],
            b[4 * i + 2],
            b[4 * i + 3],
            gamma_neg,
        );
        result[4 * i + 2] = c0;
        result[4 * i + 3] = c1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Helper: create a zero polynomial.
    fn zero_poly() -> [FieldElement; N] {
        [FieldElement::ZERO; N]
    }

    /// Helper: create a polynomial from a slice of u16 values.
    fn poly_from_slice(values: &[u16]) -> [FieldElement; N] {
        let mut poly = zero_poly();
        for (i, &v) in values.iter().enumerate() {
            if i < N {
                poly[i] = FieldElement::new(v);
            }
        }
        poly
    }

    // --- Basic NTT/INTT round-trip ---

    #[test]
    fn test_ntt_inverse_roundtrip_zero() {
        let mut poly = zero_poly();
        ntt(&mut poly);
        ntt_inverse(&mut poly);
        for (i, c) in poly.iter().enumerate() {
            assert_eq!(c.value(), 0, "coefficient {i} should be 0 after roundtrip");
        }
    }

    #[test]
    fn test_ntt_inverse_roundtrip_one() {
        // Polynomial: f(X) = 1 (constant)
        let original = poly_from_slice(&[1]);
        let mut poly = original;
        ntt(&mut poly);
        ntt_inverse(&mut poly);
        for (i, c) in poly.iter().enumerate() {
            assert_eq!(
                c.value(),
                original[i].value(),
                "coefficient {i} mismatch after roundtrip"
            );
        }
    }

    #[test]
    fn test_ntt_inverse_roundtrip_x() {
        // Polynomial: f(X) = X → coefficients [0, 1, 0, ..., 0]
        let original = poly_from_slice(&[0, 1]);
        let mut poly = original;
        ntt(&mut poly);
        ntt_inverse(&mut poly);
        for (i, c) in poly.iter().enumerate() {
            assert_eq!(
                c.value(),
                original[i].value(),
                "coefficient {i} mismatch after roundtrip"
            );
        }
    }

    #[test]
    fn test_ntt_inverse_roundtrip_arbitrary() {
        // Polynomial with arbitrary coefficients
        let mut values = [0u16; N];
        for (i, v) in values.iter_mut().enumerate() {
            *v = ((i * 37 + 13) % 3329) as u16;
        }
        let original = poly_from_slice(&values);
        let mut poly = original;
        ntt(&mut poly);
        ntt_inverse(&mut poly);
        for (i, c) in poly.iter().enumerate() {
            assert_eq!(
                c.value(),
                original[i].value(),
                "coefficient {i} mismatch after arbitrary roundtrip"
            );
        }
    }

    #[test]
    fn test_ntt_inverse_roundtrip_all_ones() {
        let values = [1u16; N];
        let original = poly_from_slice(&values);
        let mut poly = original;
        ntt(&mut poly);
        ntt_inverse(&mut poly);
        for (i, c) in poly.iter().enumerate() {
            assert_eq!(
                c.value(),
                original[i].value(),
                "coefficient {i} mismatch for all-ones roundtrip"
            );
        }
    }

    #[test]
    fn test_ntt_inverse_roundtrip_max_values() {
        // All coefficients at Q-1 = 3328
        let values = [3328u16; N];
        let original = poly_from_slice(&values);
        let mut poly = original;
        ntt(&mut poly);
        ntt_inverse(&mut poly);
        for (i, c) in poly.iter().enumerate() {
            assert_eq!(
                c.value(),
                original[i].value(),
                "coefficient {i} mismatch for max-values roundtrip"
            );
        }
    }

    // --- NTT changes the polynomial ---

    #[test]
    fn test_ntt_is_not_identity() {
        // NTT of a non-trivial polynomial should differ from the input
        let original = poly_from_slice(&[1, 2, 3, 4, 5]);
        let mut poly = original;
        ntt(&mut poly);

        let mut all_same = true;
        for i in 0..N {
            if poly[i].value() != original[i].value() {
                all_same = false;
                break;
            }
        }
        assert!(!all_same, "NTT should transform the polynomial");
    }

    // --- NTT linearity ---

    #[test]
    fn test_ntt_linearity() {
        // NTT(a + b) == NTT(a) + NTT(b) (pointwise)
        let a_vals: Vec<u16> = (0..N).map(|i| ((i * 7 + 3) % 3329) as u16).collect();
        let b_vals: Vec<u16> = (0..N).map(|i| ((i * 11 + 5) % 3329) as u16).collect();

        let mut a = poly_from_slice(&a_vals);
        let mut b = poly_from_slice(&b_vals);

        // a + b
        let mut sum = zero_poly();
        for i in 0..N {
            sum[i] = a[i].add(b[i]);
        }

        ntt(&mut a);
        ntt(&mut b);
        ntt(&mut sum);

        for i in 0..N {
            let expected = a[i].add(b[i]);
            assert_eq!(
                sum[i].value(),
                expected.value(),
                "NTT linearity failed at coefficient {i}"
            );
        }
    }

    // --- NTT multiplication correctness ---

    #[test]
    fn test_ntt_multiply_by_one() {
        // f * 1 = f in NTT domain
        // "1" as a polynomial is [1, 0, 0, ..., 0]
        let f_vals: Vec<u16> = (0..N).map(|i| ((i * 13 + 7) % 3329) as u16).collect();
        let mut f = poly_from_slice(&f_vals);
        let mut one = poly_from_slice(&[1]);

        ntt(&mut f);
        ntt(&mut one);

        let mut result = zero_poly();
        ntt_multiply(&f, &one, &mut result);

        ntt_inverse(&mut result);

        // Result should equal original f
        for (i, &v) in f_vals.iter().enumerate() {
            let expected = v % 3329;
            assert_eq!(
                result[i].value(),
                expected,
                "multiply by 1 failed at coefficient {i}"
            );
        }
    }

    #[test]
    fn test_ntt_multiply_by_zero() {
        // f * 0 = 0
        let f_vals: Vec<u16> = (0..N).map(|i| ((i * 13 + 7) % 3329) as u16).collect();
        let mut f = poly_from_slice(&f_vals);
        let mut zero = zero_poly();

        ntt(&mut f);
        ntt(&mut zero);

        let mut result = zero_poly();
        ntt_multiply(&f, &zero, &mut result);

        ntt_inverse(&mut result);

        for (i, c) in result.iter().enumerate() {
            assert_eq!(c.value(), 0, "multiply by 0 not zero at coefficient {i}");
        }
    }

    #[test]
    fn test_ntt_multiply_commutativity() {
        // a * b == b * a
        let a_vals: Vec<u16> = (0..N).map(|i| ((i * 7 + 3) % 3329) as u16).collect();
        let b_vals: Vec<u16> = (0..N).map(|i| ((i * 11 + 5) % 3329) as u16).collect();

        let mut a = poly_from_slice(&a_vals);
        let mut b = poly_from_slice(&b_vals);

        ntt(&mut a);
        ntt(&mut b);

        let mut ab = zero_poly();
        let mut ba = zero_poly();
        ntt_multiply(&a, &b, &mut ab);
        ntt_multiply(&b, &a, &mut ba);

        for i in 0..N {
            assert_eq!(
                ab[i].value(),
                ba[i].value(),
                "commutativity failed at coefficient {i}"
            );
        }
    }

    /// Verify zeta table consistency: ZETAS[i] = zeta^{BitRev_7(i)} mod q.
    #[test]
    fn test_zetas_table_correctness() {
        let zeta = FieldElement::new(crate::mlkem::params::ZETA);

        for i in 0..128usize {
            // Compute BitRev_7(i)
            let mut br = 0usize;
            let mut x = i;
            for _ in 0..7 {
                br = (br << 1) | (x & 1);
                x >>= 1;
            }

            // Compute zeta^br by repeated multiplication
            let mut power = FieldElement::ONE;
            for _ in 0..br {
                power = power.mul(zeta);
            }

            assert_eq!(
                ZETAS[i],
                power.value(),
                "ZETAS[{i}] should be zeta^{br} = {} but got {}",
                power.value(),
                ZETAS[i]
            );
        }
    }

    /// Verify N_INV is correct: 128 * N_INV mod Q == 1.
    #[test]
    fn test_n_inv_constant() {
        let n = FieldElement::new(128); // 128-point NTT
        let n_inv = FieldElement::new(N_INV);
        assert_eq!(n.mul(n_inv).value(), 1, "128 * N_INV should be 1 mod Q");
    }

    /// Test basemul: (1, 0) * (a0, a1) = (a0, a1) for any gamma.
    #[test]
    fn test_basemul_identity() {
        let one = FieldElement::ONE;
        let zero = FieldElement::ZERO;
        let a0 = FieldElement::new(1234);
        let a1 = FieldElement::new(5678 % 3329);
        let gamma = FieldElement::new(17);

        let (c0, c1) = basemul(one, zero, a0, a1, gamma);
        assert_eq!(c0.value(), a0.value());
        assert_eq!(c1.value(), a1.value());
    }

    /// Test basemul: (a, b) * (0, 0) = (0, 0).
    #[test]
    fn test_basemul_zero() {
        let a0 = FieldElement::new(1234);
        let a1 = FieldElement::new(2345);
        let zero = FieldElement::ZERO;
        let gamma = FieldElement::new(17);

        let (c0, c1) = basemul(a0, a1, zero, zero, gamma);
        assert_eq!(c0.value(), 0);
        assert_eq!(c1.value(), 0);
    }

    /// Schoolbook multiplication of two small polynomials mod (X^256 + 1),
    /// compared against NTT-based multiplication.
    #[test]
    fn test_ntt_multiply_vs_schoolbook_small() {
        // f(X) = 1 + 2X + 3X^2
        // g(X) = 4 + 5X
        // f*g = 4 + 13X + 22X^2 + 15X^3  (before mod X^256+1, same since degree < 256)
        let f_coeffs: [u16; 256] = {
            let mut c = [0u16; 256];
            c[0] = 1;
            c[1] = 2;
            c[2] = 3;
            c
        };
        let g_coeffs: [u16; 256] = {
            let mut c = [0u16; 256];
            c[0] = 4;
            c[1] = 5;
            c
        };

        // Schoolbook multiplication mod X^256 + 1
        let mut schoolbook = [0u32; 256];
        for i in 0..256 {
            if f_coeffs[i] == 0 {
                continue;
            }
            for j in 0..256 {
                if g_coeffs[j] == 0 {
                    continue;
                }
                let idx = i + j;
                if idx < 256 {
                    schoolbook[idx] += f_coeffs[i] as u32 * g_coeffs[j] as u32;
                } else {
                    // X^256 = -1, so X^(256+k) = -X^k
                    let wrap_idx = idx - 256;
                    schoolbook[wrap_idx] += 3329 * 3329; // add enough to avoid underflow
                    schoolbook[wrap_idx] -= f_coeffs[i] as u32 * g_coeffs[j] as u32;
                }
            }
        }
        let expected: Vec<u16> = schoolbook.iter().map(|&v| (v % 3329) as u16).collect();

        // NTT-based multiplication
        let mut f = poly_from_slice(&f_coeffs);
        let mut g = poly_from_slice(&g_coeffs);
        ntt(&mut f);
        ntt(&mut g);
        let mut result = zero_poly();
        ntt_multiply(&f, &g, &mut result);
        ntt_inverse(&mut result);

        for i in 0..256 {
            assert_eq!(
                result[i].value(),
                expected[i],
                "NTT multiply vs schoolbook mismatch at coefficient {i}: got {}, expected {}",
                result[i].value(),
                expected[i]
            );
        }
    }
}

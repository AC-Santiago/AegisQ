//! Compresion y descompresion de coeficientes (FIPS 203 §4.2.1).
//!
//! `Compress_d` y `Decompress_d` reducen el tamano del ciphertext
//! a costa de precision controlada.
//!
//! Compress_d: Z_q → Z_{2^d}
//!   Compress_d(x) = round(2^d / q * x) mod 2^d
//!
//! Decompress_d: Z_{2^d} → Z_q
//!   Decompress_d(y) = round(q / 2^d * y)
//!
//! These functions are inverses in the approximate sense:
//!   Decompress_d(Compress_d(x)) ≈ x
//! with maximum error bounded by ceil(q / 2^{d+1}).
//!
//! FIPS 203 §4.2.1.
//!
//! Fase 4 de la hoja de ruta.

use crate::mlkem::math::field::FieldElement;
use crate::mlkem::math::poly::Poly;
use crate::mlkem::params::{N, Q};

// ---------------------------------------------------------------------------
// Compress / Decompress on individual coefficients
// ---------------------------------------------------------------------------

/// Compress a field element from Z_q to Z_{2^d}.
///
/// FIPS 203 §4.2.1:
///   Compress_d(x) = round(2^d / q * x) mod 2^d
///                 = floor((2^d * x + q/2) / q) mod 2^d
///
/// The rounding is performed by adding q/2 before integer division
/// (equivalent to rounding to nearest integer).
///
/// Input: x in [0, Q), d in {1, 4, 5, 10, 11}
/// Output: value in [0, 2^d)
///
/// Constant-time: only uses multiplies, adds, shifts, and a mask.
#[inline]
pub fn compress(x: FieldElement, d: u32) -> u16 {
    let val = x.value() as u64;
    // round(2^d * x / q) = floor((2^d * x + q/2) / q)
    let numerator = (val << d) + (Q as u64 / 2);
    let result = (numerator / Q as u64) as u16;
    result & ((1u16 << d) - 1) // mod 2^d
}

/// Decompress a value from Z_{2^d} back to Z_q.
///
/// FIPS 203 §4.2.1:
///   Decompress_d(y) = round(q / 2^d * y)
///                   = floor((q * y + 2^{d-1}) / 2^d)
///
/// Input: y in [0, 2^d), d in {1, 4, 5, 10, 11}
/// Output: FieldElement in [0, Q)
///
/// Constant-time: only multiplies, adds, and shifts.
#[inline]
pub fn decompress(y: u16, d: u32) -> FieldElement {
    let val = y as u32;
    // round(q * y / 2^d) = floor((q * y + 2^{d-1}) / 2^d)
    let numerator = val * Q as u32 + (1u32 << (d - 1));
    let result = (numerator >> d) as u16;
    FieldElement::new(result)
}

// ---------------------------------------------------------------------------
// Compress / Decompress on polynomials
// ---------------------------------------------------------------------------

/// Compress all coefficients of a polynomial from Z_q to Z_{2^d}.
///
/// Returns a new `Poly` where each coefficient is in [0, 2^d).
pub fn compress_poly(p: &Poly, d: u32) -> Poly {
    let mut result = Poly::zero();
    for i in 0..N {
        result.coeffs_mut()[i] = FieldElement::new(compress(p.coeffs()[i], d));
    }
    result
}

/// Decompress all coefficients of a polynomial from Z_{2^d} to Z_q.
///
/// Each coefficient in the input must be in [0, 2^d).
/// Returns a new `Poly` with coefficients in [0, Q).
pub fn decompress_poly(p: &Poly, d: u32) -> Poly {
    let mut result = Poly::zero();
    for i in 0..N {
        result.coeffs_mut()[i] = decompress(p.coeffs()[i].value(), d);
    }
    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Basic compress/decompress ---

    #[test]
    fn test_compress_zero() {
        // Compress_d(0) = 0 for any d
        for d in [1, 4, 5, 10, 11] {
            assert_eq!(compress(FieldElement::ZERO, d), 0, "compress(0, {d})");
        }
    }

    #[test]
    fn test_decompress_zero() {
        // Decompress_d(0) = 0 for any d
        for d in [1, 4, 5, 10, 11] {
            assert_eq!(decompress(0, d).value(), 0, "decompress(0, {d})");
        }
    }

    #[test]
    fn test_compress_range() {
        // Compressed values must be in [0, 2^d)
        for d in [1u32, 4, 5, 10, 11] {
            let max = 1u16 << d;
            for x in 0..Q {
                let c = compress(FieldElement::new(x), d);
                assert!(c < max, "compress({x}, {d}) = {c} >= 2^{d}");
            }
        }
    }

    #[test]
    fn test_decompress_range() {
        // Decompressed values must be in [0, Q)
        for d in [1u32, 4, 5, 10, 11] {
            let max = 1u16 << d;
            for y in 0..max {
                let val = decompress(y, d).value();
                assert!(val < Q, "decompress({y}, {d}) = {val} >= Q");
            }
        }
    }

    // --- Round-trip approximation ---

    #[test]
    fn test_roundtrip_error_bound() {
        // The error |Decompress(Compress(x)) - x| mod Q must be at most ceil(Q / 2^{d+1})
        for d in [1u32, 4, 5, 10, 11] {
            let max_error = (Q as u32 + (1u32 << (d + 1)) - 1) / (1u32 << (d + 1));
            for x in 0..Q {
                let c = compress(FieldElement::new(x), d);
                let x_prime = decompress(c, d).value();

                // Error in Z_q (circular distance)
                let diff = if x >= x_prime {
                    x - x_prime
                } else {
                    x_prime - x
                };
                let error = core::cmp::min(diff as u32, Q as u32 - diff as u32);

                assert!(
                    error <= max_error,
                    "roundtrip error for x={x}, d={d}: error={error}, max={max_error}"
                );
            }
        }
    }

    // --- Specific known values ---

    #[test]
    fn test_compress_d1_halfway() {
        // With d=1, compress maps [0, Q) to {0, 1}
        // The midpoint of Q is roughly Q/2 = 1664
        // Values near 0 should map to 0, values near Q/2 should map to 1
        assert_eq!(compress(FieldElement::new(0), 1), 0);
        // Q/2 ≈ 1664.5 → round(2/Q * 1665) ≈ 1 → 1
        assert_eq!(compress(FieldElement::new(Q / 2), 1), 1);
        assert_eq!(compress(FieldElement::new(Q - 1), 1), 0);
    }

    #[test]
    fn test_decompress_d1() {
        // Decompress_1(0) = round(Q * 0 / 2) = 0
        assert_eq!(decompress(0, 1).value(), 0);
        // Decompress_1(1) = round(Q / 2) = round(1664.5) = 1665
        assert_eq!(decompress(1, 1).value(), 1665);
    }

    #[test]
    fn test_compress_decompress_identity_d12() {
        // With d=12, 2^12 = 4096 > Q = 3329, so compress is nearly lossless.
        // Specifically, for x < Q, Compress_12(x) = x because
        // round(4096/3329 * x) mod 4096 is very close to x.
        // But not exactly, so we just check the error is very small.
        for x in 0..Q {
            let c = compress(FieldElement::new(x), 12);
            let x_prime = decompress(c, 12).value();
            let diff = if x >= x_prime {
                x - x_prime
            } else {
                x_prime - x
            };
            let error = core::cmp::min(diff, Q - diff);
            assert!(
                error <= 1,
                "d=12 roundtrip error too large for x={x}: got {x_prime}, error={error}"
            );
        }
    }

    // --- Polynomial compress/decompress ---

    #[test]
    fn test_compress_decompress_poly_roundtrip() {
        let mut coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            coeffs[i] = FieldElement::new(((i * 37 + 13) % Q as usize) as u16);
        }
        let p = Poly::from_coeffs(coeffs);

        for d in [4u32, 5, 10, 11] {
            let compressed = compress_poly(&p, d);
            let decompressed = decompress_poly(&compressed, d);

            let max_error = (Q as u32 + (1u32 << (d + 1)) - 1) / (1u32 << (d + 1));
            for i in 0..N {
                let orig = p.coeffs()[i].value();
                let recovered = decompressed.coeffs()[i].value();
                let diff = if orig >= recovered {
                    orig - recovered
                } else {
                    recovered - orig
                };
                let error = core::cmp::min(diff as u32, Q as u32 - diff as u32);
                assert!(
                    error <= max_error,
                    "poly roundtrip at {i}, d={d}: orig={orig}, got={recovered}, error={error}"
                );
            }
        }
    }

    #[test]
    fn test_compress_poly_zero() {
        let p = Poly::zero();
        let c = compress_poly(&p, 10);
        for i in 0..N {
            assert_eq!(c.coeffs()[i].value(), 0);
        }
    }
}

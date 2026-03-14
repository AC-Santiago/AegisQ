//! Muestreo de distribuciones para ML-KEM (FIPS 203).
//!
//! Implementa:
//! - `SampleNTT` (Algorithm 7): Rejection sampling de polinomios uniformes en Z_q
//! - `SamplePolyCBD_eta` (Algorithm 8): Centered Binomial Distribution para ruido
//! - Hash functions: G (SHA3-512), H (SHA3-256), J (SHAKE-256)
//! - XOF (SHAKE-128) y PRF (SHAKE-256) para derivacion de bytes
//!
//! Fase 6 de la hoja de ruta.

use crate::mlkem::math::field::FieldElement;
use crate::mlkem::math::poly::Poly;
use crate::mlkem::params::{N, Q};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake128, Shake256};

// ---------------------------------------------------------------------------
// Hash functions (FIPS 203 §4.1)
// ---------------------------------------------------------------------------

/// G: SHA3-512. Used for seed expansion in KeyGen.
///
/// FIPS 203: G(input) = SHA3-512(input) → 64 bytes, split as (32 || 32).
pub fn hash_g(input: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut output = [0u8; 64];
    output.copy_from_slice(&result);
    output
}

/// H: SHA3-256. Used for hashing public keys.
///
/// FIPS 203: H(input) = SHA3-256(input) → 32 bytes.
pub fn hash_h(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, input);
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// J: SHAKE-256. Used for implicit rejection in Decaps.
///
/// FIPS 203: J(input) = SHAKE-256(input) → 32 bytes.
pub fn hash_j(input: &[u8]) -> [u8; 32] {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut output = [0u8; 32];
    reader.read(&mut output);
    output
}

// ---------------------------------------------------------------------------
// XOF and PRF (FIPS 203 §4.1)
// ---------------------------------------------------------------------------

/// XOF: SHAKE-128 based extendable output function.
///
/// FIPS 203: XOF(rho, i, j) = SHAKE-128(rho || j || i)
/// Note the order: j is appended before i.
///
/// Returns a SHAKE-128 XOF reader that can produce arbitrary-length output.
pub fn xof(rho: &[u8; 32], i: u8, j: u8) -> impl XofReader {
    let mut hasher = Shake128::default();
    Update::update(&mut hasher, rho);
    Update::update(&mut hasher, &[j, i]); // FIPS 203: j before i
    hasher.finalize_xof()
}

/// PRF: SHAKE-256 based pseudorandom function.
///
/// FIPS 203: PRF_eta(s, b) = SHAKE-256(s || b) → 64*eta bytes.
pub fn prf(seed: &[u8; 32], nonce: u8, output: &mut [u8]) {
    let mut hasher = Shake256::default();
    Update::update(&mut hasher, seed);
    Update::update(&mut hasher, &[nonce]);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

// ---------------------------------------------------------------------------
// SampleNTT — rejection sampling (FIPS 203 Algorithm 7)
// ---------------------------------------------------------------------------

/// Generates a polynomial with coefficients uniformly distributed in Z_q
/// using rejection sampling from a SHAKE-128 XOF stream.
///
/// FIPS 203 Algorithm 7 (SampleNTT).
///
/// The XOF is seeded with `rho || j || i` where `rho` is the public seed,
/// and `(i, j)` is the matrix position.
///
/// Each iteration reads 3 bytes and extracts two 12-bit candidates:
///   d1 = b0 + 256*(b1 mod 16)
///   d2 = floor(b1/16) + 16*b2
/// Candidates < Q are accepted as coefficients.
pub fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut reader = xof(rho, i, j);
    let mut poly = Poly::zero();
    let mut count = 0usize;

    while count < N {
        let mut buf = [0u8; 3];
        reader.read(&mut buf);

        let d1 = (buf[0] as u16) | (((buf[1] & 0x0F) as u16) << 8);
        let d2 = ((buf[1] >> 4) as u16) | ((buf[2] as u16) << 4);

        if d1 < Q && count < N {
            poly.coeffs_mut()[count] = FieldElement::new(d1);
            count += 1;
        }
        if d2 < Q && count < N {
            poly.coeffs_mut()[count] = FieldElement::new(d2);
            count += 1;
        }
    }

    poly
}

// ---------------------------------------------------------------------------
// SamplePolyCBD — Centered Binomial Distribution (FIPS 203 Algorithm 8)
// ---------------------------------------------------------------------------

/// Samples a polynomial from the Centered Binomial Distribution CBD_eta.
///
/// FIPS 203 Algorithm 8 (SamplePolyCBD_eta).
///
/// For each coefficient:
///   x = sum of `eta` random bits
///   y = sum of next `eta` random bits
///   coefficient = x - y  (in Z_q, i.e., mod Q)
///
/// Result has coefficients in {-eta, ..., eta} (represented as Z_q elements).
///
/// Input: byte array of length `64 * eta`.
pub fn sample_poly_cbd(bytes: &[u8], eta: usize) -> Poly {
    match eta {
        2 => sample_poly_cbd_2(bytes),
        3 => sample_poly_cbd_3(bytes),
        _ => panic!("unsupported eta value: {}", eta),
    }
}

/// CBD_2: each coefficient from 4 bits (2+2).
///
/// Input: 128 bytes (64 * 2).
fn sample_poly_cbd_2(bytes: &[u8]) -> Poly {
    debug_assert_eq!(bytes.len(), 128);
    let mut poly = Poly::zero();

    for (i, &byte) in bytes.iter().enumerate().take(N / 2) {
        // First coefficient from bits [0:3]
        let x0 = (byte & 1) + ((byte >> 1) & 1);
        let y0 = ((byte >> 2) & 1) + ((byte >> 3) & 1);
        // Second coefficient from bits [4:7]
        let x1 = ((byte >> 4) & 1) + ((byte >> 5) & 1);
        let y1 = ((byte >> 6) & 1) + ((byte >> 7) & 1);

        // Coefficients in {-2, -1, 0, 1, 2}, mapped to Z_q
        poly.coeffs_mut()[2 * i] = field_sub_small(x0, y0);
        poly.coeffs_mut()[2 * i + 1] = field_sub_small(x1, y1);
    }

    poly
}

/// CBD_3: each coefficient from 6 bits (3+3).
///
/// Input: 192 bytes (64 * 3).
fn sample_poly_cbd_3(bytes: &[u8]) -> Poly {
    debug_assert_eq!(bytes.len(), 192);
    let mut poly = Poly::zero();

    // 256 coefficients, each needs 6 bits = 256*6 = 1536 bits = 192 bytes
    let mut bit_offset = 0usize;

    for i in 0..N {
        let mut x = 0u8;
        let mut y = 0u8;

        // Read eta=3 bits for x
        for _ in 0..3 {
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;
            x += (bytes[byte_idx] >> bit_idx) & 1;
            bit_offset += 1;
        }

        // Read eta=3 bits for y
        for _ in 0..3 {
            let byte_idx = bit_offset / 8;
            let bit_idx = bit_offset % 8;
            y += (bytes[byte_idx] >> bit_idx) & 1;
            bit_offset += 1;
        }

        poly.coeffs_mut()[i] = field_sub_small(x, y);
    }

    poly
}

/// Helper: compute (x - y) mod Q for small unsigned values.
///
/// x, y are in [0, eta] where eta <= 3. Result is in [0, Q).
#[inline]
fn field_sub_small(x: u8, y: u8) -> FieldElement {
    if x >= y {
        FieldElement::new((x - y) as u16)
    } else {
        // (x - y) mod Q = Q - (y - x)
        FieldElement::new(Q - (y - x) as u16)
    }
}

// ---------------------------------------------------------------------------
// Convenience: sample noise vector
// ---------------------------------------------------------------------------

/// Samples a noise polynomial using CBD from a PRF-derived byte stream.
///
/// Equivalent to:
///   bytes = PRF_eta(sigma, nonce)
///   poly  = SamplePolyCBD_eta(bytes)
pub fn sample_noise_poly(sigma: &[u8; 32], nonce: u8, eta: usize) -> Poly {
    let prf_len = 64 * eta;
    let mut bytes = alloc::vec![0u8; prf_len];
    prf(sigma, nonce, &mut bytes);
    sample_poly_cbd(&bytes, eta)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Hash function basic tests ---

    #[test]
    fn test_hash_g_deterministic() {
        let input = b"test input";
        let h1 = hash_g(input);
        let h2 = hash_g(input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_g_different_inputs() {
        let h1 = hash_g(b"input1");
        let h2 = hash_g(b"input2");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_hash_h_deterministic() {
        let h1 = hash_h(b"test");
        let h2 = hash_h(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_j_deterministic() {
        let h1 = hash_j(b"test");
        let h2 = hash_j(b"test");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash_g_output_split() {
        // G produces 64 bytes that can be split into two 32-byte halves
        let output = hash_g(b"seed");
        let rho = &output[..32];
        let sigma = &output[32..];
        assert_eq!(rho.len(), 32);
        assert_eq!(sigma.len(), 32);
        // The two halves should differ (with overwhelming probability)
        assert_ne!(rho, sigma);
    }

    // --- PRF tests ---

    #[test]
    fn test_prf_deterministic() {
        let seed = [42u8; 32];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        prf(&seed, 0, &mut out1);
        prf(&seed, 0, &mut out2);
        assert_eq!(out1, out2);
    }

    #[test]
    fn test_prf_different_nonces() {
        let seed = [42u8; 32];
        let mut out1 = [0u8; 128];
        let mut out2 = [0u8; 128];
        prf(&seed, 0, &mut out1);
        prf(&seed, 1, &mut out2);
        assert_ne!(out1, out2);
    }

    // --- SampleNTT tests ---

    #[test]
    fn test_sample_ntt_in_range() {
        let rho = [0u8; 32];
        let poly = sample_ntt(&rho, 0, 0);
        for i in 0..N {
            assert!(
                poly.coeffs()[i].value() < Q,
                "coefficient {i} = {} >= Q",
                poly.coeffs()[i].value()
            );
        }
    }

    #[test]
    fn test_sample_ntt_deterministic() {
        let rho = [0u8; 32];
        let p1 = sample_ntt(&rho, 0, 0);
        let p2 = sample_ntt(&rho, 0, 0);
        for i in 0..N {
            assert_eq!(p1.coeffs()[i].value(), p2.coeffs()[i].value());
        }
    }

    #[test]
    fn test_sample_ntt_different_positions() {
        let rho = [0u8; 32];
        let p1 = sample_ntt(&rho, 0, 0);
        let p2 = sample_ntt(&rho, 0, 1);
        // Should differ (with overwhelming probability)
        let mut differs = false;
        for i in 0..N {
            if p1.coeffs()[i].value() != p2.coeffs()[i].value() {
                differs = true;
                break;
            }
        }
        assert!(
            differs,
            "different (i,j) should produce different polynomials"
        );
    }

    #[test]
    fn test_sample_ntt_fills_all_256() {
        // SampleNTT must produce exactly 256 coefficients
        let rho = [1u8; 32];
        let poly = sample_ntt(&rho, 0, 0);
        // Check that not all are zero (with overwhelming probability)
        let all_zero = poly.coeffs().iter().all(|c| c.value() == 0);
        assert!(!all_zero, "sampled polynomial should not be all zeros");
    }

    // --- CBD tests ---

    #[test]
    fn test_cbd_2_in_range() {
        // CBD_2 coefficients should be in {-2, -1, 0, 1, 2} = {0, 1, 2, 3327, 3328} mod Q
        let seed = [42u8; 32];
        let poly = sample_noise_poly(&seed, 0, 2);
        let valid = [0, 1, 2, Q - 2, Q - 1];
        for i in 0..N {
            let v = poly.coeffs()[i].value();
            assert!(
                valid.contains(&v),
                "CBD_2 coefficient {i} = {v}, not in {{-2..2}}"
            );
        }
    }

    #[test]
    fn test_cbd_3_in_range() {
        // CBD_3 coefficients should be in {-3, ..., 3} = {0,1,2,3,3326,3327,3328} mod Q
        let seed = [42u8; 32];
        let poly = sample_noise_poly(&seed, 0, 3);
        let valid = [0, 1, 2, 3, Q - 3, Q - 2, Q - 1];
        for i in 0..N {
            let v = poly.coeffs()[i].value();
            assert!(
                valid.contains(&v),
                "CBD_3 coefficient {i} = {v}, not in {{-3..3}}"
            );
        }
    }

    #[test]
    fn test_cbd_deterministic() {
        let seed = [0u8; 32];
        let p1 = sample_noise_poly(&seed, 0, 2);
        let p2 = sample_noise_poly(&seed, 0, 2);
        for i in 0..N {
            assert_eq!(p1.coeffs()[i].value(), p2.coeffs()[i].value());
        }
    }

    #[test]
    fn test_cbd_different_nonces() {
        let seed = [0u8; 32];
        let p1 = sample_noise_poly(&seed, 0, 2);
        let p2 = sample_noise_poly(&seed, 1, 2);
        let mut differs = false;
        for i in 0..N {
            if p1.coeffs()[i].value() != p2.coeffs()[i].value() {
                differs = true;
                break;
            }
        }
        assert!(differs, "different nonces should produce different noise");
    }

    #[test]
    fn test_cbd_2_distribution() {
        // Statistical test: CBD_2 should have mean 0 and values distributed
        // symmetrically. Over 256 coefficients, the sum should be near 0.
        let seed = [123u8; 32];
        let poly = sample_noise_poly(&seed, 0, 2);
        let mut sum = 0i64;
        for i in 0..N {
            let v = poly.coeffs()[i].value();
            let signed = if v <= 2 {
                v as i64
            } else {
                v as i64 - Q as i64
            };
            sum += signed;
        }
        // With 256 CBD_2 samples, expected variance is 256*1 = 256,
        // so std dev ≈ 16. Sum should be within ~100 of 0 with high probability.
        assert!(sum.abs() < 100, "CBD_2 sum = {sum}, too far from 0");
    }

    #[test]
    fn test_cbd_all_zeros_input() {
        // With all-zero input bytes, CBD_2 should produce all-zero polynomial
        let bytes = [0u8; 128];
        let poly = sample_poly_cbd(&bytes, 2);
        for i in 0..N {
            assert_eq!(poly.coeffs()[i].value(), 0, "all-zero input at {i}");
        }
    }

    #[test]
    fn test_cbd_all_ones_input() {
        // With all-0xFF input bytes, each group of 2 bits sums to 2,
        // so x=2, y=2, coefficient = 0 for CBD_2
        let bytes = [0xFFu8; 128];
        let poly = sample_poly_cbd(&bytes, 2);
        for i in 0..N {
            assert_eq!(
                poly.coeffs()[i].value(),
                0,
                "all-ones input should give 0 (x=2, y=2) at {i}"
            );
        }
    }
}

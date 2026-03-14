//! Operaciones sobre polinomios en R_q = Z_q[X]/(X^256 + 1).
//!
//! Define el tipo `Poly` (array de 256 coeficientes en Z_q)
//! y operaciones basicas: suma, resta, multiplicacion via NTT,
//! y serializacion a/desde bytes.
//!
//! FIPS 203 — Polynomial arithmetic in R_q.
//!
//! Fase 3 de la hoja de ruta.

use crate::mlkem::math::field::FieldElement;
use crate::mlkem::math::ntt;
use crate::mlkem::params::{N, Q};

// ---------------------------------------------------------------------------
// Poly — a polynomial in R_q = Z_q[X]/(X^256 + 1)
// ---------------------------------------------------------------------------

/// A polynomial in R_q = Z_q[X]/(X^256 + 1) with 256 coefficients in Z_q.
///
/// The polynomial f(X) = sum_{i=0}^{255} f_i * X^i is stored as
/// `coeffs[i] = f_i` where each `f_i` is a `FieldElement` in [0, Q).
///
/// Polynomials may exist in either the coefficient domain (normal) or
/// the NTT domain. The caller is responsible for tracking which domain
/// a polynomial is in — this is a zero-cost abstraction that avoids
/// runtime flags.
#[derive(Clone)]
pub struct Poly {
    pub(crate) coeffs: [FieldElement; N],
}

impl Poly {
    /// Creates a zero polynomial (all coefficients = 0).
    pub fn zero() -> Self {
        Self {
            coeffs: [FieldElement::ZERO; N],
        }
    }

    /// Creates a polynomial from an array of `FieldElement` coefficients.
    pub fn from_coeffs(coeffs: [FieldElement; N]) -> Self {
        Self { coeffs }
    }

    /// Returns a reference to the coefficient array.
    #[inline]
    pub fn coeffs(&self) -> &[FieldElement; N] {
        &self.coeffs
    }

    /// Returns a mutable reference to the coefficient array.
    #[inline]
    pub fn coeffs_mut(&mut self) -> &mut [FieldElement; N] {
        &mut self.coeffs
    }

    // --- Arithmetic operations ---

    /// Polynomial addition: (self + rhs) mod Q, coefficient-wise.
    ///
    /// Both polynomials must be in the same domain (both coefficient or both NTT).
    pub fn add(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].add(rhs.coeffs[i]);
        }
        result
    }

    /// Polynomial subtraction: (self - rhs) mod Q, coefficient-wise.
    ///
    /// Both polynomials must be in the same domain.
    pub fn sub(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        for i in 0..N {
            result.coeffs[i] = self.coeffs[i].sub(rhs.coeffs[i]);
        }
        result
    }

    /// In-place addition: self += rhs.
    pub fn add_assign(&mut self, rhs: &Self) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].add(rhs.coeffs[i]);
        }
    }

    /// In-place subtraction: self -= rhs.
    pub fn sub_assign(&mut self, rhs: &Self) {
        for i in 0..N {
            self.coeffs[i] = self.coeffs[i].sub(rhs.coeffs[i]);
        }
    }

    // --- NTT domain operations ---

    /// Forward NTT: transform from coefficient domain to NTT domain (in-place).
    ///
    /// FIPS 203 Algorithm 9.
    pub fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }

    /// Inverse NTT: transform from NTT domain to coefficient domain (in-place).
    ///
    /// FIPS 203 Algorithm 10.
    pub fn ntt_inverse(&mut self) {
        ntt::ntt_inverse(&mut self.coeffs);
    }

    /// Pointwise multiplication in NTT domain: self * rhs.
    ///
    /// Both polynomials MUST be in the NTT domain. The result is also
    /// in the NTT domain. Use `ntt_inverse()` on the result to get
    /// back to coefficient domain.
    ///
    /// FIPS 203 Algorithm 11 (BaseCaseMultiply), applied to all 128 pairs.
    pub fn ntt_multiply(&self, rhs: &Self) -> Self {
        let mut result = Self::zero();
        ntt::ntt_multiply(&self.coeffs, &rhs.coeffs, &mut result.coeffs);
        result
    }

    // --- Serialization (FIPS 203 §4.2.2) ---

    /// Encodes a polynomial to bytes.
    ///
    /// Each coefficient is a 12-bit value (since Q = 3329 < 2^12 = 4096).
    /// Packs two coefficients into 3 bytes:
    ///   byte0 = c0[7:0]
    ///   byte1 = c1[3:0] || c0[11:8]
    ///   byte2 = c1[11:4]
    ///
    /// Output size: 256 * 12 / 8 = 384 bytes.
    ///
    /// FIPS 203 ByteEncode_12 (Algorithm 5 with d=12).
    pub fn to_bytes(&self) -> [u8; 384] {
        let mut buf = [0u8; 384];
        for i in 0..128 {
            let c0 = self.coeffs[2 * i].value() as u32;
            let c1 = self.coeffs[2 * i + 1].value() as u32;
            buf[3 * i] = c0 as u8;
            buf[3 * i + 1] = ((c0 >> 8) | (c1 << 4)) as u8;
            buf[3 * i + 2] = (c1 >> 4) as u8;
        }
        buf
    }

    /// Decodes a polynomial from bytes (inverse of `to_bytes`).
    ///
    /// Reads 384 bytes and unpacks 256 twelve-bit coefficients.
    /// Coefficients are reduced mod Q.
    ///
    /// FIPS 203 ByteDecode_12 (Algorithm 6 with d=12).
    pub fn from_bytes(buf: &[u8; 384]) -> Self {
        let mut poly = Self::zero();
        for i in 0..128 {
            let b0 = buf[3 * i] as u32;
            let b1 = buf[3 * i + 1] as u32;
            let b2 = buf[3 * i + 2] as u32;
            // c0 = b0 | (b1 & 0xF) << 8
            let c0 = (b0 | ((b1 & 0x0F) << 8)) as u16;
            // c1 = (b1 >> 4) | b2 << 4
            let c1 = (((b1 >> 4) | (b2 << 4)) & 0xFFF) as u16;
            poly.coeffs[2 * i] = FieldElement::new(c0 % Q);
            poly.coeffs[2 * i + 1] = FieldElement::new(c1 % Q);
        }
        poly
    }

    /// Encodes a polynomial with d-bit coefficients (d < 12).
    ///
    /// Used for compressed coefficients where each value is in [0, 2^d).
    /// Packs coefficients into a byte array of size `256 * d / 8`.
    ///
    /// FIPS 203 ByteEncode_d (Algorithm 5).
    ///
    /// Returns a Vec since the output size depends on `d`.
    pub fn encode_d(&self, d: usize) -> alloc::vec::Vec<u8> {
        let out_len = N * d / 8;
        let mut buf = alloc::vec![0u8; out_len];
        let mut bit_pos = 0usize;
        for i in 0..N {
            let val = self.coeffs[i].value() as u32;
            for bit in 0..d {
                if (val >> bit) & 1 == 1 {
                    buf[bit_pos / 8] |= 1 << (bit_pos % 8);
                }
                bit_pos += 1;
            }
        }
        buf
    }

    /// Decodes a polynomial with d-bit coefficients (d < 12).
    ///
    /// Inverse of `encode_d`. Each coefficient is in [0, 2^d).
    ///
    /// FIPS 203 ByteDecode_d (Algorithm 6).
    pub fn decode_d(buf: &[u8], d: usize) -> Self {
        let mut poly = Self::zero();
        let mut bit_pos = 0usize;
        for i in 0..N {
            let mut val = 0u32;
            for bit in 0..d {
                if bit_pos / 8 < buf.len() {
                    val |= (((buf[bit_pos / 8] >> (bit_pos % 8)) & 1) as u32) << bit;
                }
                bit_pos += 1;
            }
            poly.coeffs[i] = FieldElement::new(val as u16);
        }
        poly
    }
}

// ---------------------------------------------------------------------------
// PolyVec — vector of polynomials
// ---------------------------------------------------------------------------

/// A vector of `k` polynomials, where `k` depends on the security level.
///
/// Used to represent matrix rows/columns and vector operations in ML-KEM.
pub struct PolyVec {
    polys: alloc::vec::Vec<Poly>,
}

impl PolyVec {
    /// Creates a zero vector of `k` polynomials.
    pub fn zero(k: usize) -> Self {
        let mut polys = alloc::vec::Vec::with_capacity(k);
        for _ in 0..k {
            polys.push(Poly::zero());
        }
        Self { polys }
    }

    /// Creates a `PolyVec` from an existing vector of polynomials.
    pub fn from_polys(polys: alloc::vec::Vec<Poly>) -> Self {
        Self { polys }
    }

    /// Returns the dimension (number of polynomials).
    pub fn len(&self) -> usize {
        self.polys.len()
    }

    /// Returns true if the vector is empty.
    pub fn is_empty(&self) -> bool {
        self.polys.is_empty()
    }

    /// Returns a reference to the i-th polynomial.
    pub fn poly(&self, i: usize) -> &Poly {
        &self.polys[i]
    }

    /// Returns a mutable reference to the i-th polynomial.
    pub fn poly_mut(&mut self, i: usize) -> &mut Poly {
        &mut self.polys[i]
    }

    /// Forward NTT on all polynomials (in-place).
    pub fn ntt(&mut self) {
        for p in self.polys.iter_mut() {
            p.ntt();
        }
    }

    /// Inverse NTT on all polynomials (in-place).
    pub fn ntt_inverse(&mut self) {
        for p in self.polys.iter_mut() {
            p.ntt_inverse();
        }
    }

    /// Pointwise addition: self + rhs.
    pub fn add(&self, rhs: &Self) -> Self {
        debug_assert_eq!(self.len(), rhs.len());
        let polys = self
            .polys
            .iter()
            .zip(rhs.polys.iter())
            .map(|(a, b)| a.add(b))
            .collect();
        Self { polys }
    }

    /// Inner product in NTT domain: sum_i(self[i] * rhs[i]).
    ///
    /// Both vectors must be in the NTT domain. Returns a single polynomial
    /// in the NTT domain.
    pub fn inner_product_ntt(&self, rhs: &Self) -> Poly {
        debug_assert_eq!(self.len(), rhs.len());
        let mut result = Poly::zero();
        for (a, b) in self.polys.iter().zip(rhs.polys.iter()) {
            let product = a.ntt_multiply(b);
            result.add_assign(&product);
        }
        result
    }

    /// Encodes all polynomials to bytes (12-bit encoding).
    ///
    /// Output size: k * 384 bytes.
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::with_capacity(self.len() * 384);
        for p in &self.polys {
            buf.extend_from_slice(&p.to_bytes());
        }
        buf
    }

    /// Decodes a polynomial vector from bytes (12-bit encoding).
    ///
    /// `buf` must have length `k * 384`.
    pub fn from_bytes(buf: &[u8], k: usize) -> Self {
        debug_assert_eq!(buf.len(), k * 384);
        let mut polys = alloc::vec::Vec::with_capacity(k);
        for i in 0..k {
            let chunk = &buf[i * 384..(i + 1) * 384];
            let arr: [u8; 384] = chunk.try_into().expect("slice length mismatch");
            polys.push(Poly::from_bytes(&arr));
        }
        Self { polys }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Poly construction ---

    #[test]
    fn test_zero_poly() {
        let p = Poly::zero();
        for i in 0..N {
            assert_eq!(p.coeffs[i].value(), 0, "coefficient {i} should be 0");
        }
    }

    #[test]
    fn test_from_coeffs() {
        let mut coeffs = [FieldElement::ZERO; N];
        coeffs[0] = FieldElement::new(42);
        coeffs[1] = FieldElement::new(100);
        let p = Poly::from_coeffs(coeffs);
        assert_eq!(p.coeffs[0].value(), 42);
        assert_eq!(p.coeffs[1].value(), 100);
        assert_eq!(p.coeffs[2].value(), 0);
    }

    // --- Arithmetic ---

    #[test]
    fn test_add() {
        let mut a_coeffs = [FieldElement::ZERO; N];
        let mut b_coeffs = [FieldElement::ZERO; N];
        a_coeffs[0] = FieldElement::new(100);
        a_coeffs[1] = FieldElement::new(3000);
        b_coeffs[0] = FieldElement::new(200);
        b_coeffs[1] = FieldElement::new(500);

        let a = Poly::from_coeffs(a_coeffs);
        let b = Poly::from_coeffs(b_coeffs);
        let c = a.add(&b);

        assert_eq!(c.coeffs[0].value(), 300);
        // 3000 + 500 = 3500 → 3500 - 3329 = 171
        assert_eq!(c.coeffs[1].value(), 171);
    }

    #[test]
    fn test_sub() {
        let mut a_coeffs = [FieldElement::ZERO; N];
        let mut b_coeffs = [FieldElement::ZERO; N];
        a_coeffs[0] = FieldElement::new(100);
        b_coeffs[0] = FieldElement::new(200);

        let a = Poly::from_coeffs(a_coeffs);
        let b = Poly::from_coeffs(b_coeffs);
        let c = a.sub(&b);

        // 100 - 200 mod 3329 = 3229
        assert_eq!(c.coeffs[0].value(), 3229);
    }

    #[test]
    fn test_add_sub_inverse() {
        let mut a_coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            a_coeffs[i] = FieldElement::new(((i * 37 + 13) % 3329) as u16);
        }
        let a = Poly::from_coeffs(a_coeffs);
        let b = a.add(&a).sub(&a);

        for i in 0..N {
            assert_eq!(b.coeffs[i].value(), a.coeffs[i].value(), "at index {i}");
        }
    }

    // --- NTT roundtrip ---

    #[test]
    fn test_ntt_roundtrip() {
        let mut coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            coeffs[i] = FieldElement::new(((i * 17 + 5) % 3329) as u16);
        }
        let original_coeffs = coeffs;
        let mut p = Poly::from_coeffs(coeffs);

        p.ntt();
        p.ntt_inverse();

        for i in 0..N {
            assert_eq!(
                p.coeffs[i].value(),
                original_coeffs[i].value(),
                "NTT roundtrip mismatch at {i}"
            );
        }
    }

    // --- NTT multiplication ---

    #[test]
    fn test_ntt_multiply_by_one() {
        let mut f_coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            f_coeffs[i] = FieldElement::new(((i * 13 + 7) % 3329) as u16);
        }
        let original = f_coeffs;

        let mut one_coeffs = [FieldElement::ZERO; N];
        one_coeffs[0] = FieldElement::ONE;

        let mut f = Poly::from_coeffs(f_coeffs);
        let mut one = Poly::from_coeffs(one_coeffs);
        f.ntt();
        one.ntt();

        let mut result = f.ntt_multiply(&one);
        result.ntt_inverse();

        for i in 0..N {
            assert_eq!(
                result.coeffs[i].value(),
                original[i].value(),
                "multiply by 1 failed at {i}"
            );
        }
    }

    // --- Serialization ---

    #[test]
    fn test_to_from_bytes_roundtrip() {
        let mut coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            coeffs[i] = FieldElement::new(((i * 37 + 13) % 3329) as u16);
        }
        let p = Poly::from_coeffs(coeffs);

        let bytes = p.to_bytes();
        assert_eq!(bytes.len(), 384);

        let p2 = Poly::from_bytes(&bytes);
        for i in 0..N {
            assert_eq!(
                p2.coeffs[i].value(),
                p.coeffs[i].value(),
                "byte roundtrip mismatch at {i}"
            );
        }
    }

    #[test]
    fn test_to_from_bytes_zero() {
        let p = Poly::zero();
        let bytes = p.to_bytes();
        assert!(bytes.iter().all(|&b| b == 0));

        let p2 = Poly::from_bytes(&bytes);
        for i in 0..N {
            assert_eq!(p2.coeffs[i].value(), 0);
        }
    }

    #[test]
    fn test_to_from_bytes_max() {
        // All coefficients at Q-1 = 3328
        let coeffs = [FieldElement::new(Q - 1); N];
        let p = Poly::from_coeffs(coeffs);

        let bytes = p.to_bytes();
        let p2 = Poly::from_bytes(&bytes);
        for i in 0..N {
            assert_eq!(p2.coeffs[i].value(), Q - 1, "max value roundtrip at {i}");
        }
    }

    #[test]
    fn test_encode_decode_d_roundtrip() {
        // Test with d=4 (values in [0, 16))
        let mut coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            coeffs[i] = FieldElement::new((i % 16) as u16);
        }
        let p = Poly::from_coeffs(coeffs);

        let encoded = p.encode_d(4);
        assert_eq!(encoded.len(), 256 * 4 / 8);

        let p2 = Poly::decode_d(&encoded, 4);
        for i in 0..N {
            assert_eq!(
                p2.coeffs[i].value(),
                p.coeffs[i].value(),
                "encode_d/decode_d roundtrip at {i}"
            );
        }
    }

    #[test]
    fn test_encode_decode_d_10() {
        // Test with d=10 (values in [0, 1024))
        let mut coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            coeffs[i] = FieldElement::new(((i * 7 + 3) % 1024) as u16);
        }
        let p = Poly::from_coeffs(coeffs);

        let encoded = p.encode_d(10);
        assert_eq!(encoded.len(), 256 * 10 / 8);

        let p2 = Poly::decode_d(&encoded, 10);
        for i in 0..N {
            assert_eq!(
                p2.coeffs[i].value(),
                p.coeffs[i].value(),
                "encode_d(10) roundtrip at {i}"
            );
        }
    }

    #[test]
    fn test_encode_decode_d_1() {
        // Test with d=1 (binary polynomial, values 0 or 1)
        let mut coeffs = [FieldElement::ZERO; N];
        for i in 0..N {
            coeffs[i] = FieldElement::new((i % 2) as u16);
        }
        let p = Poly::from_coeffs(coeffs);

        let encoded = p.encode_d(1);
        assert_eq!(encoded.len(), 32); // 256 bits = 32 bytes

        let p2 = Poly::decode_d(&encoded, 1);
        for i in 0..N {
            assert_eq!(
                p2.coeffs[i].value(),
                p.coeffs[i].value(),
                "encode_d(1) roundtrip at {i}"
            );
        }
    }

    // --- PolyVec ---

    #[test]
    fn test_polyvec_zero() {
        let pv = PolyVec::zero(3);
        assert_eq!(pv.len(), 3);
        for i in 0..3 {
            for j in 0..N {
                assert_eq!(pv.poly(i).coeffs[j].value(), 0);
            }
        }
    }

    #[test]
    fn test_polyvec_add() {
        let mut a = PolyVec::zero(2);
        let mut b = PolyVec::zero(2);
        a.poly_mut(0).coeffs[0] = FieldElement::new(100);
        b.poly_mut(0).coeffs[0] = FieldElement::new(200);

        let c = a.add(&b);
        assert_eq!(c.poly(0).coeffs[0].value(), 300);
    }

    #[test]
    fn test_polyvec_inner_product_ntt() {
        // Inner product of unit vectors should give the product of their first elements
        let mut a = PolyVec::zero(2);
        let mut b = PolyVec::zero(2);

        // Set a[0] = constant polynomial 1, a[1] = 0
        a.poly_mut(0).coeffs[0] = FieldElement::new(1);
        // Set b[0] = constant polynomial 2, b[1] = 0
        b.poly_mut(0).coeffs[0] = FieldElement::new(2);

        a.ntt();
        b.ntt();

        let mut result = a.inner_product_ntt(&b);
        result.ntt_inverse();

        // Should be 1 * 2 = 2 (constant polynomial)
        assert_eq!(result.coeffs[0].value(), 2);
        for i in 1..N {
            assert_eq!(result.coeffs[i].value(), 0, "non-zero at {i}");
        }
    }

    #[test]
    fn test_polyvec_to_from_bytes() {
        let mut pv = PolyVec::zero(3);
        for k in 0..3 {
            for i in 0..N {
                pv.poly_mut(k).coeffs[i] = FieldElement::new(((k * 1000 + i * 37) % 3329) as u16);
            }
        }

        let bytes = pv.to_bytes();
        assert_eq!(bytes.len(), 3 * 384);

        let pv2 = PolyVec::from_bytes(&bytes, 3);
        for k in 0..3 {
            for i in 0..N {
                assert_eq!(
                    pv2.poly(k).coeffs[i].value(),
                    pv.poly(k).coeffs[i].value(),
                    "polyvec byte roundtrip mismatch at poly {k}, coeff {i}"
                );
            }
        }
    }

    #[test]
    fn test_polyvec_is_empty() {
        assert!(PolyVec::zero(0).is_empty());
        assert!(!PolyVec::zero(1).is_empty());
    }
}

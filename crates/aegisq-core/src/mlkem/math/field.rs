//! Aritmetica en el campo Z_q donde q = 3329.
//!
//! Implementa operaciones modulares con reduccion Barrett
//! para evitar divisiones costosas. Todas las operaciones
//! son en tiempo constante para prevenir side-channel attacks.
//!
//! FIPS 203 §4.2 — Operaciones aritmeticas sobre Z_q.
//!
//! Fase 1 de la hoja de ruta.

use crate::mlkem::params::Q;

// ---------------------------------------------------------------------------
// Barrett reduction constants
// ---------------------------------------------------------------------------
// Barrett constant: floor(2^26 / Q) = floor(67_108_864 / 3329) = 20159
// Used to approximate division by Q using only shifts and multiplies.
//
// For any a in [0, Q^2), Barrett reduction computes a mod Q without division:
//   t = ((a as u64) * BARRETT_MULTIPLIER) >> BARRETT_SHIFT
//   r = a - t * Q
//   if r >= Q { r -= Q }
//
// The shift of 26 bits is chosen to provide sufficient precision for
// inputs up to Q*Q - 1 = 3329*3329 - 1 = 11_082_240 which fits in u32.
const BARRETT_SHIFT: u32 = 26;
const BARRETT_MULTIPLIER: u64 = 20158; // floor(2^26 / 3329)

// ---------------------------------------------------------------------------
// Constant-time helpers
// ---------------------------------------------------------------------------

/// Reduces a value in [0, 2*Q) to [0, Q) without branching.
///
/// Constant-time: uses arithmetic right shift to produce a mask.
///
/// Algorithm:
///   1. Compute diff = x - Q (wrapping subtraction in u16)
///   2. Interpret diff as i16 and arithmetic-right-shift by 15
///      → mask = 0xFFFF if x < Q (diff was negative), 0x0000 if x >= Q
///   3. result = diff + (Q & mask)
///      → if x >= Q: diff = x-Q, mask = 0  → result = x - Q  (reduced)
///      → if x <  Q: diff wrapped, mask = 0xFFFF → result = (x-Q wrapping) + Q = x
///
/// Note: when x < Q, `x.wrapping_sub(Q)` produces `x + 65536 - Q` as a u16.
/// Adding Q back: `(x + 65536 - Q) + Q = x + 65536`, which truncated to u16 is `x`.
#[inline]
const fn ct_reduce_once(x: u16) -> u16 {
    let diff = x.wrapping_sub(Q);
    let mask = ((diff as i16) >> 15) as u16;
    diff.wrapping_add(Q & mask)
}

/// Constant-time mask: returns 0xFFFF if x != 0, 0x0000 if x == 0.
#[inline]
const fn ct_nonzero_mask_u16(x: u16) -> u16 {
    let x32 = x as u32;
    let v = (x32 | x32.wrapping_neg()) >> 31;
    0u16.wrapping_sub(v as u16)
}

// ---------------------------------------------------------------------------
// Barrett reduction
// ---------------------------------------------------------------------------

/// Barrett reduction: computes `a mod Q` for `a` in [0, Q*Q).
///
/// This avoids expensive division by using a precomputed multiplier.
/// The algorithm:
///   1. t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT  (approximate quotient)
///   2. r = a - t * Q                                  (approximate remainder)
///   3. if r >= Q: r -= Q                               (correct off-by-one)
///
/// For inputs in [0, Q*Q) = [0, 11_082_241), the approximation error
/// is at most 1, so a single conditional subtraction suffices.
///
/// Constant-time: only multiplies, shifts, and a branchless conditional subtract.
#[inline]
const fn barrett_reduce(a: u32) -> u16 {
    let t = ((a as u64 * BARRETT_MULTIPLIER) >> BARRETT_SHIFT) as u32;
    let r = (a - t * Q as u32) as u16;
    ct_reduce_once(r)
}

// ---------------------------------------------------------------------------
// FieldElement
// ---------------------------------------------------------------------------

/// Element of the field Z_q where q = 3329.
///
/// Invariant: the inner value is always in [0, Q) after construction
/// via public APIs. Internal intermediate values may temporarily exceed Q
/// but are always reduced before being exposed.
///
/// All operations are constant-time: no secret-dependent branches or
/// memory accesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldElement(u16);

impl FieldElement {
    /// Zero element of Z_q.
    pub const ZERO: Self = Self(0);

    /// Multiplicative identity of Z_q.
    pub const ONE: Self = Self(1);

    /// Creates a `FieldElement` from a `u16`, reducing mod Q.
    ///
    /// Accepts any u16 value. The result is always in [0, Q).
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value % Q)
    }

    /// Creates a `FieldElement` from a value already known to be in [0, Q).
    ///
    /// # Safety (logical)
    /// The caller MUST guarantee that `value < Q`. This is not `unsafe`
    /// in the Rust memory-safety sense, but violating the precondition
    /// will produce incorrect cryptographic results.
    ///
    /// This function exists only for performance-critical internal paths
    /// where the invariant is maintained by construction (e.g., after
    /// Barrett reduction).
    #[allow(dead_code)] // Used by NTT and poly modules in later phases
    #[inline]
    pub(crate) const fn from_reduced(value: u16) -> Self {
        debug_assert!(value < Q);
        Self(value)
    }

    /// Returns the inner value as `u16`. Always in [0, Q).
    #[inline]
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Modular addition: (self + rhs) mod Q.
    ///
    /// Constant-time: uses conditional subtraction instead of branching.
    /// Since both inputs are < Q, the sum is < 2*Q, so one reduction suffices.
    #[inline]
    pub const fn add(self, rhs: Self) -> Self {
        let sum = self.0.wrapping_add(rhs.0);
        Self(ct_reduce_once(sum))
    }

    /// Modular subtraction: (self - rhs) mod Q.
    ///
    /// Constant-time: adds Q before subtracting to avoid underflow,
    /// then reduces. Since both inputs are < Q, (self + Q - rhs) is in [1, 2*Q-1],
    /// which ct_reduce_once handles.
    #[inline]
    pub const fn sub(self, rhs: Self) -> Self {
        let diff = self.0.wrapping_add(Q).wrapping_sub(rhs.0);
        Self(ct_reduce_once(diff))
    }

    /// Modular multiplication: (self * rhs) mod Q.
    ///
    /// Uses Barrett reduction to avoid division.
    /// Constant-time: Barrett reduction uses only multiplies and shifts.
    #[inline]
    pub const fn mul(self, rhs: Self) -> Self {
        let product = self.0 as u32 * rhs.0 as u32;
        Self(barrett_reduce(product))
    }

    /// Modular negation: (-self) mod Q.
    ///
    /// Constant-time: uses a mask to handle the zero case.
    /// If self == 0, returns 0. Otherwise, returns Q - self.
    #[inline]
    pub const fn neg(self) -> Self {
        let nonzero_mask = ct_nonzero_mask_u16(self.0);
        Self((Q.wrapping_sub(self.0)) & nonzero_mask)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- FieldElement construction ---

    #[test]
    fn test_new_reduces_mod_q() {
        assert_eq!(FieldElement::new(0).value(), 0);
        assert_eq!(FieldElement::new(1).value(), 1);
        assert_eq!(FieldElement::new(3328).value(), 3328);
        assert_eq!(FieldElement::new(3329).value(), 0);
        assert_eq!(FieldElement::new(3330).value(), 1);
        assert_eq!(FieldElement::new(6658).value(), 0); // 2*Q
        assert_eq!(FieldElement::new(u16::MAX).value(), u16::MAX % Q);
    }

    #[test]
    fn test_zero_and_one_constants() {
        assert_eq!(FieldElement::ZERO.value(), 0);
        assert_eq!(FieldElement::ONE.value(), 1);
    }

    // --- Addition ---

    #[test]
    fn test_add_no_wrap() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(200);
        assert_eq!(a.add(b).value(), 300);
    }

    #[test]
    fn test_add_wrap() {
        let a = FieldElement::new(3000);
        let b = FieldElement::new(500);
        // 3000 + 500 = 3500 → 3500 - 3329 = 171
        assert_eq!(a.add(b).value(), 171);
    }

    #[test]
    fn test_add_identity() {
        let a = FieldElement::new(1234);
        assert_eq!(a.add(FieldElement::ZERO).value(), 1234);
        assert_eq!(FieldElement::ZERO.add(a).value(), 1234);
    }

    #[test]
    fn test_add_max_values() {
        let a = FieldElement::new(Q - 1); // 3328
        let b = FieldElement::new(Q - 1); // 3328
        // 3328 + 3328 = 6656 → 6656 - 3329 = 3327
        assert_eq!(a.add(b).value(), 3327);
    }

    #[test]
    fn test_add_commutative() {
        let a = FieldElement::new(1234);
        let b = FieldElement::new(2345);
        assert_eq!(a.add(b).value(), b.add(a).value());
    }

    #[test]
    fn test_add_associative() {
        let a = FieldElement::new(1111);
        let b = FieldElement::new(2222);
        let c = FieldElement::new(3000);
        assert_eq!(a.add(b).add(c).value(), a.add(b.add(c)).value());
    }

    // --- Subtraction ---

    #[test]
    fn test_sub_no_wrap() {
        let a = FieldElement::new(500);
        let b = FieldElement::new(200);
        assert_eq!(a.sub(b).value(), 300);
    }

    #[test]
    fn test_sub_wrap() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(200);
        // 100 - 200 mod 3329 = 3229
        assert_eq!(a.sub(b).value(), 3229);
    }

    #[test]
    fn test_sub_self_is_zero() {
        let a = FieldElement::new(1234);
        assert_eq!(a.sub(a).value(), 0);
    }

    #[test]
    fn test_sub_zero_identity() {
        let a = FieldElement::new(1234);
        assert_eq!(a.sub(FieldElement::ZERO).value(), 1234);
    }

    #[test]
    fn test_sub_from_zero() {
        let a = FieldElement::new(100);
        // 0 - 100 mod 3329 = 3229
        assert_eq!(FieldElement::ZERO.sub(a).value(), 3229);
    }

    // --- Multiplication ---

    #[test]
    fn test_mul_small() {
        let a = FieldElement::new(100);
        let b = FieldElement::new(20);
        assert_eq!(a.mul(b).value(), 2000);
    }

    #[test]
    fn test_mul_wrap() {
        let a = FieldElement::new(2000);
        let b = FieldElement::new(3);
        // 2000 * 3 = 6000 → 6000 mod 3329 = 2671
        assert_eq!(a.mul(b).value(), 2671);
    }

    #[test]
    fn test_mul_identity() {
        let a = FieldElement::new(1234);
        assert_eq!(a.mul(FieldElement::ONE).value(), 1234);
        assert_eq!(FieldElement::ONE.mul(a).value(), 1234);
    }

    #[test]
    fn test_mul_zero() {
        let a = FieldElement::new(1234);
        assert_eq!(a.mul(FieldElement::ZERO).value(), 0);
        assert_eq!(FieldElement::ZERO.mul(a).value(), 0);
    }

    #[test]
    fn test_mul_max_values() {
        let a = FieldElement::new(Q - 1); // 3328
        let b = FieldElement::new(Q - 1); // 3328
        let expected = (3328u32 * 3328u32 % Q as u32) as u16;
        assert_eq!(a.mul(b).value(), expected);
    }

    #[test]
    fn test_mul_commutative() {
        let a = FieldElement::new(1234);
        let b = FieldElement::new(2345);
        assert_eq!(a.mul(b).value(), b.mul(a).value());
    }

    #[test]
    fn test_mul_associative() {
        let a = FieldElement::new(1111);
        let b = FieldElement::new(2222);
        let c = FieldElement::new(3000);
        assert_eq!(a.mul(b).mul(c).value(), a.mul(b.mul(c)).value());
    }

    #[test]
    fn test_distributive() {
        let a = FieldElement::new(1234);
        let b = FieldElement::new(567);
        let c = FieldElement::new(890);
        let lhs = a.mul(b.add(c));
        let rhs = a.mul(b).add(a.mul(c));
        assert_eq!(lhs.value(), rhs.value());
    }

    // --- Negation ---

    #[test]
    fn test_neg_basic() {
        let a = FieldElement::new(100);
        assert_eq!(a.neg().value(), 3229);
    }

    #[test]
    fn test_neg_zero() {
        assert_eq!(FieldElement::ZERO.neg().value(), 0);
    }

    #[test]
    fn test_neg_double_is_identity() {
        let a = FieldElement::new(1234);
        assert_eq!(a.neg().neg().value(), a.value());
    }

    #[test]
    fn test_add_neg_is_zero() {
        let a = FieldElement::new(1234);
        assert_eq!(a.add(a.neg()).value(), 0);
    }

    #[test]
    fn test_neg_one() {
        // -1 mod 3329 = 3328
        assert_eq!(FieldElement::ONE.neg().value(), Q - 1);
    }

    // --- Barrett reduction ---

    #[test]
    fn test_barrett_reduce_small_range() {
        for a in 0..10_000u32 {
            let expected = (a % Q as u32) as u16;
            let got = barrett_reduce(a);
            assert_eq!(got, expected, "Barrett failed for a={a}");
        }
    }

    #[test]
    fn test_barrett_reduce_near_q_squared() {
        let q32 = Q as u32;
        for a in (q32 * q32 - 100)..=(q32 * q32 - 1) {
            let expected = (a % q32) as u16;
            let got = barrett_reduce(a);
            assert_eq!(got, expected, "Barrett failed for a={a}");
        }
    }

    #[test]
    fn test_barrett_reduce_exact_multiples() {
        let q32 = Q as u32;
        for k in 0..3330u32 {
            assert_eq!(barrett_reduce(k * q32), 0, "Failed for {k}*Q");
        }
    }

    #[test]
    fn test_barrett_constant_is_correct() {
        let expected = (1u64 << BARRETT_SHIFT) / Q as u64;
        assert_eq!(BARRETT_MULTIPLIER, expected);
    }

    // --- ct_reduce_once ---

    #[test]
    fn test_ct_reduce_once_below_q() {
        for x in 0..Q {
            assert_eq!(ct_reduce_once(x), x, "ct_reduce_once({x}) should be {x}");
        }
    }

    #[test]
    fn test_ct_reduce_once_at_and_above_q() {
        assert_eq!(ct_reduce_once(Q), 0);
        assert_eq!(ct_reduce_once(Q + 1), 1);
        // Maximum valid input: 2*Q - 1
        assert_eq!(ct_reduce_once(2 * Q - 1), Q - 1);
    }

    // --- FIPS 203 mathematical properties ---

    /// FIPS 203 uses zeta = 17 as the primitive 256th root of unity in Z_q.
    /// Verify: 17^256 mod 3329 == 1 and 17^128 mod 3329 != 1.
    #[test]
    fn test_zeta_is_primitive_256th_root() {
        let zeta = FieldElement::new(crate::mlkem::params::ZETA);
        let mut power = FieldElement::ONE;

        // zeta^128 must NOT be 1 (otherwise order divides 128, not primitive)
        for _ in 0..128 {
            power = power.mul(zeta);
        }
        assert_ne!(power.value(), 1, "zeta^128 should not be 1");

        // zeta^256 MUST be 1
        for _ in 128..256 {
            power = power.mul(zeta);
        }
        assert_eq!(power.value(), 1, "zeta^256 must be 1");
    }

    /// Verify q = 3329 is prime by trial division.
    #[test]
    fn test_q_is_prime() {
        let q = Q as u32;
        let mut i = 2u32;
        while i * i <= q {
            assert_ne!(q % i, 0, "Q={q} is divisible by {i}");
            i += 1;
        }
    }

    /// Verify Fermat's little theorem: a^(q-1) == 1 for a != 0.
    #[test]
    fn test_fermat_little_theorem() {
        // Test a few representative values
        for &a_val in &[1u16, 2, 17, 100, 1000, 3328] {
            let a = FieldElement::new(a_val);
            let mut result = FieldElement::ONE;
            // Compute a^(Q-1) by repeated squaring
            let exp = Q - 1; // 3328
            let mut base = a;
            let mut e = exp;
            while e > 0 {
                if e & 1 == 1 {
                    result = result.mul(base);
                }
                base = base.mul(base);
                e >>= 1;
            }
            assert_eq!(result.value(), 1, "a^(q-1) != 1 for a={a_val}");
        }
    }

    /// Comprehensive: verify all operations for every element in Z_q.
    /// (Only runs add/sub on boundaries; full exhaustive is too slow for all pairs.)
    #[test]
    fn test_add_sub_inverse_exhaustive() {
        // For every a, verify a + (-a) == 0 and a - a == 0
        for a_val in 0..Q {
            let a = FieldElement::new(a_val);
            assert_eq!(a.add(a.neg()).value(), 0, "a + (-a) != 0 for a={a_val}");
            assert_eq!(a.sub(a).value(), 0, "a - a != 0 for a={a_val}");
        }
    }
}

//! ML-KEM Encapsulation — FIPS 203.
//!
//! Implements:
//! - K-PKE.Encrypt (Algorithm 13): Inner CPA encryption
//! - ML-KEM.Encaps (Algorithm 16): Outer CCA-secure encapsulation
//!
//! The public API is `ml_kem_encaps()` which produces a capsule and shared secret.
//!
//! Fase 8 de la hoja de ruta.

use crate::error::AegisQError;
use crate::kem::SecurityLevel;
use crate::mlkem::math::compress::{compress_poly, decompress};
use crate::mlkem::math::poly::{Poly, PolyVec};
use crate::mlkem::params::{params_for_level, MlKemParams, N};
use crate::mlkem::sampling::{hash_g, hash_h, sample_noise_poly, sample_ntt};
use rand_core::{OsRng, RngCore};

// ---------------------------------------------------------------------------
// K-PKE.Encrypt — FIPS 203 Algorithm 13
// ---------------------------------------------------------------------------

/// K-PKE.Encrypt — FIPS 203 Algorithm 13.
///
/// Encrypts a 32-byte message `m` under the CPA encryption key `ek_pke`
/// using randomness coins `r_coins`.
///
/// Steps:
/// 1. Parse ek_pke as (t̂ || ρ) where t̂ is k polynomials (each 384 bytes)
/// 2. Â[i,j] = SampleNTT(ρ, i, j)
/// 3. y[i]  = CBD_η₁(PRF(r_coins, i))       for i in 0..k
/// 4. e₁[i] = CBD_η₂(PRF(r_coins, k+i))     for i in 0..k
/// 5. e₂    = CBD_η₂(PRF(r_coins, 2k))
/// 6. ŷ = NTT(y)
/// 7. u = NTT⁻¹(Â^T · ŷ) + e₁
/// 8. μ = Decompress₁(ByteDecode₁(m))
/// 9. v = NTT⁻¹(t̂^T · ŷ) + e₂ + μ
/// 10. c₁ = ByteEncode_{du}(Compress_{du}(u))
/// 11. c₂ = ByteEncode_{dv}(Compress_{dv}(v))
/// 12. Return c = c₁ || c₂
///
/// This function is also used internally by Decaps for re-encryption verification.
pub(crate) fn k_pke_encrypt(
    ek_pke: &[u8],
    m: &[u8; 32],
    r_coins: &[u8; 32],
    params: &MlKemParams,
) -> alloc::vec::Vec<u8> {
    let k = params.k;
    let eta1 = params.eta1;
    let eta2 = params.eta2;
    let du = params.du;
    let dv = params.dv;

    // Step 1: Parse ek_pke as (t̂ || ρ)
    // t̂ is k * 384 bytes, ρ is 32 bytes
    let t_hat_bytes = &ek_pke[..k * 384];
    let rho: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&ek_pke[k * 384..k * 384 + 32]);
        buf
    };
    let t_hat = PolyVec::from_bytes(t_hat_bytes, k);

    // Step 2: Regenerate matrix Â in NTT domain from ρ
    let mut a_hat = alloc::vec::Vec::with_capacity(k * k);
    for i in 0..k {
        for j in 0..k {
            a_hat.push(sample_ntt(&rho, i as u8, j as u8));
        }
    }

    // Step 3: Generate randomness vector y with CBD(η₁), nonces 0..k-1
    let mut y = PolyVec::zero(k);
    for i in 0..k {
        *y.poly_mut(i) = sample_noise_poly(r_coins, i as u8, eta1);
    }

    // Step 4: Generate error vector e₁ with CBD(η₂), nonces k..2k-1
    let mut e1 = PolyVec::zero(k);
    for i in 0..k {
        *e1.poly_mut(i) = sample_noise_poly(r_coins, (k + i) as u8, eta2);
    }

    // Step 5: Generate error polynomial e₂ with CBD(η₂), nonce 2k
    let e2 = sample_noise_poly(r_coins, (2 * k) as u8, eta2);

    // Step 6: ŷ = NTT(y)
    y.ntt();

    // Step 7: u = NTT⁻¹(Â^T · ŷ) + e₁
    // Â^T[j,i] = Â[i,j], so the j-th row of Â^T is the j-th column of Â
    let mut u = PolyVec::zero(k);
    for j in 0..k {
        let mut u_j = Poly::zero();
        for i in 0..k {
            // Â^T[j,i] = Â[i,j] = a_hat[i * k + j]
            let product = a_hat[i * k + j].ntt_multiply(y.poly(i));
            u_j.add_assign(&product);
        }
        u_j.ntt_inverse();
        u_j.add_assign(e1.poly(j));
        *u.poly_mut(j) = u_j;
    }

    // Step 8: μ = Decompress₁(ByteDecode₁(m))
    // m is 32 bytes = 256 bits, each bit is a coefficient
    // Decompress₁(b) maps 0 → 0, 1 → round(Q/2) = 1665
    let mu = decode_message(m);

    // Step 9: v = NTT⁻¹(t̂^T · ŷ) + e₂ + μ
    // t̂^T · ŷ is the inner product of t̂ and ŷ in NTT domain
    let mut v = t_hat.inner_product_ntt(&y);
    v.ntt_inverse();
    v.add_assign(&e2);
    v.add_assign(&mu);

    // Step 10: c₁ = ByteEncode_{du}(Compress_{du}(u))
    let mut c1 = alloc::vec::Vec::with_capacity(k * N * du / 8);
    for i in 0..k {
        let compressed = compress_poly(u.poly(i), du as u32);
        c1.extend_from_slice(&compressed.encode_d(du));
    }

    // Step 11: c₂ = ByteEncode_{dv}(Compress_{dv}(v))
    let compressed_v = compress_poly(&v, dv as u32);
    let c2 = compressed_v.encode_d(dv);

    // Step 12: c = c₁ || c₂
    let mut c = alloc::vec::Vec::with_capacity(c1.len() + c2.len());
    c.extend_from_slice(&c1);
    c.extend_from_slice(&c2);

    c
}

/// Decode a 32-byte message into a polynomial.
///
/// Each bit of `m` becomes a coefficient:
///   bit 0 → Decompress₁(0) = 0
///   bit 1 → Decompress₁(1) = round(Q/2) = 1665
///
/// FIPS 203: μ = Decompress₁(ByteDecode₁(m))
fn decode_message(m: &[u8; 32]) -> Poly {
    let mut poly = Poly::zero();
    for i in 0..N {
        let byte_idx = i / 8;
        let bit_idx = i % 8;
        let bit = (m[byte_idx] >> bit_idx) & 1;
        poly.coeffs_mut()[i] = decompress(bit as u16, 1);
    }
    poly
}

/// Encode a polynomial back to a 32-byte message.
///
/// Each coefficient is compressed to 1 bit:
///   Compress₁(x) maps x to {0, 1}
///
/// FIPS 203: m = ByteEncode₁(Compress₁(v - e₂ - μ_recovered))
/// Used in K-PKE.Decrypt (Phase 9).
#[allow(dead_code)] // Used by decaps.rs in Phase 9
pub(crate) fn encode_message(p: &Poly) -> [u8; 32] {
    use crate::mlkem::math::compress::compress;
    let mut m = [0u8; 32];
    for i in 0..N {
        let bit = compress(p.coeffs()[i], 1);
        m[i / 8] |= (bit as u8) << (i % 8);
    }
    m
}

// ---------------------------------------------------------------------------
// ML-KEM.Encaps — FIPS 203 Algorithm 16
// ---------------------------------------------------------------------------

/// ML-KEM.Encaps — FIPS 203 Algorithm 16.
///
/// Generates a shared secret and capsule from the recipient's public key.
///
/// Steps:
/// 1. m ← random(32 bytes)
/// 2. (K, r) = G(m || H(ek))
/// 3. c = K-PKE.Encrypt(ek, m, r)
/// 4. Return (K, c)
///
/// # Arguments
/// - `ek`: The recipient's ML-KEM encryption (public) key
/// - `level`: The security level (must match the key's level)
///
/// # Returns
/// `(shared_secret, capsule)` — the 32-byte shared secret and the capsule (ciphertext)
///
/// # Errors
/// - `AegisQError::InvalidParameter` if `ek` has the wrong size
/// - `AegisQError::RngError` if the OS CSPRNG is unavailable
pub fn ml_kem_encaps(
    ek: &[u8],
    level: SecurityLevel,
) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), AegisQError> {
    let params = params_for_level(level);

    // Validate ek size
    let expected_ek_len = params.k * 384 + 32;
    if ek.len() != expected_ek_len {
        return Err(AegisQError::InvalidParameter(
            "encryption key has incorrect size",
        ));
    }

    // Step 1: m ← random(32 bytes)
    let mut m = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut m)
        .map_err(|_| AegisQError::RngError)?;

    // Step 2: (K, r) = G(m || H(ek))
    let h_ek = hash_h(ek);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m);
    g_input[32..].copy_from_slice(&h_ek);
    let g_output = hash_g(&g_input);

    let shared_secret = g_output[..32].to_vec();
    let r_coins: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&g_output[32..64]);
        buf
    };

    // Step 3: c = K-PKE.Encrypt(ek, m, r)
    let capsule = k_pke_encrypt(ek, &m, &r_coins, &params);

    // Zeroize sensitive intermediates
    use zeroize::Zeroize;
    m.zeroize();

    Ok((shared_secret, capsule))
}

/// Deterministic variant of ML-KEM.Encaps for testing and for Decaps re-encryption.
///
/// Takes an explicit message `m` instead of generating it randomly.
/// This is used by:
/// - Tests (KAT vector validation)
/// - Decaps (re-encryption check in Algorithm 17)
#[allow(dead_code)] // Used by decaps.rs in Phase 9
pub(crate) fn ml_kem_encaps_deterministic(
    ek: &[u8],
    m: &[u8; 32],
    level: SecurityLevel,
) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
    let params = params_for_level(level);

    let h_ek = hash_h(ek);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h_ek);
    let g_output = hash_g(&g_input);

    let shared_secret = g_output[..32].to_vec();
    let r_coins: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&g_output[32..64]);
        buf
    };

    let capsule = k_pke_encrypt(ek, m, &r_coins, &params);

    (shared_secret, capsule)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::keygen::{ml_kem_keygen, ml_kem_keygen_deterministic};

    // --- Capsule size verification ---

    #[test]
    fn test_encaps_512_capsule_size() {
        let level = SecurityLevel::MlKem512;
        let (ek, _) = ml_kem_keygen(level).expect("keygen should succeed");
        let (ss, capsule) = ml_kem_encaps(&ek, level).expect("encaps should succeed");

        assert_eq!(
            capsule.len(),
            level.capsule_size(),
            "capsule size for ML-KEM-512"
        );
        assert_eq!(ss.len(), 32, "shared secret size");
    }

    #[test]
    fn test_encaps_768_capsule_size() {
        let level = SecurityLevel::MlKem768;
        let (ek, _) = ml_kem_keygen(level).expect("keygen should succeed");
        let (ss, capsule) = ml_kem_encaps(&ek, level).expect("encaps should succeed");

        assert_eq!(
            capsule.len(),
            level.capsule_size(),
            "capsule size for ML-KEM-768"
        );
        assert_eq!(ss.len(), 32, "shared secret size");
    }

    #[test]
    fn test_encaps_1024_capsule_size() {
        let level = SecurityLevel::MlKem1024;
        let (ek, _) = ml_kem_keygen(level).expect("keygen should succeed");
        let (ss, capsule) = ml_kem_encaps(&ek, level).expect("encaps should succeed");

        assert_eq!(
            capsule.len(),
            level.capsule_size(),
            "capsule size for ML-KEM-1024"
        );
        assert_eq!(ss.len(), 32, "shared secret size");
    }

    // --- Deterministic encaps is consistent ---

    #[test]
    fn test_encaps_deterministic_consistent() {
        let d = [0x42u8; 32];
        let z = [0x13u8; 32];
        let m = [0x55u8; 32];
        let level = SecurityLevel::MlKem768;

        let (ek, _) = ml_kem_keygen_deterministic(&d, &z, level);

        let (ss1, c1) = ml_kem_encaps_deterministic(&ek, &m, level);
        let (ss2, c2) = ml_kem_encaps_deterministic(&ek, &m, level);

        assert_eq!(ss1, ss2, "deterministic encaps: same shared secret");
        assert_eq!(c1, c2, "deterministic encaps: same capsule");
    }

    // --- Different messages produce different results ---

    #[test]
    fn test_encaps_different_messages() {
        let d = [0x01u8; 32];
        let z = [0x02u8; 32];
        let level = SecurityLevel::MlKem768;

        let (ek, _) = ml_kem_keygen_deterministic(&d, &z, level);

        let m1 = [0xAAu8; 32];
        let m2 = [0xBBu8; 32];

        let (ss1, c1) = ml_kem_encaps_deterministic(&ek, &m1, level);
        let (ss2, c2) = ml_kem_encaps_deterministic(&ek, &m2, level);

        assert_ne!(
            ss1, ss2,
            "different messages should give different shared secrets"
        );
        assert_ne!(c1, c2, "different messages should give different capsules");
    }

    // --- Random encaps produces different results each time ---

    #[test]
    fn test_encaps_random_different() {
        let level = SecurityLevel::MlKem768;
        let (ek, _) = ml_kem_keygen(level).expect("keygen should succeed");

        let (ss1, c1) = ml_kem_encaps(&ek, level).expect("encaps should succeed");
        let (ss2, c2) = ml_kem_encaps(&ek, level).expect("encaps should succeed");

        assert_ne!(
            ss1, ss2,
            "random encaps should produce different shared secrets"
        );
        assert_ne!(c1, c2, "random encaps should produce different capsules");
    }

    // --- Invalid ek size is rejected ---

    #[test]
    fn test_encaps_invalid_ek_size() {
        let level = SecurityLevel::MlKem768;
        let bad_ek = alloc::vec![0u8; 100]; // Wrong size

        let result = ml_kem_encaps(&bad_ek, level);
        assert!(result.is_err(), "encaps should reject wrong ek size");
    }

    // --- Encode/decode message roundtrip ---

    #[test]
    fn test_message_encode_decode_roundtrip() {
        let m: [u8; 32] = [
            0xFF, 0x00, 0xAA, 0x55, 0x0F, 0xF0, 0x33, 0xCC, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
            0x40, 0x80, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x56, 0x78,
            0x9A, 0xBC, 0xDE, 0xF0,
        ];

        let poly = decode_message(&m);
        let m_recovered = encode_message(&poly);

        assert_eq!(m, m_recovered, "message encode/decode roundtrip failed");
    }

    // --- Message decoding maps bits correctly ---

    #[test]
    fn test_message_decode_bits() {
        let mut m = [0u8; 32];
        m[0] = 0b10101010; // bits: 0,1,0,1,0,1,0,1

        let poly = decode_message(&m);

        // Bit 0 → 0, Bit 1 → 1665, Bit 2 → 0, etc.
        assert_eq!(poly.coeffs()[0].value(), 0);
        assert_eq!(poly.coeffs()[1].value(), 1665);
        assert_eq!(poly.coeffs()[2].value(), 0);
        assert_eq!(poly.coeffs()[3].value(), 1665);
    }

    // --- All levels produce valid capsule and shared secret ---

    #[test]
    fn test_encaps_all_levels() {
        for level in [
            SecurityLevel::MlKem512,
            SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024,
        ] {
            let (ek, _) = ml_kem_keygen(level).expect("keygen should succeed");
            let result = ml_kem_encaps(&ek, level);
            assert!(result.is_ok(), "encaps should succeed for {:?}", level);

            let (ss, capsule) = result.expect("already checked");
            assert_eq!(ss.len(), 32);
            assert_eq!(capsule.len(), level.capsule_size());
        }
    }

    // --- Capsule structure: c₁ and c₂ sizes ---

    #[test]
    fn test_capsule_component_sizes() {
        // For ML-KEM-768: du=10, dv=4, k=3
        // c₁ = k * N * du / 8 = 3 * 256 * 10 / 8 = 960
        // c₂ = N * dv / 8 = 256 * 4 / 8 = 128
        // total = 960 + 128 = 1088
        let level = SecurityLevel::MlKem768;
        let params = params_for_level(level);
        let c1_len = params.k * N * params.du / 8;
        let c2_len = N * params.dv / 8;
        assert_eq!(c1_len + c2_len, level.capsule_size());

        // For ML-KEM-512: du=10, dv=4, k=2
        // c₁ = 2 * 256 * 10 / 8 = 640
        // c₂ = 256 * 4 / 8 = 128
        // total = 768
        let level = SecurityLevel::MlKem512;
        let params = params_for_level(level);
        let c1_len = params.k * N * params.du / 8;
        let c2_len = N * params.dv / 8;
        assert_eq!(c1_len + c2_len, level.capsule_size());

        // For ML-KEM-1024: du=11, dv=5, k=4
        // c₁ = 4 * 256 * 11 / 8 = 1408
        // c₂ = 256 * 5 / 8 = 160
        // total = 1568
        let level = SecurityLevel::MlKem1024;
        let params = params_for_level(level);
        let c1_len = params.k * N * params.du / 8;
        let c2_len = N * params.dv / 8;
        assert_eq!(c1_len + c2_len, level.capsule_size());
    }
}

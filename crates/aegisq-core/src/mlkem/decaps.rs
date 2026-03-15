//! ML-KEM.Decaps — Decapsulation with implicit rejection (FIPS 203 Alg. 17).
//!
//! Implements:
//! - K-PKE.Decrypt (Algorithm 14): Inner CPA decryption
//! - ML-KEM.Decaps (Algorithm 17): Outer CCA-secure decapsulation
//!
//! CRITICAL (FIPS 203 §7.3): When the ciphertext is invalid, this function
//! NEVER returns an error. Instead, it silently returns a pseudorandom key
//! derived from `z || c`. This prevents CCA2 attacks via oracle queries.
//!
//! Fase 9 de la hoja de ruta.

use crate::error::AegisQError;
use crate::kem::SecurityLevel;
use crate::mlkem::encaps::{encode_message, k_pke_encrypt};
use crate::mlkem::math::compress::decompress_poly;
use crate::mlkem::math::poly::{Poly, PolyVec};
use crate::mlkem::params::{MlKemParams, N, params_for_level};
use crate::mlkem::sampling::{hash_g, hash_j};
use subtle::ConstantTimeEq;

// ---------------------------------------------------------------------------
// K-PKE.Decrypt — FIPS 203 Algorithm 14
// ---------------------------------------------------------------------------

/// K-PKE.Decrypt — FIPS 203 Algorithm 14.
///
/// Decrypts a CPA ciphertext `c` using the CPA decryption key `dk_pke`.
///
/// Steps:
/// 1. Parse c as (c₁ || c₂)
/// 2. u' = Decompress_{du}(ByteDecode_{du}(c₁))
/// 3. v' = Decompress_{dv}(ByteDecode_{dv}(c₂))
/// 4. ŝ = ByteDecode₁₂(dk_pke)
/// 5. w = v' - NTT⁻¹(ŝ^T · NTT(u'))
/// 6. m = ByteEncode₁(Compress₁(w))
/// 7. Return m
fn k_pke_decrypt(dk_pke: &[u8], c: &[u8], params: &MlKemParams) -> [u8; 32] {
    let k = params.k;
    let du = params.du;
    let dv = params.dv;

    // Step 1: Parse c as (c₁ || c₂)
    let c1_len = k * N * du / 8;
    let c1 = &c[..c1_len];
    let c2 = &c[c1_len..];

    // Step 2: u' = Decompress_{du}(ByteDecode_{du}(c₁))
    let mut u_prime = PolyVec::zero(k);
    for i in 0..k {
        let chunk = &c1[i * (N * du / 8)..(i + 1) * (N * du / 8)];
        let encoded = Poly::decode_d(chunk, du);
        *u_prime.poly_mut(i) = decompress_poly(&encoded, du as u32);
    }

    // Step 3: v' = Decompress_{dv}(ByteDecode_{dv}(c₂))
    let encoded_v = Poly::decode_d(c2, dv);
    let v_prime = decompress_poly(&encoded_v, dv as u32);

    // Step 4: ŝ = ByteDecode₁₂(dk_pke)
    let s_hat = PolyVec::from_bytes(dk_pke, k);

    // Step 5: w = v' - NTT⁻¹(ŝ^T · NTT(u'))
    u_prime.ntt();
    let mut inner = s_hat.inner_product_ntt(&u_prime);
    inner.ntt_inverse();
    let w = v_prime.sub(&inner);

    // Step 6: m = ByteEncode₁(Compress₁(w))
    encode_message(&w)
}

// ---------------------------------------------------------------------------
// ML-KEM.Decaps — FIPS 203 Algorithm 17
// ---------------------------------------------------------------------------

/// ML-KEM.Decaps — FIPS 203 Algorithm 17.
///
/// Decapsulates the shared secret from a capsule using the secret key.
///
/// **CRITICAL SECURITY PROPERTY:** This function NEVER returns an error for
/// invalid ciphertext. If the capsule was tampered with, it silently returns
/// a pseudorandom key derived from `z || c`. This prevents CCA2 attacks.
///
/// Steps:
/// 1. Parse dk as (dk_pke || ek || h || z)
/// 2. m' = K-PKE.Decrypt(dk_pke, c)
/// 3. (K̄', r') = G(m' || h)
/// 4. K̄_reject = J(z || c)
/// 5. c' = K-PKE.Encrypt(ek, m', r')
/// 6. if c == c' (CONSTANT-TIME): return K̄'
///    else: return K̄_reject  (IMPLICIT REJECTION — no error!)
///
/// # Arguments
/// - `c`: The capsule (ciphertext) received from the sender
/// - `dk`: The recipient's ML-KEM decapsulation (secret) key
/// - `level`: The security level (must match the key's level)
///
/// # Returns
/// A 32-byte shared secret — always succeeds (implicit rejection on invalid input)
///
/// # Errors
/// - `AegisQError::InvalidParameter` if `dk` or `c` have the wrong size
///   (structural errors only — NOT for invalid ciphertext content)
pub fn ml_kem_decaps(
    c: &[u8],
    dk: &[u8],
    level: SecurityLevel,
) -> Result<alloc::vec::Vec<u8>, AegisQError> {
    let params = params_for_level(level);
    let k = params.k;

    // Validate sizes (structural check only)
    let expected_dk_len = k * 384 + (k * 384 + 32) + 32 + 32;
    if dk.len() != expected_dk_len {
        return Err(AegisQError::InvalidParameter(
            "decapsulation key has incorrect size",
        ));
    }

    let expected_c_len = level.capsule_size();
    if c.len() != expected_c_len {
        return Err(AegisQError::InvalidParameter("capsule has incorrect size"));
    }

    // Step 1: Parse dk as (dk_pke || ek || h || z)
    let dk_pke_len = k * 384;
    let ek_len = k * 384 + 32;

    let dk_pke = &dk[..dk_pke_len];
    let ek = &dk[dk_pke_len..dk_pke_len + ek_len];
    let h: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32]);
        buf
    };
    let z: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&dk[dk_pke_len + ek_len + 32..dk_pke_len + ek_len + 64]);
        buf
    };

    // Step 2: m' = K-PKE.Decrypt(dk_pke, c)
    let m_prime = k_pke_decrypt(dk_pke, c, &params);

    // Step 3: (K̄', r') = G(m' || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(&h);
    let g_output = hash_g(&g_input);

    let k_bar_prime: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&g_output[..32]);
        buf
    };
    let r_prime: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&g_output[32..64]);
        buf
    };

    // Step 4: K̄_reject = J(z || c)
    // J is SHAKE-256, producing 32 bytes
    let mut j_input = alloc::vec::Vec::with_capacity(32 + c.len());
    j_input.extend_from_slice(&z);
    j_input.extend_from_slice(c);
    let k_bar_reject = hash_j(&j_input);

    // Step 5: c' = K-PKE.Encrypt(ek, m', r')
    let c_prime = k_pke_encrypt(ek, &m_prime, &r_prime, &params);

    // Step 6: Constant-time comparison and selection
    // FIPS 203 §7.3: MUST be constant-time to prevent CCA2 attacks
    let capsules_match: subtle::Choice = c.ct_eq(&c_prime);

    // Constant-time selection: if match → k_bar_prime, else → k_bar_reject
    let mut shared_secret = [0u8; 32];
    for i in 0..32 {
        // ct_select: if capsules_match then k_bar_prime[i] else k_bar_reject[i]
        shared_secret[i] = subtle::ConditionallySelectable::conditional_select(
            &k_bar_reject[i],
            &k_bar_prime[i],
            capsules_match,
        );
    }

    Ok(shared_secret.to_vec())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mlkem::encaps::{ml_kem_encaps, ml_kem_encaps_deterministic};
    use crate::mlkem::keygen::{ml_kem_keygen, ml_kem_keygen_deterministic};

    // --- Full roundtrip: KeyGen → Encaps → Decaps ---

    #[test]
    fn test_roundtrip_768() {
        let level = SecurityLevel::MlKem768;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen");
        let (ss_encaps, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
        let ss_decaps = ml_kem_decaps(&capsule, &dk, level).expect("decaps");

        assert_eq!(
            ss_encaps, ss_decaps,
            "shared secrets must match after roundtrip"
        );
    }

    #[test]
    fn test_roundtrip_512() {
        let level = SecurityLevel::MlKem512;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen");
        let (ss_encaps, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
        let ss_decaps = ml_kem_decaps(&capsule, &dk, level).expect("decaps");

        assert_eq!(ss_encaps, ss_decaps, "roundtrip ML-KEM-512");
    }

    #[test]
    fn test_roundtrip_1024() {
        let level = SecurityLevel::MlKem1024;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen");
        let (ss_encaps, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
        let ss_decaps = ml_kem_decaps(&capsule, &dk, level).expect("decaps");

        assert_eq!(ss_encaps, ss_decaps, "roundtrip ML-KEM-1024");
    }

    // --- Deterministic roundtrip ---

    #[test]
    fn test_roundtrip_deterministic() {
        let d = [0x42u8; 32];
        let z = [0x13u8; 32];
        let m = [0xAAu8; 32];
        let level = SecurityLevel::MlKem768;

        let (ek, dk) = ml_kem_keygen_deterministic(&d, &z, level);
        let (ss_encaps, capsule) = ml_kem_encaps_deterministic(&ek, &m, level);
        let ss_decaps = ml_kem_decaps(&capsule, &dk, level).expect("decaps");

        assert_eq!(ss_encaps, ss_decaps, "deterministic roundtrip");
    }

    // --- Implicit rejection: tampered capsule returns different key ---

    #[test]
    fn test_implicit_rejection_tampered_capsule() {
        let level = SecurityLevel::MlKem768;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen");
        let (ss_encaps, mut capsule) = ml_kem_encaps(&ek, level).expect("encaps");

        // Tamper with the capsule (flip some bytes)
        capsule[0] ^= 0xFF;
        capsule[100] ^= 0xFF;
        capsule[500] ^= 0xFF;

        // Decaps should NOT return an error — implicit rejection
        let ss_decaps = ml_kem_decaps(&capsule, &dk, level).expect("decaps must not fail");

        // But the shared secret should be DIFFERENT from the original
        assert_ne!(
            ss_encaps, ss_decaps,
            "tampered capsule must produce different shared secret (implicit rejection)"
        );

        // The rejected key should be 32 bytes
        assert_eq!(ss_decaps.len(), 32);
    }

    // --- Implicit rejection is deterministic for same inputs ---

    #[test]
    fn test_implicit_rejection_deterministic() {
        let d = [0x01u8; 32];
        let z = [0x02u8; 32];
        let m = [0x03u8; 32];
        let level = SecurityLevel::MlKem768;

        let (ek, dk) = ml_kem_keygen_deterministic(&d, &z, level);
        let (_, mut capsule) = ml_kem_encaps_deterministic(&ek, &m, level);

        // Tamper
        capsule[0] ^= 0xFF;

        let ss1 = ml_kem_decaps(&capsule, &dk, level).expect("decaps");
        let ss2 = ml_kem_decaps(&capsule, &dk, level).expect("decaps");

        assert_eq!(
            ss1, ss2,
            "implicit rejection must be deterministic for same (z, c)"
        );
    }

    // --- Wrong dk produces different shared secret ---

    #[test]
    fn test_wrong_dk_different_secret() {
        let level = SecurityLevel::MlKem768;
        let (ek, _dk_correct) = ml_kem_keygen(level).expect("keygen");
        let (_ek2, dk_wrong) = ml_kem_keygen(level).expect("keygen2");

        let (ss_encaps, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
        let ss_decaps = ml_kem_decaps(&capsule, &dk_wrong, level).expect("decaps");

        assert_ne!(
            ss_encaps, ss_decaps,
            "wrong dk should produce different shared secret"
        );
    }

    // --- Invalid dk size is rejected ---

    #[test]
    fn test_decaps_invalid_dk_size() {
        let level = SecurityLevel::MlKem768;
        let bad_dk = alloc::vec![0u8; 100];
        let capsule = alloc::vec![0u8; level.capsule_size()];

        let result = ml_kem_decaps(&capsule, &bad_dk, level);
        assert!(result.is_err(), "decaps should reject wrong dk size");
    }

    // --- Invalid capsule size is rejected ---

    #[test]
    fn test_decaps_invalid_capsule_size() {
        let level = SecurityLevel::MlKem768;
        let (_, dk) = ml_kem_keygen(level).expect("keygen");
        let bad_capsule = alloc::vec![0u8; 100];

        let result = ml_kem_decaps(&bad_capsule, &dk, level);
        assert!(result.is_err(), "decaps should reject wrong capsule size");
    }

    // --- Multiple roundtrips with same key pair ---

    #[test]
    fn test_multiple_roundtrips_same_keypair() {
        let level = SecurityLevel::MlKem768;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen");

        for _ in 0..5 {
            let (ss_enc, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
            let ss_dec = ml_kem_decaps(&capsule, &dk, level).expect("decaps");
            assert_eq!(ss_enc, ss_dec, "roundtrip must succeed with same keypair");
        }
    }

    // --- Shared secret is 32 bytes ---

    #[test]
    fn test_shared_secret_size() {
        let level = SecurityLevel::MlKem768;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen");
        let (_, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
        let ss = ml_kem_decaps(&capsule, &dk, level).expect("decaps");

        assert_eq!(ss.len(), 32, "shared secret must be 32 bytes");
    }

    // --- All three levels roundtrip ---

    #[test]
    fn test_roundtrip_all_levels() {
        for level in [
            SecurityLevel::MlKem512,
            SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024,
        ] {
            let (ek, dk) = ml_kem_keygen(level).expect("keygen");
            let (ss_enc, capsule) = ml_kem_encaps(&ek, level).expect("encaps");
            let ss_dec = ml_kem_decaps(&capsule, &dk, level).expect("decaps");
            assert_eq!(ss_enc, ss_dec, "roundtrip failed for {:?}", level);
        }
    }
}

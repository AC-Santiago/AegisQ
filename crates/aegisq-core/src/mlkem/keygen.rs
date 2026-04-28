//! ML-KEM Key Generation — FIPS 203.
//!
//! Implements:
//! - K-PKE.KeyGen (Algorithm 12): Inner CPA key generation
//! - ML-KEM.KeyGen (Algorithm 15): Outer CCA-secure key generation
//!
//! The public API is `ml_kem_keygen()` which produces a full ML-KEM key pair.
//!
//! Fase 7 de la hoja de ruta.

use crate::error::AegisQError;
use crate::kem::SecurityLevel;
use crate::mlkem::math::poly::{Poly, PolyVec};
use crate::mlkem::params::{MlKemParams, params_for_level};
use crate::mlkem::sampling::{hash_g, hash_h, sample_noise_poly, sample_ntt};
use getrandom::fill;

/// Wrapper around getrandom to provide try_fill_bytes method.
struct OsRng;

impl OsRng {
    fn try_fill_bytes(&self, dest: &mut [u8]) -> Result<(), getrandom::Error> {
        fill(dest)
    }
}

// ---------------------------------------------------------------------------
// K-PKE.KeyGen — FIPS 203 Algorithm 12
// ---------------------------------------------------------------------------

/// Output of K-PKE.KeyGen: the inner CPA encryption/decryption key pair.
///
/// - `ek_pke`: Encryption key = ByteEncode₁₂(t̂) || ρ
/// - `dk_pke`: Decryption key = ByteEncode₁₂(ŝ)
struct CpaKeyPair {
    ek_pke: alloc::vec::Vec<u8>,
    dk_pke: alloc::vec::Vec<u8>,
}

/// K-PKE.KeyGen — FIPS 203 Algorithm 12.
///
/// Generates a CPA-secure encryption key pair from a 32-byte seed `d`.
///
/// Steps:
/// 1. (ρ, σ) = G(d || k)
/// 2. Â[i,j] = SampleNTT(ρ, i, j)     for i,j in 0..k
/// 3. s[i]   = SamplePolyCBD_η₁(σ, i)  for i in 0..k
/// 4. e[i]   = SamplePolyCBD_η₁(σ, k+i) for i in 0..k
/// 5. ŝ = NTT(s),  ê = NTT(e)
/// 6. t̂ = Â · ŝ + ê
/// 7. ek_pke = ByteEncode₁₂(t̂) || ρ
/// 8. dk_pke = ByteEncode₁₂(ŝ)
fn k_pke_keygen(d: &[u8; 32], params: &MlKemParams) -> CpaKeyPair {
    let k = params.k;
    let eta1 = params.eta1;

    // Step 1: (ρ, σ) = G(d || k)
    // FIPS 203: G takes (d || k) where k is the dimension as a single byte
    let mut g_input = alloc::vec::Vec::with_capacity(33);
    g_input.extend_from_slice(d);
    g_input.push(k as u8);
    let g_output = hash_g(&g_input);
    let rho: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&g_output[0..32]);
        buf
    };
    let sigma: [u8; 32] = {
        let mut buf = [0u8; 32];
        buf.copy_from_slice(&g_output[32..64]);
        buf
    };

    // Step 2: Generate matrix Â in NTT domain from ρ
    // Â is a k×k matrix of polynomials. Â[i][j] = SampleNTT(ρ, i, j)
    // We store it as a flat Vec of k*k polynomials, row-major: A_hat[i*k + j]
    let mut a_hat = alloc::vec::Vec::with_capacity(k * k);
    for i in 0..k {
        for j in 0..k {
            a_hat.push(sample_ntt(&rho, i as u8, j as u8));
        }
    }

    // Step 3: Generate secret vector s with CBD(η₁), nonces 0..k-1
    let mut s = PolyVec::zero(k);
    for i in 0..k {
        *s.poly_mut(i) = sample_noise_poly(&sigma, i as u8, eta1);
    }

    // Step 4: Generate error vector e with CBD(η₁), nonces k..2k-1
    let mut e = PolyVec::zero(k);
    for i in 0..k {
        *e.poly_mut(i) = sample_noise_poly(&sigma, (k + i) as u8, eta1);
    }

    // Step 5: ŝ = NTT(s), ê = NTT(e)
    s.ntt();
    e.ntt();

    // Step 6: t̂ = Â · ŝ + ê
    // t̂[i] = sum_j(Â[i,j] ◦ ŝ[j]) + ê[i]
    let mut t_hat = PolyVec::zero(k);
    for i in 0..k {
        let mut t_i = Poly::zero();
        for j in 0..k {
            let product = a_hat[i * k + j].ntt_multiply(s.poly(j));
            t_i.add_assign(&product);
        }
        t_i.add_assign(e.poly(i));
        *t_hat.poly_mut(i) = t_i;
    }

    // Step 7: ek_pke = ByteEncode₁₂(t̂) || ρ
    let t_hat_bytes = t_hat.to_bytes(); // k * 384 bytes
    let mut ek_pke = alloc::vec::Vec::with_capacity(t_hat_bytes.len() + 32);
    ek_pke.extend_from_slice(&t_hat_bytes);
    ek_pke.extend_from_slice(&rho);

    // Step 8: dk_pke = ByteEncode₁₂(ŝ)
    let dk_pke = s.to_bytes(); // k * 384 bytes

    CpaKeyPair { ek_pke, dk_pke }
}

// ---------------------------------------------------------------------------
// ML-KEM.KeyGen — FIPS 203 Algorithm 15
// ---------------------------------------------------------------------------

/// ML-KEM.KeyGen — FIPS 203 Algorithm 15.
///
/// Generates a CCA-secure ML-KEM key pair for the given security level.
///
/// Steps:
/// 1. d ← random(32), z ← random(32)
/// 2. (ek_pke, dk_pke) = K-PKE.KeyGen(d)
/// 3. ek = ek_pke
/// 4. dk = dk_pke || ek || H(ek) || z
///
/// Returns `(ek, dk)` as byte vectors.
///
/// # Errors
/// Returns `AegisQError::RngError` if the OS CSPRNG is unavailable.
pub fn ml_kem_keygen(
    level: SecurityLevel,
) -> Result<(alloc::vec::Vec<u8>, alloc::vec::Vec<u8>), AegisQError> {
    let params = params_for_level(level);

    // Step 1: Generate random seeds d and z (32 bytes each)
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut d)
        .map_err(|_| AegisQError::RngError)?;
    OsRng
        .try_fill_bytes(&mut z)
        .map_err(|_| AegisQError::RngError)?;

    // Step 2: K-PKE.KeyGen(d) → (ek_pke, dk_pke)
    let cpa_keys = k_pke_keygen(&d, &params);

    // Step 3: ek = ek_pke
    let ek = cpa_keys.ek_pke;

    // Step 4: dk = dk_pke || ek || H(ek) || z
    let h_ek = hash_h(&ek);
    let dk_len = cpa_keys.dk_pke.len() + ek.len() + 32 + 32;
    let mut dk = alloc::vec::Vec::with_capacity(dk_len);
    dk.extend_from_slice(&cpa_keys.dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(&z);

    // Zeroize sensitive intermediate values
    // d and z are on the stack and will be dropped, but let's be explicit
    use zeroize::Zeroize;
    d.zeroize();
    z.zeroize();

    Ok((ek, dk))
}

/// Deterministic variant of K-PKE.KeyGen for testing purposes.
///
/// Takes explicit `d` seed instead of generating from OsRng.
/// This is NOT for production use — only for KAT vector validation.
#[cfg(test)]
fn k_pke_keygen_deterministic(d: &[u8; 32], level: SecurityLevel) -> CpaKeyPair {
    let params = params_for_level(level);
    k_pke_keygen(d, &params)
}

/// Deterministic variant of ML-KEM.KeyGen for testing purposes.
///
/// Takes explicit `d` and `z` seeds instead of generating from OsRng.
/// This is NOT for production use — only for KAT vector validation.
pub(crate) fn ml_kem_keygen_deterministic(
    d: &[u8; 32],
    z: &[u8; 32],
    level: SecurityLevel,
) -> (alloc::vec::Vec<u8>, alloc::vec::Vec<u8>) {
    let params = params_for_level(level);
    let cpa_keys = k_pke_keygen(d, &params);

    let ek = cpa_keys.ek_pke;
    let h_ek = hash_h(&ek);
    let dk_len = cpa_keys.dk_pke.len() + ek.len() + 32 + 32;
    let mut dk = alloc::vec::Vec::with_capacity(dk_len);
    dk.extend_from_slice(&cpa_keys.dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);

    (ek, dk)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kem::SecurityLevel;

    // --- Key size verification ---

    #[test]
    fn test_keygen_512_sizes() {
        let level = SecurityLevel::MlKem512;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen should succeed");

        // ek = k*384 + 32 = 2*384 + 32 = 800
        assert_eq!(ek.len(), level.public_key_size(), "ek size for ML-KEM-512");
        // dk = k*384 + ek.len() + 32 + 32 = 768 + 800 + 32 + 32 = 1632
        assert_eq!(dk.len(), level.secret_key_size(), "dk size for ML-KEM-512");
    }

    #[test]
    fn test_keygen_768_sizes() {
        let level = SecurityLevel::MlKem768;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen should succeed");

        // ek = 3*384 + 32 = 1184
        assert_eq!(ek.len(), level.public_key_size(), "ek size for ML-KEM-768");
        // dk = 3*384 + 1184 + 32 + 32 = 1152 + 1184 + 64 = 2400
        assert_eq!(dk.len(), level.secret_key_size(), "dk size for ML-KEM-768");
    }

    #[test]
    fn test_keygen_1024_sizes() {
        let level = SecurityLevel::MlKem1024;
        let (ek, dk) = ml_kem_keygen(level).expect("keygen should succeed");

        // ek = 4*384 + 32 = 1568
        assert_eq!(ek.len(), level.public_key_size(), "ek size for ML-KEM-1024");
        // dk = 4*384 + 1568 + 32 + 32 = 1536 + 1568 + 64 = 3168
        assert_eq!(dk.len(), level.secret_key_size(), "dk size for ML-KEM-1024");
    }

    // --- Deterministic keygen produces consistent output ---

    #[test]
    fn test_keygen_deterministic_consistent() {
        let d = [0x42u8; 32];
        let z = [0x13u8; 32];

        let (ek1, dk1) = ml_kem_keygen_deterministic(&d, &z, SecurityLevel::MlKem768);
        let (ek2, dk2) = ml_kem_keygen_deterministic(&d, &z, SecurityLevel::MlKem768);

        assert_eq!(ek1, ek2, "deterministic keygen must produce same ek");
        assert_eq!(dk1, dk2, "deterministic keygen must produce same dk");
    }

    // --- Different seeds produce different keys ---

    #[test]
    fn test_keygen_different_seeds() {
        let d1 = [0x01u8; 32];
        let d2 = [0x02u8; 32];
        let z = [0x00u8; 32];

        let (ek1, _) = ml_kem_keygen_deterministic(&d1, &z, SecurityLevel::MlKem768);
        let (ek2, _) = ml_kem_keygen_deterministic(&d2, &z, SecurityLevel::MlKem768);

        assert_ne!(ek1, ek2, "different d seeds must produce different ek");
    }

    // --- dk contains ek, H(ek), and z in the correct positions ---

    #[test]
    fn test_keygen_dk_structure_768() {
        let d = [0xAAu8; 32];
        let z = [0xBBu8; 32];
        let level = SecurityLevel::MlKem768;
        let k = 3usize;

        let (ek, dk) = ml_kem_keygen_deterministic(&d, &z, level);

        // dk layout: dk_pke (k*384) || ek (k*384 + 32) || H(ek) (32) || z (32)
        let dk_pke_len = k * 384;
        let ek_len = ek.len();

        // dk_pke is the first k*384 bytes
        assert_eq!(dk.len(), dk_pke_len + ek_len + 32 + 32);

        // ek is embedded in dk starting at offset dk_pke_len
        let ek_in_dk = &dk[dk_pke_len..dk_pke_len + ek_len];
        assert_eq!(ek_in_dk, &ek[..], "ek must be embedded in dk");

        // H(ek) follows ek
        let h_ek = hash_h(&ek);
        let h_ek_in_dk = &dk[dk_pke_len + ek_len..dk_pke_len + ek_len + 32];
        assert_eq!(h_ek_in_dk, &h_ek[..], "H(ek) must be in dk");

        // z is the last 32 bytes
        let z_in_dk = &dk[dk.len() - 32..];
        assert_eq!(z_in_dk, &z[..], "z must be the last 32 bytes of dk");
    }

    // --- Structure test for ML-KEM-512 ---

    #[test]
    fn test_keygen_dk_structure_512() {
        let d = [0xCCu8; 32];
        let z = [0xDDu8; 32];
        let level = SecurityLevel::MlKem512;
        let k = 2usize;

        let (ek, dk) = ml_kem_keygen_deterministic(&d, &z, level);

        let dk_pke_len = k * 384;
        let ek_len = ek.len();

        assert_eq!(dk.len(), dk_pke_len + ek_len + 32 + 32);

        // ek embedded in dk
        assert_eq!(&dk[dk_pke_len..dk_pke_len + ek_len], &ek[..]);

        // z at the end
        assert_eq!(&dk[dk.len() - 32..], &z[..]);
    }

    // --- Structure test for ML-KEM-1024 ---

    #[test]
    fn test_keygen_dk_structure_1024() {
        let d = [0xEEu8; 32];
        let z = [0xFFu8; 32];
        let level = SecurityLevel::MlKem1024;
        let k = 4usize;

        let (ek, dk) = ml_kem_keygen_deterministic(&d, &z, level);

        let dk_pke_len = k * 384;
        let ek_len = ek.len();

        assert_eq!(dk.len(), dk_pke_len + ek_len + 32 + 32);

        // ek embedded
        assert_eq!(&dk[dk_pke_len..dk_pke_len + ek_len], &ek[..]);

        // z at end
        assert_eq!(&dk[dk.len() - 32..], &z[..]);
    }

    // --- ek starts with encoded t̂ and ends with ρ ---

    #[test]
    fn test_keygen_ek_ends_with_rho() {
        // Two calls with same d should produce same ρ (last 32 bytes of ek)
        let d = [0x55u8; 32];
        let z1 = [0x01u8; 32];
        let z2 = [0x02u8; 32];

        let (ek1, _) = ml_kem_keygen_deterministic(&d, &z1, SecurityLevel::MlKem768);
        let (ek2, _) = ml_kem_keygen_deterministic(&d, &z2, SecurityLevel::MlKem768);

        // Same d → same (ρ, σ) → same ek, regardless of z
        assert_eq!(ek1, ek2, "same d must produce same ek regardless of z");

        // ρ is the last 32 bytes of ek
        let rho1 = &ek1[ek1.len() - 32..];
        let rho2 = &ek2[ek2.len() - 32..];
        assert_eq!(rho1, rho2);
    }

    // --- Random keygen produces different keys each time ---

    #[test]
    fn test_keygen_random_different() {
        let level = SecurityLevel::MlKem768;
        let (ek1, dk1) = ml_kem_keygen(level).expect("keygen should succeed");
        let (ek2, dk2) = ml_kem_keygen(level).expect("keygen should succeed");

        // Probability of collision is astronomically low (2^-256)
        assert_ne!(ek1, ek2, "random keygen should produce different ek");
        assert_ne!(dk1, dk2, "random keygen should produce different dk");
    }

    // --- dk_pke can be decoded back to polynomial vector ---

    #[test]
    fn test_keygen_dk_pke_decodable() {
        let d = [0x77u8; 32];
        let z = [0x88u8; 32];
        let level = SecurityLevel::MlKem768;
        let k = 3usize;

        let (_, dk) = ml_kem_keygen_deterministic(&d, &z, level);

        // dk_pke is the first k*384 bytes
        let dk_pke = &dk[..k * 384];

        // It should be decodable as a PolyVec
        let s_hat = PolyVec::from_bytes(dk_pke, k);
        assert_eq!(s_hat.len(), k);

        // All coefficients should be valid field elements (< Q)
        for i in 0..k {
            for j in 0..256 {
                assert!(
                    s_hat.poly(i).coeffs()[j].value() < 3329,
                    "coefficient out of range at poly {i}, coeff {j}"
                );
            }
        }
    }

    // --- All three levels produce valid keys ---

    #[test]
    fn test_keygen_all_levels() {
        for level in [
            SecurityLevel::MlKem512,
            SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024,
        ] {
            let result = ml_kem_keygen(level);
            assert!(result.is_ok(), "keygen should succeed for {:?}", level);
        }
    }

    // --- CPA keygen deterministic helper ---

    #[test]
    fn test_cpa_keygen_deterministic() {
        let d = [0x33u8; 32];

        let kp1 = k_pke_keygen_deterministic(&d, SecurityLevel::MlKem768);
        let kp2 = k_pke_keygen_deterministic(&d, SecurityLevel::MlKem768);

        assert_eq!(
            kp1.ek_pke, kp2.ek_pke,
            "deterministic CPA keygen: same ek_pke"
        );
        assert_eq!(
            kp1.dk_pke, kp2.dk_pke,
            "deterministic CPA keygen: same dk_pke"
        );
    }
}

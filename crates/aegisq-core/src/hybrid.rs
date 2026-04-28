//! Integracion hibrida KEM-DEM: ML-KEM + AES-256-GCM.
//!
//! Este modulo ensambla y parsea el Transit Package:
//! `[ ML-KEM Capsule (variable) | AES Nonce (12B) | AES Auth Tag (16B) | Ciphertext (variable) ]`
//!
//! El flujo de cifrado:
//! 1. ML-KEM.Encaps genera capsule + shared_secret (32 bytes)
//! 2. shared_secret se usa como clave AES-256-GCM
//! 3. OsRng genera un nonce aleatorio de 12 bytes
//! 4. AES-256-GCM cifra el plaintext con (key=shared_secret, nonce)
//! 5. Se ensambla el Transit Package
//!
//! El flujo de descifrado:
//! 1. Se parsea el Transit Package segun el nivel de seguridad
//! 2. ML-KEM.Decaps extrae shared_secret de la capsule
//! 3. AES-256-GCM descifra con (key=shared_secret, nonce, tag)
//! 4. Si el tag es invalido, se lanza DecryptionFailed

use alloc::vec::Vec;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use getrandom::fill;
use zeroize::Zeroize;

use crate::error::AegisQError;
use crate::kem::{self, SecurityLevel};

/// Wrapper around getrandom to provide fill_bytes method.
struct OsRng;

impl OsRng {
    fn fill_bytes(&self, dest: &mut [u8]) {
        // fill() returns Result and panics on error in no_std context
        // On supported platforms (Linux/macOS/Windows), this never fails
        let _ = fill(dest);
    }
}

/// Tamano del nonce AES-GCM en bytes (96 bits).
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// Tamano del auth tag AES-GCM en bytes (128 bits).
pub const AES_GCM_TAG_SIZE: usize = 16;

/// Calcula el overhead fijo del Transit Package (capsule + nonce + tag).
///
/// El tamano total del Transit Package es `transit_package_overhead(level) + plaintext_len`.
pub const fn transit_package_overhead(level: SecurityLevel) -> usize {
    level.capsule_size() + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE
}

/// Cifra un payload usando el esquema hibrido ML-KEM + AES-256-GCM.
///
/// # Flujo
/// 1. `ML-KEM.Encaps(recipient_pk)` → `(capsule, shared_secret)`
/// 2. `AES-256-GCM.Encrypt(key=shared_secret, nonce=OsRng(12), plaintext)` → `(ciphertext, tag)`
/// 3. Ensambla Transit Package: `[ capsule | nonce | tag | ciphertext ]`
///
/// # Arguments
/// - `recipient_public_key`: Clave publica ML-KEM del receptor
/// - `plaintext`: Datos a cifrar (puede ser vacio)
/// - `level`: Nivel de seguridad ML-KEM (debe coincidir con la clave)
///
/// # Returns
/// Transit Package como `Vec<u8>`.
///
/// # Errors
/// - `AegisQError::InvalidParameter` si `recipient_public_key` tiene tamano incorrecto
/// - `AegisQError::RngError` si el CSPRNG del OS no esta disponible
pub fn encrypt(
    recipient_public_key: &[u8],
    plaintext: &[u8],
    level: SecurityLevel,
) -> Result<Vec<u8>, AegisQError> {
    // 1. ML-KEM.Encaps: genera capsule + shared_secret (32 bytes)
    let encaps_result = kem::encapsulate(recipient_public_key, level)?;
    let capsule = encaps_result.capsule;
    let mut shared_secret = encaps_result.shared_secret;

    // 2. Generar nonce aleatorio de 12 bytes via OsRng
    let mut nonce_bytes = [0u8; AES_GCM_NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    // 3. AES-256-GCM encrypt
    //    aes-gcm retorna ciphertext || tag concatenados
    let aes_result = aes_gcm_encrypt(&shared_secret, &nonce_bytes, plaintext);

    // Zeroizar shared_secret inmediatamente despues de usarlo
    shared_secret.zeroize();

    let ct_with_tag = aes_result?;

    // aes-gcm 0.10 retorna: ciphertext (len=plaintext.len()) || tag (16 bytes)
    // Separar para ensamblar en el orden del Transit Package
    let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
    let ciphertext = &ct_with_tag[..ct_len];
    let tag = &ct_with_tag[ct_len..];

    // 4. Ensamblar Transit Package: [ capsule | nonce | tag | ciphertext ]
    let total_size = capsule.len() + AES_GCM_NONCE_SIZE + AES_GCM_TAG_SIZE + ciphertext.len();
    let mut package = Vec::with_capacity(total_size);
    package.extend_from_slice(&capsule);
    package.extend_from_slice(&nonce_bytes);
    package.extend_from_slice(tag);
    package.extend_from_slice(ciphertext);

    Ok(package)
}

/// Descifra un Transit Package usando la clave secreta propia.
///
/// # Flujo
/// 1. Parsea el Transit Package: `[ capsule | nonce | tag | ciphertext ]`
/// 2. `ML-KEM.Decaps(capsule, secret_key)` → `shared_secret`
/// 3. `AES-256-GCM.Decrypt(key=shared_secret, nonce, tag, ciphertext)` → `plaintext`
///
/// # Arguments
/// - `encrypted_package`: Transit Package completo
/// - `secret_key`: Clave secreta ML-KEM del receptor
/// - `level`: Nivel de seguridad ML-KEM (debe coincidir con la clave)
///
/// # Returns
/// Plaintext descifrado como `Vec<u8>`.
///
/// # Errors
/// - `AegisQError::InvalidParameter` si el package o secret_key tienen tamano incorrecto
/// - `AegisQError::DecryptionFailed` si el Auth Tag de AES-GCM es invalido
///   (indica payload manipulado o clave incorrecta)
///
/// # Security Note
/// Si el ciphertext ML-KEM fue manipulado, implicit rejection (FIPS 203 §7.3)
/// produce un shared_secret pseudoaleatorio. Esto causa un fallo natural del
/// Auth Tag de AES-GCM, que se reporta como `DecryptionFailed`.
pub fn decrypt(
    encrypted_package: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> Result<Vec<u8>, AegisQError> {
    let overhead = transit_package_overhead(level);

    // Validar tamano minimo del package (overhead + 0 bytes de ciphertext es valido)
    if encrypted_package.len() < overhead {
        return Err(AegisQError::InvalidParameter(
            "Encrypted package too small for the given security level",
        ));
    }

    // 1. Parsear Transit Package: [ capsule | nonce (12B) | tag (16B) | ciphertext ]
    let capsule_size = level.capsule_size();
    let capsule = &encrypted_package[..capsule_size];
    let nonce_start = capsule_size;
    let nonce_end = nonce_start + AES_GCM_NONCE_SIZE;
    let nonce_bytes = &encrypted_package[nonce_start..nonce_end];
    let tag_start = nonce_end;
    let tag_end = tag_start + AES_GCM_TAG_SIZE;
    let tag = &encrypted_package[tag_start..tag_end];
    let ciphertext = &encrypted_package[tag_end..];

    // 2. ML-KEM.Decaps: extraer shared_secret de la capsule
    //    Si el ciphertext KEM fue manipulado, implicit rejection produce un
    //    shared_secret pseudoaleatorio. Esto causara que AES-GCM falle el tag check.
    let mut shared_secret = kem::decapsulate(capsule, secret_key, level)?;

    // 3. AES-256-GCM decrypt
    //    Reconstruir el formato que aes-gcm espera: ciphertext || tag
    let aes_result = aes_gcm_decrypt(&shared_secret, nonce_bytes, ciphertext, tag);

    // Zeroizar shared_secret inmediatamente despues de usarlo
    shared_secret.zeroize();

    aes_result
}

/// Cifra con AES-256-GCM. Retorna ciphertext || tag.
///
/// Funcion interna para aislar la logica AES-GCM.
fn aes_gcm_encrypt(
    key: &[u8],
    nonce_bytes: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, AegisQError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AegisQError::InvalidParameter("AES-256-GCM key must be 32 bytes"))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| AegisQError::RngError) // encrypt only fails on alloc/nonce issues
}

/// Descifra con AES-256-GCM.
///
/// Reconstruye el formato `ciphertext || tag` que espera el crate aes-gcm,
/// y retorna el plaintext. Si el tag es invalido, retorna `DecryptionFailed`.
fn aes_gcm_decrypt(
    key: &[u8],
    nonce_bytes: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> Result<Vec<u8>, AegisQError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| AegisQError::InvalidParameter("AES-256-GCM key must be 32 bytes"))?;

    let nonce = Nonce::from_slice(nonce_bytes);

    // aes-gcm expects payload as: ciphertext || tag
    let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + tag.len());
    ct_with_tag.extend_from_slice(ciphertext);
    ct_with_tag.extend_from_slice(tag);

    cipher
        .decrypt(nonce, ct_with_tag.as_ref())
        .map_err(|_| AegisQError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    // ── AES-256-GCM unit tests ──────────────────────────────────────────────

    #[test]
    fn test_aes_gcm_encrypt_decrypt_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"Hello, post-quantum world!";

        let ct_with_tag = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        // ciphertext len == plaintext len, plus 16 byte tag
        assert_eq!(ct_with_tag.len(), plaintext.len() + AES_GCM_TAG_SIZE);

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag = &ct_with_tag[ct_len..];

        let recovered = aes_gcm_decrypt(&key, &nonce, ciphertext, tag).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0xABu8; 32];
        let nonce = [0xCDu8; AES_GCM_NONCE_SIZE];
        let plaintext = b"";

        let ct_with_tag = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        // Empty plaintext: only tag (16 bytes)
        assert_eq!(ct_with_tag.len(), AES_GCM_TAG_SIZE);

        let ciphertext = &ct_with_tag[..0];
        let tag = &ct_with_tag[..];

        let recovered = aes_gcm_decrypt(&key, &nonce, ciphertext, tag).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_aes_gcm_tampered_ciphertext_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"Sensitive data";

        let mut ct_with_tag = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        // Tamper with the first byte of ciphertext
        ct_with_tag[0] ^= 0xFF;

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag = &ct_with_tag[ct_len..];

        let result = aes_gcm_decrypt(&key, &nonce, ciphertext, tag);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_tampered_tag_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"Sensitive data";

        let mut ct_with_tag = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();
        // Tamper with the last byte of tag
        let last = ct_with_tag.len() - 1;
        ct_with_tag[last] ^= 0x01;

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag = &ct_with_tag[ct_len..];

        let result = aes_gcm_decrypt(&key, &nonce, ciphertext, tag);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_wrong_key_fails() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"Sensitive data";

        let ct_with_tag = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag = &ct_with_tag[ct_len..];

        let result = aes_gcm_decrypt(&wrong_key, &nonce, ciphertext, tag);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_wrong_nonce_fails() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];
        let wrong_nonce = [0x02u8; AES_GCM_NONCE_SIZE];
        let plaintext = b"Sensitive data";

        let ct_with_tag = aes_gcm_encrypt(&key, &nonce, plaintext).unwrap();

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag = &ct_with_tag[ct_len..];

        let result = aes_gcm_decrypt(&key, &wrong_nonce, ciphertext, tag);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_aes_gcm_invalid_key_size() {
        let short_key = [0x42u8; 16]; // AES-128, not AES-256
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];

        let result = aes_gcm_encrypt(&short_key, &nonce, b"data");
        assert!(matches!(result, Err(AegisQError::InvalidParameter(_))));
    }

    #[test]
    fn test_aes_gcm_large_payload() {
        let key = [0x42u8; 32];
        let nonce = [0x01u8; AES_GCM_NONCE_SIZE];
        // 1 MB payload
        let plaintext = vec![0xABu8; 1_000_000];

        let ct_with_tag = aes_gcm_encrypt(&key, &nonce, &plaintext).unwrap();
        assert_eq!(ct_with_tag.len(), plaintext.len() + AES_GCM_TAG_SIZE);

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag = &ct_with_tag[ct_len..];

        let recovered = aes_gcm_decrypt(&key, &nonce, ciphertext, tag).unwrap();
        assert_eq!(recovered, plaintext);
    }

    // ── Transit Package overhead tests ──────────────────────────────────────

    #[test]
    fn test_transit_package_overhead_512() {
        // capsule 768 + nonce 12 + tag 16 = 796
        assert_eq!(transit_package_overhead(SecurityLevel::MlKem512), 796);
    }

    #[test]
    fn test_transit_package_overhead_768() {
        // capsule 1088 + nonce 12 + tag 16 = 1116
        assert_eq!(transit_package_overhead(SecurityLevel::MlKem768), 1116);
    }

    #[test]
    fn test_transit_package_overhead_1024() {
        // capsule 1568 + nonce 12 + tag 16 = 1596
        assert_eq!(transit_package_overhead(SecurityLevel::MlKem1024), 1596);
    }

    // ── Hybrid encrypt/decrypt end-to-end tests ─────────────────────────────

    #[test]
    fn test_hybrid_roundtrip_768() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Post-quantum encryption works!";

        let package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();

        // Verify package size
        let expected_size = transit_package_overhead(SecurityLevel::MlKem768) + plaintext.len();
        assert_eq!(package.len(), expected_size);

        let recovered = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_hybrid_roundtrip_512() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem512).unwrap();
        let plaintext = b"ML-KEM-512 test";

        let package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem512).unwrap();
        let expected_size = transit_package_overhead(SecurityLevel::MlKem512) + plaintext.len();
        assert_eq!(package.len(), expected_size);

        let recovered = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem512).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_hybrid_roundtrip_1024() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem1024).unwrap();
        let plaintext = b"ML-KEM-1024 highest security";

        let package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem1024).unwrap();
        let expected_size = transit_package_overhead(SecurityLevel::MlKem1024) + plaintext.len();
        assert_eq!(package.len(), expected_size);

        let recovered = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem1024).unwrap();
        assert_eq!(recovered.as_slice(), plaintext);
    }

    #[test]
    fn test_hybrid_empty_plaintext() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"";

        let package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();
        let expected_size = transit_package_overhead(SecurityLevel::MlKem768);
        assert_eq!(package.len(), expected_size);

        let recovered = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_hybrid_large_payload() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = vec![0x42u8; 100_000]; // 100 KB

        let package = encrypt(&keypair.public_key, &plaintext, SecurityLevel::MlKem768).unwrap();
        let expected_size = transit_package_overhead(SecurityLevel::MlKem768) + plaintext.len();
        assert_eq!(package.len(), expected_size);

        let recovered = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_hybrid_tampered_capsule_fails() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Tamper test";

        let mut package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();
        // Tamper with first byte of capsule
        package[0] ^= 0xFF;

        // ML-KEM implicit rejection gives a wrong shared_secret,
        // so AES-GCM tag check fails → DecryptionFailed
        let result = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_hybrid_tampered_nonce_fails() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Nonce tamper test";

        let mut package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();
        // Tamper with first byte of nonce (right after capsule)
        let nonce_offset = SecurityLevel::MlKem768.capsule_size();
        package[nonce_offset] ^= 0xFF;

        let result = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_hybrid_tampered_tag_fails() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Tag tamper test";

        let mut package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();
        // Tamper with first byte of auth tag
        let tag_offset = SecurityLevel::MlKem768.capsule_size() + AES_GCM_NONCE_SIZE;
        package[tag_offset] ^= 0xFF;

        let result = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_hybrid_tampered_ciphertext_fails() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Ciphertext tamper test";

        let mut package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();
        // Tamper with last byte (in ciphertext region)
        let last = package.len() - 1;
        package[last] ^= 0xFF;

        let result = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem768);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_hybrid_wrong_secret_key_fails() {
        let keypair_alice = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let keypair_bob = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Wrong key test";

        // Encrypt for Alice
        let package = encrypt(
            &keypair_alice.public_key,
            plaintext,
            SecurityLevel::MlKem768,
        )
        .unwrap();

        // Try to decrypt with Bob's key → should fail
        let result = decrypt(&package, &keypair_bob.secret_key, SecurityLevel::MlKem768);
        assert!(matches!(result, Err(AegisQError::DecryptionFailed)));
    }

    #[test]
    fn test_hybrid_package_too_small() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();

        // Package smaller than overhead
        let small_package = vec![0u8; 100];
        let result = decrypt(&small_package, &keypair.secret_key, SecurityLevel::MlKem768);
        assert!(matches!(result, Err(AegisQError::InvalidParameter(_))));
    }

    #[test]
    fn test_hybrid_wrong_level_fails() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Level mismatch test";

        let package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();

        // Try to decrypt with wrong security level — parsing will be off,
        // leading to either InvalidParameter (wrong sk size) or DecryptionFailed
        let result = decrypt(&package, &keypair.secret_key, SecurityLevel::MlKem512);
        assert!(result.is_err());
    }

    #[test]
    fn test_hybrid_each_encrypt_produces_different_package() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Same plaintext, different packages";

        let package1 = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();
        let package2 = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();

        // Different capsules (random m in Encaps) and different nonces
        assert_ne!(package1, package2);

        // But both decrypt to the same plaintext
        let pt1 = decrypt(&package1, &keypair.secret_key, SecurityLevel::MlKem768).unwrap();
        let pt2 = decrypt(&package2, &keypair.secret_key, SecurityLevel::MlKem768).unwrap();
        assert_eq!(pt1.as_slice(), plaintext);
        assert_eq!(pt2.as_slice(), plaintext);
    }

    #[test]
    fn test_hybrid_transit_package_structure() {
        let keypair = kem::generate_keypair(SecurityLevel::MlKem768).unwrap();
        let plaintext = b"Structure verification";

        let package = encrypt(&keypair.public_key, plaintext, SecurityLevel::MlKem768).unwrap();

        // Verify structure: [ capsule(1088) | nonce(12) | tag(16) | ciphertext(22) ]
        let capsule_size = SecurityLevel::MlKem768.capsule_size();
        assert_eq!(package.len(), capsule_size + 12 + 16 + plaintext.len());

        // The capsule region should NOT be all zeros (it's a real KEM ciphertext)
        let capsule = &package[..capsule_size];
        assert!(capsule.iter().any(|&b| b != 0));

        // The nonce region should NOT be all zeros (random nonce)
        let nonce = &package[capsule_size..capsule_size + 12];
        // Probability of all-zero nonce from OsRng is 2^-96, effectively impossible
        assert!(nonce.iter().any(|&b| b != 0));
    }
}

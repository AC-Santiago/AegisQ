//! Cifrado/descifrado de llaves privadas ML-KEM con AES-256-GCM + HKDF-SHA3-256.
//!
//! El formato del blob binario (en orden, little-endian layout) es:
//!
//! - 4 bytes: magic `"AQPK"`
//! - 1 byte:  version = 1
//! - 1 byte:  level_id (0=512, 1=768, 2=1024)
//! - 16 bytes: salt HKDF
//! - 12 bytes: nonce AES-GCM
//! - N bytes:  ciphertext AES-GCM de secret_key
//! - 16 bytes: tag AES-GCM
//!
//! **JAMAS exporta la llave privada en texto plano.** La contrasena del usuario
//! es requerida para recuperar la llave.
//!
//! Reglas de seguridad:
//! - La clave derivada de HKDF vive en `Zeroizing<[u8; 32]>` y se borra al salir del scope.
//! - `salt` y `nonce` son generados externamente (Capa 2 con `getrandom`) y pasados
//!   como parametros. Asi la Capa 1 permanece pura y no_std-friendly.
//! - Contrasena incorrecta → `AegisQError::DecryptionFailed` (INDISTINGUIBLE de
//!   blob corrupto, para no dar informacion al atacante).

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use alloc::vec::Vec;
use zeroize::{Zeroize, Zeroizing};

use crate::error::AegisQError;
use crate::kdf::hkdf_sha3_256;
use crate::kem::SecurityLevel;

/// Magic bytes que identifican un blob AegisQ.
pub const MAGIC: &[u8; 4] = b"AQPK";

/// Version actual del formato de blob.
pub const VERSION: u8 = 1;

/// Header fijo del blob: magic(4) + version(1) + level_id(1) = 6 bytes.
pub const HEADER_SIZE: usize = 6;

/// Tamano del salt HKDF en bytes.
pub const SALT_SIZE: usize = 16;

/// Tamano del nonce AES-GCM en bytes (96 bits, mismo que hybrid.rs).
pub const NONCE_SIZE: usize = 12;

/// Tamano del tag AES-GCM en bytes (128 bits, mismo que hybrid.rs).
pub const TAG_SIZE: usize = 16;

/// Domain separation string para HKDF-Expand (NIST SP 800-108 style).
const HKDF_INFO: &[u8] = b"aegisq-key-wrap-v1";

/// Codifica un `SecurityLevel` a su byte identificador en el blob.
fn level_to_id(level: SecurityLevel) -> u8 {
    match level {
        SecurityLevel::MlKem512 => 0,
        SecurityLevel::MlKem768 => 1,
        SecurityLevel::MlKem1024 => 2,
    }
}

/// Decodifica un byte identificador a `SecurityLevel`. Retorna error si es desconocido.
fn id_to_level(id: u8) -> Result<SecurityLevel, AegisQError> {
    match id {
        0 => Ok(SecurityLevel::MlKem512),
        1 => Ok(SecurityLevel::MlKem768),
        2 => Ok(SecurityLevel::MlKem1024),
        _ => Err(AegisQError::KeySerializationError(
            "unknown level_id in wrapped blob",
        )),
    }
}

/// Cifra una llave secreta ML-KEM con una contrasena, retorna blob binario opaco.
///
/// # Arguments
/// - `secret_key`: bytes crudos de la llave secreta
/// - `password`: contrasena del usuario (cualquier longitud)
/// - `level`: nivel de seguridad (codificado en el blob)
/// - `rng_salt`: 16 bytes aleatorios (generados por el caller con `getrandom`)
/// - `rng_nonce`: 12 bytes aleatorios (generados por el caller con `getrandom`)
///
/// # Errors
/// - `AegisQError::InvalidParameter` si `secret_key.len()` no coincide con `level.secret_key_size()`.
pub fn wrap_secret_key(
    secret_key: &[u8],
    password: &[u8],
    level: SecurityLevel,
    rng_salt: [u8; SALT_SIZE],
    rng_nonce: [u8; NONCE_SIZE],
) -> Result<Vec<u8>, AegisQError> {
    // 1. Validar tamano de la llave secreta para el nivel dado
    if secret_key.len() != level.secret_key_size() {
        return Err(AegisQError::InvalidParameter(
            "secret key size does not match the specified security level",
        ));
    }

    // 2. Derivar la clave de cifrado via HKDF-SHA3-256 (32 bytes para AES-256)
    let mut wrap_key = Zeroizing::new(hkdf_sha3_256(password, &rng_salt, HKDF_INFO));

    // 3. AES-256-GCM encrypt
    let cipher = Aes256Gcm::new_from_slice(&*wrap_key)
        .map_err(|_| AegisQError::KeySerializationError("invalid derived key length"))?;
    // aes-gcm 0.11 deprecó `Nonce::from_slice` en favor de `TryFrom`.
    // `rng_nonce` ya fue generado con longitud fija `NONCE_SIZE` arriba.
    let nonce = Nonce::try_from(&rng_nonce[..])
        .map_err(|_| AegisQError::KeySerializationError("invalid nonce length"))?;
    let ct_with_tag = cipher
        .encrypt(&nonce, secret_key)
        .map_err(|_| AegisQError::KeySerializationError("AES-GCM encrypt failed"))?;

    // 4. Ensamblar blob en el orden canonico
    let mut blob = Vec::with_capacity(HEADER_SIZE + SALT_SIZE + NONCE_SIZE + ct_with_tag.len());
    blob.extend_from_slice(MAGIC);
    blob.push(VERSION);
    blob.push(level_to_id(level));
    blob.extend_from_slice(&rng_salt);
    blob.extend_from_slice(&rng_nonce);
    blob.extend_from_slice(&ct_with_tag);

    // 5. Zeroizar la clave derivada explicitamente (Zeroizing tambien lo haria en drop)
    wrap_key.zeroize();

    Ok(blob)
}

/// Descifra un blob y retorna la llave secreta en `Zeroizing<Vec<u8>>`.
///
/// # Arguments
/// - `blob`: bytes del blob producido por `wrap_secret_key`
/// - `password`: contrasena usada al cifrar
///
/// # Returns
/// Tupla `(secret_key_bytes, security_level)` con borrado automatico de memoria
/// al salir del scope.
///
/// # Errors
/// - `AegisQError::KeySerializationError` si magic/version son invalidos o el blob esta truncado.
/// - `AegisQError::DecryptionFailed` si la contrasena es incorrecta o el tag AES-GCM no verifica.
///   (El error es INDISTINGUIBLE entre "contrasena incorrecta" y "blob corrupto".)
pub fn unwrap_secret_key(
    blob: &[u8],
    password: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, SecurityLevel), AegisQError> {
    // 1. Validar longitud minima: header(6) + salt(16) + nonce(12) + tag(16) = 50 bytes
    if blob.len() < HEADER_SIZE + SALT_SIZE + NONCE_SIZE + TAG_SIZE {
        return Err(AegisQError::KeySerializationError(
            "wrapped blob is too short to contain a valid header",
        ));
    }

    // 2. Verificar magic bytes
    if &blob[..4] != MAGIC {
        return Err(AegisQError::KeySerializationError(
            "invalid magic bytes in wrapped blob",
        ));
    }

    // 3. Verificar version
    if blob[4] != VERSION {
        return Err(AegisQError::KeySerializationError(
            "unsupported wrapped blob version",
        ));
    }

    // 4. Decodificar nivel
    let level = id_to_level(blob[5])?;

    // 5. Extraer salt y nonce
    let salt: [u8; SALT_SIZE] = blob[HEADER_SIZE..HEADER_SIZE + SALT_SIZE]
        .try_into()
        .map_err(|_| AegisQError::KeySerializationError("failed to extract salt from blob"))?;
    let nonce_bytes: [u8; NONCE_SIZE] = blob
        [HEADER_SIZE + SALT_SIZE..HEADER_SIZE + SALT_SIZE + NONCE_SIZE]
        .try_into()
        .map_err(|_| AegisQError::KeySerializationError("failed to extract nonce from blob"))?;

    // 6. Extraer ciphertext || tag (resto del blob)
    let ct_with_tag = &blob[HEADER_SIZE + SALT_SIZE + NONCE_SIZE..];

    // 7. Derivar la clave de descifrado
    let mut wrap_key = Zeroizing::new(hkdf_sha3_256(password, &salt, HKDF_INFO));

    // 8. AES-256-GCM decrypt — CRITICO: tag failure -> DecryptionFailed (no KeySerializationError)
    let cipher = Aes256Gcm::new_from_slice(&*wrap_key)
        .map_err(|_| AegisQError::KeySerializationError("invalid derived key length"))?;
    // aes-gcm 0.11 deprecó `Nonce::from_slice` en favor de `TryFrom`.
    // `nonce_bytes` ya fue validado arriba (NONCE_SIZE bytes).
    let nonce = Nonce::try_from(&nonce_bytes[..])
        .map_err(|_| AegisQError::KeySerializationError("invalid nonce length"))?;
    let plaintext = cipher
        .decrypt(&nonce, ct_with_tag)
        .map_err(|_| AegisQError::DecryptionFailed)?;

    // 9. Validar que la longitud recuperada coincida con el tamano esperado para el nivel
    if plaintext.len() != level.secret_key_size() {
        // Tratar como fallo de autenticacion (no filtrar que el tamano fue incorrecto)
        return Err(AegisQError::DecryptionFailed);
    }

    wrap_key.zeroize();
    Ok((Zeroizing::new(plaintext), level))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Roundtrip basico: wrap -> unwrap con contrasena correcta -> recupera bytes originales.
    #[test]
    fn roundtrip_ml_kem_768() {
        let sk = alloc::vec![0x42u8; SecurityLevel::MlKem768.secret_key_size()];
        let salt = [1u8; SALT_SIZE];
        let nonce = [2u8; NONCE_SIZE];
        let blob = wrap_secret_key(
            &sk,
            b"correct-horse-battery-staple",
            SecurityLevel::MlKem768,
            salt,
            nonce,
        )
        .expect("wrap must succeed");
        let (recovered, level) = unwrap_secret_key(&blob, b"correct-horse-battery-staple")
            .expect("unwrap with correct password must succeed");
        assert_eq!(level, SecurityLevel::MlKem768);
        assert_eq!(&*recovered, &sk[..]);
    }

    #[test]
    fn roundtrip_all_levels() {
        for level in [
            SecurityLevel::MlKem512,
            SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024,
        ] {
            let sk = alloc::vec![0xABu8; level.secret_key_size()];
            let salt = [3u8; SALT_SIZE];
            let nonce = [4u8; NONCE_SIZE];
            let blob = wrap_secret_key(&sk, b"pwd", level, salt, nonce).expect("wrap must succeed");
            let (recovered, recovered_level) =
                unwrap_secret_key(&blob, b"pwd").expect("unwrap must succeed");
            assert_eq!(recovered_level, level);
            assert_eq!(&*recovered, &sk[..]);
        }
    }

    #[test]
    fn wrong_password_raises_decryption_failed() {
        let sk = alloc::vec![0x42u8; SecurityLevel::MlKem768.secret_key_size()];
        let salt = [5u8; SALT_SIZE];
        let nonce = [6u8; NONCE_SIZE];
        let blob = wrap_secret_key(&sk, b"correct", SecurityLevel::MlKem768, salt, nonce)
            .expect("wrap must succeed");
        let result = unwrap_secret_key(&blob, b"WRONG");
        assert!(
            matches!(result, Err(AegisQError::DecryptionFailed)),
            "contrasena incorrecta DEBE producir DecryptionFailed (no KeySerializationError) — requisito de seguridad"
        );
    }

    #[test]
    fn invalid_magic_raises_key_serialization_error() {
        let mut blob = alloc::vec![0u8; 100];
        blob[..4].copy_from_slice(b"XXXX");
        let result = unwrap_secret_key(&blob, b"pwd");
        assert!(matches!(result, Err(AegisQError::KeySerializationError(_))));
    }

    #[test]
    fn truncated_blob_raises_key_serialization_error() {
        let blob = alloc::vec![0u8; 10];
        let result = unwrap_secret_key(&blob, b"pwd");
        assert!(matches!(result, Err(AegisQError::KeySerializationError(_))));
    }

    #[test]
    fn wrong_version_raises_key_serialization_error() {
        let mut blob = alloc::vec![0u8; 100];
        blob[..4].copy_from_slice(MAGIC);
        blob[4] = 99;
        let result = unwrap_secret_key(&blob, b"pwd");
        assert!(matches!(result, Err(AegisQError::KeySerializationError(_))));
    }

    #[test]
    fn unknown_level_id_raises_key_serialization_error() {
        let mut blob = alloc::vec![0u8; 100];
        blob[..4].copy_from_slice(MAGIC);
        blob[4] = VERSION;
        blob[5] = 99;
        let result = unwrap_secret_key(&blob, b"pwd");
        assert!(matches!(result, Err(AegisQError::KeySerializationError(_))));
    }

    #[test]
    fn wrong_size_secret_key_raises_invalid_parameter() {
        let sk = alloc::vec![0u8; 100];
        let salt = [7u8; SALT_SIZE];
        let nonce = [8u8; NONCE_SIZE];
        let result = wrap_secret_key(&sk, b"pwd", SecurityLevel::MlKem768, salt, nonce);
        assert!(matches!(result, Err(AegisQError::InvalidParameter(_))));
    }

    #[test]
    fn blob_has_correct_layout() {
        let sk = alloc::vec![0u8; SecurityLevel::MlKem768.secret_key_size()];
        let salt = [0xABu8; SALT_SIZE];
        let nonce = [0xCDu8; NONCE_SIZE];
        let blob = wrap_secret_key(&sk, b"pwd", SecurityLevel::MlKem768, salt, nonce)
            .expect("wrap must succeed");

        // Verificar magic al inicio
        assert_eq!(&blob[..4], b"AQPK");
        // Verificar version
        assert_eq!(blob[4], 1);
        // Verificar level_id (1 = MlKem768)
        assert_eq!(blob[5], 1);
        // Verificar salt en los siguientes 16 bytes
        assert_eq!(&blob[6..22], &salt[..]);
        // Verificar nonce en los siguientes 12 bytes
        assert_eq!(&blob[22..34], &nonce[..]);
        // Tamano total esperado: header(6) + salt(16) + nonce(12) + sk(2400) + tag(16) = 2450
        assert_eq!(
            blob.len(),
            HEADER_SIZE + SALT_SIZE + NONCE_SIZE + sk.len() + TAG_SIZE
        );
    }
}

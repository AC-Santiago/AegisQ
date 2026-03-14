//! API publica KEM del crate.
//!
//! Define los traits y structs para operaciones de Key Encapsulation Mechanism.
//! Este modulo expone la interfaz publica que consume la capa PyO3,
//! sin exponer detalles internos de `mlkem/math/`.

use crate::error::AegisQError;
use crate::mlkem::decaps::ml_kem_decaps;
use crate::mlkem::encaps::ml_kem_encaps;
use crate::mlkem::keygen::ml_kem_keygen;

/// Nivel de seguridad ML-KEM segun FIPS 203.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SecurityLevel {
    /// ML-KEM-512 — Nivel NIST 1 (pk: 800B, sk: 1632B, ct: 768B)
    MlKem512,
    /// ML-KEM-768 — Nivel NIST 3 (pk: 1184B, sk: 2400B, ct: 1088B) — Default
    #[default]
    MlKem768,
    /// ML-KEM-1024 — Nivel NIST 5 (pk: 1568B, sk: 3168B, ct: 1568B)
    MlKem1024,
}

impl SecurityLevel {
    /// Tamano de la clave publica en bytes.
    pub const fn public_key_size(&self) -> usize {
        match self {
            SecurityLevel::MlKem512 => 800,
            SecurityLevel::MlKem768 => 1184,
            SecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Tamano de la clave secreta en bytes.
    pub const fn secret_key_size(&self) -> usize {
        match self {
            SecurityLevel::MlKem512 => 1632,
            SecurityLevel::MlKem768 => 2400,
            SecurityLevel::MlKem1024 => 3168,
        }
    }

    /// Tamano de la capsula (ciphertext KEM) en bytes.
    pub const fn capsule_size(&self) -> usize {
        match self {
            SecurityLevel::MlKem512 => 768,
            SecurityLevel::MlKem768 => 1088,
            SecurityLevel::MlKem1024 => 1568,
        }
    }

    /// Tamano del shared secret en bytes (32 para todos los niveles).
    pub const fn shared_secret_size(&self) -> usize {
        32
    }
}

/// Par de claves ML-KEM.
pub struct KeyPair {
    /// Clave publica (encryption key).
    pub public_key: alloc::vec::Vec<u8>,
    /// Clave secreta (decapsulation key).
    pub secret_key: alloc::vec::Vec<u8>,
    /// Nivel de seguridad con el que se genero.
    pub level: SecurityLevel,
}

/// Resultado de una encapsulacion ML-KEM.
pub struct EncapsulationResult {
    /// Capsula (ciphertext KEM) para enviar al receptor.
    pub capsule: alloc::vec::Vec<u8>,
    /// Shared secret de 32 bytes.
    pub shared_secret: alloc::vec::Vec<u8>,
}

// --- Funciones publicas ---

/// Genera un par de claves ML-KEM para el nivel de seguridad dado.
///
/// Corresponde a FIPS 203 Alg. 15 (ML-KEM.KeyGen).
///
/// # Errors
/// Returns `AegisQError::RngError` if the OS CSPRNG is unavailable.
pub fn generate_keypair(level: SecurityLevel) -> Result<KeyPair, AegisQError> {
    let (public_key, secret_key) = ml_kem_keygen(level)?;
    Ok(KeyPair {
        public_key,
        secret_key,
        level,
    })
}

/// Encapsula un shared secret usando la clave publica del receptor.
///
/// Corresponde a FIPS 203 Alg. 16 (ML-KEM.Encaps).
///
/// # Arguments
/// - `public_key`: The recipient's public key (encryption key)
/// - `level`: The security level (must match the key's level)
///
/// # Returns
/// An `EncapsulationResult` containing the capsule and the 32-byte shared secret.
///
/// # Errors
/// - `AegisQError::InvalidParameter` if `public_key` has the wrong size
/// - `AegisQError::RngError` if the OS CSPRNG is unavailable
pub fn encapsulate(
    public_key: &[u8],
    level: SecurityLevel,
) -> Result<EncapsulationResult, AegisQError> {
    let (shared_secret, capsule) = ml_kem_encaps(public_key, level)?;
    Ok(EncapsulationResult {
        capsule,
        shared_secret,
    })
}

/// Desencapsula el shared secret usando la clave secreta propia.
///
/// Corresponde a FIPS 203 Alg. 17 (ML-KEM.Decaps).
///
/// **CRITICAL:** This function NEVER returns an error for invalid ciphertext
/// (implicit rejection, FIPS 203 §7.3). Instead, it silently returns a
/// pseudorandom shared secret derived from `z || H(c)`.
///
/// # Arguments
/// - `capsule`: The capsule (ciphertext) received from the sender
/// - `secret_key`: The recipient's secret key (decapsulation key)
/// - `level`: The security level (must match the key's level)
///
/// # Returns
/// A 32-byte shared secret.
///
/// # Errors
/// - `AegisQError::InvalidParameter` if `capsule` or `secret_key` have wrong sizes
///   (structural errors only — NOT for invalid ciphertext content)
pub fn decapsulate(
    capsule: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> Result<alloc::vec::Vec<u8>, AegisQError> {
    ml_kem_decaps(capsule, secret_key, level)
}

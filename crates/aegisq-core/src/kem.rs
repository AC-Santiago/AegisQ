//! API publica KEM del crate.
//!
//! Define los traits y structs para operaciones de Key Encapsulation Mechanism.
//! Este modulo expone la interfaz publica que consume la capa PyO3,
//! sin exponer detalles internos de `mlkem/math/`.

use crate::error::AegisQError;
use crate::mlkem::decaps::ml_kem_decaps;
use crate::mlkem::encaps::{ml_kem_encaps, ml_kem_encaps_deterministic};
use crate::mlkem::keygen::{ml_kem_keygen, ml_kem_keygen_deterministic};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

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

/// Resultado de una encapsulacion determinista (para KAT vector validation).
pub struct DeterministicEncapsulationResult {
    /// Capsula (ciphertext KEM) para enviar al receptor.
    pub capsule: alloc::vec::Vec<u8>,
    /// Shared secret de 32 bytes.
    pub shared_secret: alloc::vec::Vec<u8>,
    /// Mensaje `m` usado (32 bytes) — útil para debugging.
    pub m: [u8; 32],
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

// --- Funciones deterministas para KAT vector validation ---

/// Genera un par de claves ML-KEM usando seeds especificos.
///
/// Esta version es DETERMINISTA y debe usarse SOLO para validacion
/// con vectores KAT conocidos. NO usar en produccion.
///
/// Corresponde a FIPS 203 Alg. 15 (ML-KEM.KeyGen).
///
/// # Arguments
/// - `d`: Seed de 32 bytes para generacion de claves K-PKE
/// - `z`: Seed de 32 bytes para el contenido de la clave secreta
/// - `level`: Nivel de seguridad ML-KEM
///
/// # Returns
/// Un `KeyPair` con las claves generadas.
pub fn generate_keypair_deterministic(d: &[u8; 32], z: &[u8; 32], level: SecurityLevel) -> KeyPair {
    let (public_key, secret_key) = ml_kem_keygen_deterministic(d, z, level);
    KeyPair {
        public_key,
        secret_key,
        level,
    }
}

/// Encapsula un shared secret usando un mensaje especifico.
///
/// Esta version es DETERMINISTA y debe usarse SOLO para validacion
/// con vectores KAT conocidos. NO usar en produccion.
///
/// Corresponde a FIPS 203 Alg. 16 (ML-KEM.Encaps).
///
/// # Arguments
/// - `public_key`: Clave publica del receptor
/// - `m`: Mensaje de 32 bytes a encapsular
/// - `level`: Nivel de seguridad ML
///
/// # Returns
/// Un `DeterministicEncapsulationResult` con la capsula, shared secret y el mensaje usado.
///
/// # Errors
/// - `AegisQError::InvalidParameter` si el tamano de la clave publica es incorrecto
pub fn encapsulate_deterministic(
    public_key: &[u8],
    m: &[u8; 32],
    level: SecurityLevel,
) -> Result<DeterministicEncapsulationResult, AegisQError> {
    // Validate ek size
    let params = crate::mlkem::params::params_for_level(level);
    let expected_ek_len = params.k * 384 + 32;
    if public_key.len() != expected_ek_len {
        return Err(AegisQError::InvalidParameter(
            "encryption key publica tiene tamano incorrecto",
        ));
    }

    let (shared_secret, capsule) = ml_kem_encaps_deterministic(public_key, m, level);
    Ok(DeterministicEncapsulationResult {
        capsule,
        shared_secret,
        m: *m,
    })
}

// ── Serializacion de llaves publicas ─────────────────────────────────────

/// Serializa una llave publica ML-KEM a Base64 URL-safe sin padding.
///
/// Produce un string seguro para usar en URLs, headers HTTP, bases de datos
/// y cualquier contexto que requiera texto ASCII. El formato es Base64 URL-safe
/// sin padding (`=`) segun RFC 4648 §5.
///
/// # Arguments
/// - `public_key`: La llave publica como slice de bytes.
///
/// # Returns
/// Un `String` con la representacion Base64 URL-safe sin padding de la llave.
///
/// # Note
/// Solo la llave PUBLICA debe serializarse con esta funcion.
/// La llave secreta NO debe exportarse sin cifrado de contrasena adicional.
pub fn public_key_to_b64(public_key: &[u8]) -> alloc::string::String {
    URL_SAFE_NO_PAD.encode(public_key)
}

/// Deserializa una llave publica ML-KEM desde Base64 URL-safe sin padding.
///
/// Acepta tanto Base64 con padding (`=`) como sin padding para maxima
/// interoperabilidad, aunque el formato canonico de AegisQ es sin padding.
///
/// # Arguments
/// - `b64`: El string Base64 URL-safe a decodificar.
/// - `level`: El nivel de seguridad esperado. Se usa para validar que el tamano
///   de los bytes decodificados corresponde a una llave publica valida.
///
/// # Errors
/// - `AegisQError::Base64DecodeError` si el string no es Base64 valido.
/// - `AegisQError::InvalidParameter` si el tamano de los bytes decodificados
///   no corresponde al tamano de llave publica del nivel indicado.
pub fn public_key_from_b64(
    b64: &str,
    level: SecurityLevel,
) -> Result<alloc::vec::Vec<u8>, AegisQError> {
    // Trim surrounding whitespace (e.g., trailing `\n` from env vars or files)
    // before decoding. Only `=` padding was being stripped before, which caused
    // spurious decode failures on otherwise-valid Base64.
    let b64 = b64.trim();
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.trim_end_matches('='))
        .map_err(|_| AegisQError::Base64DecodeError("invalid base64 URL-safe string"))?;

    let expected = level.public_key_size();
    if bytes.len() != expected {
        return Err(AegisQError::InvalidParameter(
            "decoded public key has incorrect size for the specified security level",
        ));
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    /// `public_key_from_b64` must accept strings with surrounding whitespace
    /// (e.g. trailing `\n` from env vars or files) and still decode them to
    /// the original public key bytes.
    #[test]
    fn public_key_from_b64_trims_whitespace() {
        // Generate a real ML-KEM-768 keypair to get a valid 1184-byte public key
        let keypair = generate_keypair(SecurityLevel::MlKem768).unwrap();
        let pk_b64 = public_key_to_b64(&keypair.public_key);

        // Wrap the canonical Base64 with the kinds of whitespace that appear
        // when reading from env vars or trailing-newline-terminated files.
        let with_whitespace = format!("\n  {}\t\n", pk_b64);

        // The decode must succeed and yield exactly the original bytes.
        let decoded = public_key_from_b64(&with_whitespace, SecurityLevel::MlKem768)
            .expect("decode should succeed with surrounding whitespace");
        assert_eq!(decoded, keypair.public_key);
    }
}

// ── Validacion de tamano de llaves (v1.3.0) ─────────────────────────────

/// Valida que los bytes corresponden al tamano esperado de una llave publica para el nivel dado.
///
/// # Errors
/// - `AegisQError::InvalidParameter` si el tamano no coincide.
pub fn validate_public_key_size(pk: &[u8], level: SecurityLevel) -> Result<(), AegisQError> {
    let expected = level.public_key_size();
    if pk.len() != expected {
        return Err(AegisQError::InvalidParameter(
            "public key size does not match the specified security level",
        ));
    }
    Ok(())
}

/// Valida que los bytes corresponden al tamano esperado de una llave secreta para el nivel dado.
///
/// # Errors
/// - `AegisQError::InvalidParameter` si el tamano no coincide.
pub fn validate_secret_key_size(sk: &[u8], level: SecurityLevel) -> Result<(), AegisQError> {
    let expected = level.secret_key_size();
    if sk.len() != expected {
        return Err(AegisQError::InvalidParameter(
            "secret key size does not match the specified security level",
        ));
    }
    Ok(())
}

/// Fingerprint publico de una clave ML-KEM: primeros 8 bytes de
/// `SHA3-256(public_key)`, hex-encodeados en minusculas.
///
/// Usado por `__repr__` de `KeyPair` para identificar inequivocamente
/// la clave publica sin filtrar material criptografico. La eleccion de
/// SHA3-256 (funcion `H` de FIPS 203 §4.1) y un truncamiento a 8 bytes
/// (64 bits) es deliberada:
///
/// - SHA3-256 ya esta en el workspace (crate `sha3`), sin nuevas deps.
/// - 8 bytes dan 2^64 valores distintos — suficiente para que dos
///   `KeyPair` diferentes colisionen con probabilidad < 2^-32, que es
///   el orden de magnitud tipico de los fingerprints de certificados.
/// - 8 bytes NO permiten invertir el hash ni recuperar la clave
///   publica (que es publica de todos modos, asi que esto no es una
///   preocupacion de secreto, solo de tamano del repr).
///
/// Devuelve una `String` hex de 16 caracteres ASCII. Es seguro
/// formatearla en logs, repr, excepciones y mensajes de error.
///
/// Args:
///     public_key: Bytes de la clave publica (longitud dependiente del
///         nivel ML-KEM, validada o no por el caller).
///
/// Returns:
///     String hex de 16 caracteres en lowercase.
pub fn public_key_fingerprint(public_key: &[u8]) -> alloc::string::String {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    Digest::update(&mut hasher, public_key);
    let digest = hasher.finalize();
    let mut hex = alloc::string::String::with_capacity(16);
    for byte in &digest[..8] {
        let _ = alloc::fmt::Write::write_fmt(&mut hex, format_args!("{:02x}", byte));
    }
    hex
}

#[cfg(test)]
mod validation_tests {
    use super::*;

    #[test]
    fn validate_public_key_size_accepts_correct_sizes() {
        for level in [
            SecurityLevel::MlKem512,
            SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024,
        ] {
            let pk = alloc::vec![0u8; level.public_key_size()];
            assert!(
                validate_public_key_size(&pk, level).is_ok(),
                "valid size for {level:?} must be accepted"
            );
        }
    }

    #[test]
    fn validate_public_key_size_rejects_wrong_sizes() {
        let pk = alloc::vec![0u8; 100];
        assert!(matches!(
            validate_public_key_size(&pk, SecurityLevel::MlKem768),
            Err(AegisQError::InvalidParameter(_))
        ));
    }

    #[test]
    fn validate_public_key_size_rejects_empty() {
        let pk: &[u8] = &[];
        assert!(matches!(
            validate_public_key_size(pk, SecurityLevel::MlKem768),
            Err(AegisQError::InvalidParameter(_))
        ));
    }

    #[test]
    fn validate_secret_key_size_accepts_correct_sizes() {
        for level in [
            SecurityLevel::MlKem512,
            SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024,
        ] {
            let sk = alloc::vec![0u8; level.secret_key_size()];
            assert!(
                validate_secret_key_size(&sk, level).is_ok(),
                "valid size for {level:?} must be accepted"
            );
        }
    }

    #[test]
    fn validate_secret_key_size_rejects_wrong_sizes() {
        let sk = alloc::vec![0u8; 100];
        assert!(matches!(
            validate_secret_key_size(&sk, SecurityLevel::MlKem768),
            Err(AegisQError::InvalidParameter(_))
        ));
    }
}

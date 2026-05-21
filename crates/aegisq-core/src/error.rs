//! Tipos de error para aegisq-core.
//!
//! Define la jerarquia de errores del motor criptografico.
//! Estos errores se mapean a excepciones Python en la capa PyO3.

/// Errores que pueden ocurrir en operaciones criptograficas de AegisQ.
#[derive(Debug)]
pub enum AegisQError {
    /// Parametros invalidos (tamano de buffer incorrecto, nivel invalido).
    InvalidParameter(&'static str),

    /// Error en la generacion de numeros aleatorios (CSPRNG no disponible).
    RngError,

    /// Error en la desencapsulacion ML-KEM (error estructural, no de validacion).
    /// NOTA: Un ciphertext invalido NO genera este error (implicit rejection, FIPS 203 §7.3).
    DecapsulationError(&'static str),

    /// Fallo en la verificacion del Auth Tag de AES-GCM.
    /// Indica que el ciphertext fue manipulado o que la clave es incorrecta.
    DecryptionFailed,

    /// Error al decodificar una llave publica desde Base64.
    ///
    /// Se produce cuando el string provisto no es Base64 URL-safe valido.
    Base64DecodeError(&'static str),
}

impl core::fmt::Display for AegisQError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AegisQError::InvalidParameter(msg) => write!(f, "Invalid parameter: {}", msg),
            AegisQError::RngError => write!(f, "CSPRNG not available"),
            AegisQError::DecapsulationError(msg) => write!(f, "Decapsulation error: {}", msg),
            AegisQError::DecryptionFailed => {
                write!(f, "AES-GCM authentication tag verification failed")
            }
            AegisQError::Base64DecodeError(msg) => write!(f, "base64 decode error: {}", msg),
        }
    }
}

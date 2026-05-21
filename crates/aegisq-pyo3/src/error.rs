//! Mapeo de errores Rust (AegisQError) a excepciones Python (PyException).
//!
//! Define excepciones customizadas como subclases de Exception para
//! que el usuario Python pueda hacer catch especifico.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

// Jerarquia de excepciones:
// AegisQError(Exception)
// ├── DecapsulationError(AegisQError)
// ├── DecryptionError(AegisQError)
// ├── InvalidParameterError(AegisQError, ValueError)
// └── RngError(AegisQError)

create_exception!(
    aegisq,
    AegisQError,
    PyException,
    "Base exception for all AegisQ errors."
);
create_exception!(
    aegisq,
    DecapsulationError,
    AegisQError,
    "ML-KEM structural decapsulation error."
);
create_exception!(
    aegisq,
    DecryptionError,
    AegisQError,
    "AES-GCM authentication tag verification failed."
);
create_exception!(
    aegisq,
    InvalidParameterError,
    AegisQError,
    "Invalid parameter (buffer size, security level)."
);
create_exception!(
    aegisq,
    RngError,
    AegisQError,
    "CSPRNG not available from the operating system."
);

/// Registra las excepciones customizadas en el modulo Python.
pub fn register_exceptions(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("AegisQError", m.py().get_type::<AegisQError>())?;
    m.add(
        "DecapsulationError",
        m.py().get_type::<DecapsulationError>(),
    )?;
    m.add("DecryptionError", m.py().get_type::<DecryptionError>())?;
    m.add(
        "InvalidParameterError",
        m.py().get_type::<InvalidParameterError>(),
    )?;
    m.add("RngError", m.py().get_type::<RngError>())?;
    Ok(())
}

/// Convierte un AegisQError del core a la excepcion Python correspondiente.
///
/// Se usa como funcion en lugar de `impl From` para respetar las orphan rules de Rust
/// (ni `AegisQError` de aegisq-core ni `PyErr` de pyo3 son tipos locales de este crate).
pub fn core_error_to_pyerr(err: aegisq_core::error::AegisQError) -> PyErr {
    match err {
        aegisq_core::error::AegisQError::InvalidParameter(msg) => {
            InvalidParameterError::new_err(msg.to_string())
        }
        aegisq_core::error::AegisQError::RngError => RngError::new_err("CSPRNG not available"),
        aegisq_core::error::AegisQError::DecapsulationError(msg) => {
            DecapsulationError::new_err(msg.to_string())
        }
        aegisq_core::error::AegisQError::DecryptionFailed => {
            DecryptionError::new_err("AES-GCM authentication tag verification failed")
        }
        aegisq_core::error::AegisQError::Base64DecodeError(msg) => {
            AegisQError::new_err(format!("base64 decode error: {}", msg))
        }
    }
}

//! Bindings PyO3 para operaciones KEM crudas.
//!
//! Expone funciones de generacion de claves, encapsulacion y desencapsulacion
//! para usuarios avanzados que necesitan acceso directo a ML-KEM.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::core_error_to_pyerr;
use crate::types::{KeyPair, SecurityLevel};

/// Genera un par de claves ML-KEM para el nivel de seguridad dado.
///
/// Args:
///     level: Nivel de seguridad (SecurityLevel.ML_KEM_512, ML_KEM_768, o ML_KEM_1024).
///
/// Returns:
///     KeyPair con public_key y secret_key.
///
/// Raises:
///     InvalidParameterError: Si el nivel es invalido.
///     RngError: Si el CSPRNG del OS no esta disponible.
#[pyfunction]
#[pyo3(signature = (level=SecurityLevel::MlKem768))]
pub fn generate_keypair(py: Python<'_>, level: SecurityLevel) -> PyResult<KeyPair> {
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result = py.detach(|| aegisq_core::kem::generate_keypair(core_level));

    match result {
        Ok(kp) => Ok(KeyPair::new(kp.public_key, kp.secret_key, level)),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

/// Encapsula un shared secret usando la clave publica del receptor.
///
/// Args:
///     public_key: Clave publica ML-KEM del receptor (bytes).
///     level: Nivel de seguridad.
///
/// Returns:
///     Tupla (capsule: bytes, shared_secret: bytes).
#[pyfunction]
#[pyo3(signature = (public_key, level=SecurityLevel::MlKem768))]
pub fn encapsulate<'py>(
    py: Python<'py>,
    public_key: &[u8],
    level: SecurityLevel,
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result = py.detach(|| aegisq_core::kem::encapsulate(public_key, core_level));

    match result {
        Ok(enc_result) => {
            let capsule = PyBytes::new(py, &enc_result.capsule);
            let shared_secret = PyBytes::new(py, &enc_result.shared_secret);
            Ok((capsule, shared_secret))
        }
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

/// Desencapsula el shared secret usando la clave secreta.
///
/// NOTA: Esta funcion NUNCA lanza error para ciphertext invalido
/// (implicit rejection, FIPS 203 §7.3).
///
/// Args:
///     capsule: Capsula ML-KEM recibida (bytes).
///     secret_key: Clave secreta propia (bytes).
///     level: Nivel de seguridad.
///
/// Returns:
///     shared_secret: bytes de 32 bytes.
#[pyfunction]
#[pyo3(signature = (capsule, secret_key, level=SecurityLevel::MlKem768))]
pub fn decapsulate<'py>(
    py: Python<'py>,
    capsule: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> PyResult<Bound<'py, PyBytes>> {
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result = py.detach(|| aegisq_core::kem::decapsulate(capsule, secret_key, core_level));

    match result {
        Ok(shared_secret) => Ok(PyBytes::new(py, &shared_secret)),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

//! Bindings PyO3 para operaciones hibridas ML-KEM + AES-256-GCM.
//!
//! Expone encrypt_hybrid y decrypt_hybrid que realizan el flujo completo
//! KEM-DEM: encapsulacion de clave + cifrado autenticado del payload.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::core_error_to_pyerr;
use crate::types::SecurityLevel;

/// Cifra un payload usando el esquema hibrido ML-KEM + AES-256-GCM.
///
/// Args:
///     recipient_public_key: Clave publica ML-KEM del receptor (bytes).
///     plaintext: Datos a cifrar (bytes).
///     level: Nivel de seguridad.
///
/// Returns:
///     Transit Package como bytes:
///     [ML-KEM Capsule | AES Nonce (12B) | Auth Tag (16B) | Ciphertext]
///
/// Raises:
///     InvalidParameterError: Si la clave publica tiene tamano incorrecto.
///     RngError: Si el CSPRNG del OS no esta disponible.
#[pyfunction]
#[pyo3(signature = (recipient_public_key, plaintext, level=SecurityLevel::MlKem768))]
pub fn encrypt_hybrid<'py>(
    py: Python<'py>,
    recipient_public_key: &[u8],
    plaintext: &[u8],
    level: SecurityLevel,
) -> PyResult<Bound<'py, PyBytes>> {
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result =
        py.detach(|| aegisq_core::hybrid::encrypt(recipient_public_key, plaintext, core_level));

    match result {
        Ok(package) => Ok(PyBytes::new(py, &package)),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

/// Descifra un Transit Package usando la clave secreta propia.
///
/// Args:
///     encrypted_package: Transit Package completo (bytes).
///     secret_key: Clave secreta ML-KEM propia (bytes).
///     level: Nivel de seguridad.
///
/// Returns:
///     Plaintext original como bytes.
///
/// Raises:
///     DecryptionError: Si el Auth Tag de AES-GCM es invalido (payload manipulado).
///     InvalidParameterError: Si el paquete tiene tamano incorrecto.
#[pyfunction]
#[pyo3(signature = (encrypted_package, secret_key, level=SecurityLevel::MlKem768))]
pub fn decrypt_hybrid<'py>(
    py: Python<'py>,
    encrypted_package: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> PyResult<Bound<'py, PyBytes>> {
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result =
        py.detach(|| aegisq_core::hybrid::decrypt(encrypted_package, secret_key, core_level));

    match result {
        Ok(plaintext) => Ok(PyBytes::new(py, &plaintext)),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

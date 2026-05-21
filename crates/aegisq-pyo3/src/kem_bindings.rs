//! Bindings PyO3 para operaciones KEM crudas.
//!
//! Expone funciones de generacion de claves, encapsulacion y desencapsulacion
//! para usuarios avanzados que necesitan acceso directo a ML-KEM.

use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::core_error_to_pyerr;
use crate::types::{KeyPair, SecurityLevel};
use aegisq_core::kem::{public_key_from_b64, public_key_to_b64};

/// Resultado de encapsulacion determinista.
#[allow(dead_code)]
#[derive(Clone)]
pub struct DeterministicEncapsulationResult {
    /// Capsula (ciphertext).
    pub capsule: Vec<u8>,
    /// Shared secret (32 bytes).
    pub shared_secret: Vec<u8>,
    /// Mensaje `m` usado (32 bytes).
    pub m: [u8; 32],
}

impl From<aegisq_core::kem::DeterministicEncapsulationResult> for DeterministicEncapsulationResult {
    fn from(core_result: aegisq_core::kem::DeterministicEncapsulationResult) -> Self {
        DeterministicEncapsulationResult {
            capsule: core_result.capsule,
            shared_secret: core_result.shared_secret,
            m: core_result.m,
        }
    }
}

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

// --- Funciones deterministas para KAT vector validation ---

/// Genera un par de claves ML-KEM usando seeds especificos.
///
/// Esta version es DETERMINISTA y debe usarse SOLO para validacion
/// con vectores KAT conocidos. NO usar en produccion.
///
/// Args:
///     d: Seed de 32 bytes para generacion de claves K-PKE.
///     z: Seed de 32 bytes para el contenido de la clave secreta.
///     level: Nivel de seguridad.
///
/// Returns:
///     KeyPair con public_key y secret_key.
///
/// Raises:
///     InvalidParameterError: Si los seeds no tienen 32 bytes o el nivel es invalido.
#[pyfunction]
#[pyo3(signature = (d, z, level=SecurityLevel::MlKem768))]
pub fn generate_keypair_deterministic(
    py: Python<'_>,
    d: &[u8],
    z: &[u8],
    level: SecurityLevel,
) -> PyResult<KeyPair> {
    // Validate seed sizes
    if d.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "El seed 'd' debe tener exactamente 32 bytes",
        ));
    }
    if z.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "El seed 'z' debe tener exactamente 32 bytes",
        ));
    }

    let d_array: [u8; 32] = d.try_into().unwrap();
    let z_array: [u8; 32] = z.try_into().unwrap();
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result = py.detach(|| {
        aegisq_core::kem::generate_keypair_deterministic(&d_array, &z_array, core_level)
    });

    Ok(KeyPair::new(result.public_key, result.secret_key, level))
}

/// Encapsula un shared secret usando un mensaje especifico.
///
/// Esta version es DETERMINISTA y debe usarse SOLO para validacion
/// con vectores KAT conocidos. NO usar en produccion.
///
/// Args:
///     public_key: Clave publica del receptor (bytes).
///     m: Mensaje de 32 bytes a encapsular.
///     level: Nivel de seguridad.
///
/// Returns:
///     Tupla (capsule: bytes, shared_secret: bytes, m: bytes).
///
/// Raises:
///     InvalidParameterError: Si los parametros tienen tamano incorrecto.
#[pyfunction]
#[pyo3(signature = (public_key, m, level=SecurityLevel::MlKem768))]
pub fn encapsulate_deterministic<'py>(
    py: Python<'py>,
    public_key: &[u8],
    m: &[u8],
    level: SecurityLevel,
) -> PyResult<(
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
    Bound<'py, PyBytes>,
)> {
    // Validate m size
    if m.len() != 32 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "El mensaje 'm' debe tener exactamente 32 bytes",
        ));
    }

    let m_array: [u8; 32] = m.try_into().unwrap();
    let core_level: aegisq_core::kem::SecurityLevel = level.into();

    let result =
        py.detach(|| aegisq_core::kem::encapsulate_deterministic(public_key, &m_array, core_level));

    match result {
        Ok(enc_result) => {
            let capsule = PyBytes::new(py, &enc_result.capsule);
            let shared_secret = PyBytes::new(py, &enc_result.shared_secret);
            let m_bytes = PyBytes::new(py, &enc_result.m);
            Ok((capsule, shared_secret, m_bytes))
        }
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

// ── Serializacion Base64 de llaves publicas ────────────────────────────────

/// Serializa una llave publica ML-KEM a Base64 URL-safe sin padding.
///
/// Args:
///     public_key: La llave publica como bytes.
///
/// Returns:
///     str: La llave publica en formato Base64 URL-safe sin padding.
#[pyfunction]
pub fn serialize_public_key(public_key: &[u8]) -> PyResult<String> {
    Ok(public_key_to_b64(public_key))
}

/// Deserializa una llave publica ML-KEM desde Base64 URL-safe.
///
/// Args:
///     b64 (str): El string Base64 URL-safe con la llave publica.
///     level (SecurityLevel): El nivel de seguridad ML-KEM esperado.
///
/// Returns:
///     bytes: Los bytes de la llave publica.
///
/// Raises:
///     AegisQError: Si el string no es Base64 valido.
///     InvalidParameterError: Si el tamano no coincide con el nivel.
#[pyfunction]
#[pyo3(signature = (b64, level=SecurityLevel::MlKem768))]
pub fn deserialize_public_key<'py>(
    py: Python<'py>,
    b64: &str,
    level: SecurityLevel,
) -> PyResult<Bound<'py, PyBytes>> {
    let core_level: aegisq_core::kem::SecurityLevel = level.into();
    match public_key_from_b64(b64, core_level) {
        Ok(bytes) => Ok(PyBytes::new(py, &bytes)),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

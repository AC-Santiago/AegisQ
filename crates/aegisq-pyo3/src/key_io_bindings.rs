//! Funciones PyO3 para serializacion y carga de llaves ML-KEM (v1.3.0).
//!
//! Exporta:
//! - load_public_key_pem, load_public_key_json
//! - load_secret_key_raw, load_secret_key_pem
//!
//! Estas funciones operan sobre bytes/strings y NO dependen de la clase KeyPair.
//! La Capa 3 (Python) las envuelve con la API de alto nivel (save_/load_).

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::error::core_error_to_pyerr;
use crate::types::SecurityLevel;
use aegisq_core::kem::{self, SecurityLevel as CoreSecurityLevel};
use aegisq_core::key_wrap;

// ── Constantes de formato PEM ────────────────────────────────────────────

const PEM_PUBLIC_HEADER: &str = "-----BEGIN ML-KEM PUBLIC KEY-----";
const PEM_PUBLIC_FOOTER: &str = "-----END ML-KEM PUBLIC KEY-----";
const PEM_ENCRYPTED_HEADER: &str = "-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----";
const PEM_ENCRYPTED_FOOTER: &str = "-----END ENCRYPTED ML-KEM PRIVATE KEY-----";

/// Une las lineas de un cuerpo PEM en un solo string sin saltos de linea.
fn unwrap_pem_body(body: &str) -> String {
    body.chars().filter(|c| !c.is_whitespace()).collect()
}

/// Extrae el cuerpo entre header y footer. Retorna error si falta alguno.
fn extract_pem_body<'a>(
    pem: &'a str,
    header: &str,
    footer: &str,
) -> Result<&'a str, aegisq_core::error::AegisQError> {
    let after_header =
        pem.find(header)
            .ok_or(aegisq_core::error::AegisQError::KeySerializationError(
                "PEM header not found",
            ))?;
    let body_start = after_header + header.len();
    let after_footer = pem[body_start..].find(footer).ok_or(
        aegisq_core::error::AegisQError::KeySerializationError("PEM footer not found"),
    )?;
    Ok(&pem[body_start..body_start + after_footer])
}

// ── Funciones de carga de llave PUBLICA ──────────────────────────────────

/// Carga una llave publica desde formato PEM-like ML-KEM.
///
/// Args:
///     pem (str): String PEM con el header `-----BEGIN ML-KEM PUBLIC KEY-----`.
///     level (SecurityLevel): Nivel de seguridad esperado.
///
/// Returns:
///     bytes: La llave publica lista para pasar a `AegisCipher.encrypt()`.
///
/// Raises:
///     KeySerializationError: Si el PEM no tiene header/footer o el Base64 es invalido.
///     InvalidParameterError: Si el tamano no coincide con el nivel.
#[pyfunction]
#[pyo3(signature = (pem, level=SecurityLevel::MlKem768))]
pub fn load_public_key_pem<'py>(
    py: Python<'py>,
    pem: &str,
    level: SecurityLevel,
) -> PyResult<Bound<'py, PyBytes>> {
    let core_level: CoreSecurityLevel = level.into();

    let body =
        extract_pem_body(pem, PEM_PUBLIC_HEADER, PEM_PUBLIC_FOOTER).map_err(core_error_to_pyerr)?;

    let b64 = unwrap_pem_body(body);
    let bytes = STANDARD
        .decode(&b64)
        .map_err(|_| {
            aegisq_core::error::AegisQError::KeySerializationError(
                "PEM body is not valid Base64 STANDARD",
            )
        })
        .map_err(core_error_to_pyerr)?;

    // Validar tamano para el nivel — AegisQError::InvalidParameter se mapea solo
    kem::validate_public_key_size(&bytes, core_level).map_err(core_error_to_pyerr)?;

    Ok(PyBytes::new(py, &bytes))
}

/// Carga una llave publica desde JSON.
///
/// El JSON debe tener los campos:
///   - "algorithm": "ML-KEM"
///   - "level": uno de "ML_KEM_512", "ML_KEM_768", "ML_KEM_1024"
///   - "public_key": Base64 URL-safe sin padding
///
/// Returns:
///     tuple[bytes, SecurityLevel]: (llave_publica, nivel)
///
/// Raises:
///     KeySerializationError: Si el JSON es invalido o le faltan campos.
///     InvalidParameterError: Si el tamano no coincide con el nivel declarado.
#[pyfunction]
pub fn load_public_key_json<'py>(
    py: Python<'py>,
    json: &str,
) -> PyResult<(Bound<'py, PyBytes>, SecurityLevel)> {
    // Parsing manual minimo para evitar dependencia de serde.
    // Formato esperado: {"algorithm":"...","level":"...","public_key":"..."}
    let algorithm = extract_json_string(json, "algorithm").map_err(core_error_to_pyerr)?;
    let level_str = extract_json_string(json, "level").map_err(core_error_to_pyerr)?;
    let public_key_b64 = extract_json_string(json, "public_key").map_err(core_error_to_pyerr)?;

    if algorithm != "ML-KEM" {
        return Err(core_error_to_pyerr(
            aegisq_core::error::AegisQError::KeySerializationError(
                "unsupported algorithm (expected 'ML-KEM')",
            ),
        ));
    }

    let core_level = match level_str.as_str() {
        "ML_KEM_512" => CoreSecurityLevel::MlKem512,
        "ML_KEM_768" => CoreSecurityLevel::MlKem768,
        "ML_KEM_1024" => CoreSecurityLevel::MlKem1024,
        _ => {
            return Err(core_error_to_pyerr(
                aegisq_core::error::AegisQError::KeySerializationError(
                    "unsupported level in JSON (expected ML_KEM_512/768/1024)",
                ),
            ));
        }
    };

    // Decodifica con la funcion existente (URL-safe sin padding, con trim de whitespace).
    let bytes =
        kem::public_key_from_b64(&public_key_b64, core_level).map_err(core_error_to_pyerr)?;

    Ok((PyBytes::new(py, &bytes), level_from_core(core_level)))
}

fn level_from_core(level: CoreSecurityLevel) -> SecurityLevel {
    match level {
        CoreSecurityLevel::MlKem512 => SecurityLevel::MlKem512,
        CoreSecurityLevel::MlKem768 => SecurityLevel::MlKem768,
        CoreSecurityLevel::MlKem1024 => SecurityLevel::MlKem1024,
    }
}

/// Extrae el valor string de un campo en un JSON muy simple (sin escapes).
/// Espera formato `"key":"value"` sin espacios. Suficiente para nuestros casos.
fn extract_json_string(
    json: &str,
    key: &str,
) -> Result<alloc::string::String, aegisq_core::error::AegisQError> {
    let needle = alloc::format!("\"{}\":", key);
    let key_pos =
        json.find(&needle)
            .ok_or(aegisq_core::error::AegisQError::KeySerializationError(
                "missing JSON field",
            ))?;
    let after_key = key_pos + needle.len();
    let rest = &json[after_key..];
    let rest = rest.trim_start();

    // Esperamos string que empieza con "
    let rest =
        rest.strip_prefix('"')
            .ok_or(aegisq_core::error::AegisQError::KeySerializationError(
                "JSON field value is not a string",
            ))?;
    let end = rest
        .find('"')
        .ok_or(aegisq_core::error::AegisQError::KeySerializationError(
            "unterminated JSON string value",
        ))?;
    Ok(alloc::string::String::from(&rest[..end]))
}

extern crate alloc;

// ── Funciones de carga de llave PRIVADA ──────────────────────────────────

/// Descifra y retorna la llave secreta desde un blob binario.
///
/// Args:
///     blob (bytes): Blob producido por `KeyPair.export_secret_key_raw`.
///     password (bytes): Contrasena usada al cifrar.
///
/// Returns:
///     tuple[bytes, SecurityLevel]: (secret_key, nivel)
///
/// Raises:
///     DecryptionError: Si la contrasena es incorrecta o el blob esta corrupto.
///     KeySerializationError: Si magic/version son invalidos o el blob esta truncado.
#[pyfunction]
pub fn load_secret_key_raw<'py>(
    py: Python<'py>,
    blob: &[u8],
    password: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, SecurityLevel)> {
    let result = py.detach(|| key_wrap::unwrap_secret_key(blob, password));
    match result {
        Ok((sk, core_level)) => Ok((PyBytes::new(py, &sk), level_from_core(core_level))),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

/// Descifra y retorna la llave secreta desde un PEM-like ENCRYPTED.
///
/// Args:
///     pem (str): String PEM con header `-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----`.
///     password (bytes): Contrasena usada al cifrar.
///
/// Returns:
///     tuple[bytes, SecurityLevel]: (secret_key, nivel)
///
/// Raises:
///     DecryptionError: Si la contrasena es incorrecta o el blob esta corrupto.
///     KeySerializationError: Si el PEM/Base64/magic son invalidos.
#[pyfunction]
pub fn load_secret_key_pem<'py>(
    py: Python<'py>,
    pem: &str,
    password: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, SecurityLevel)> {
    let body = extract_pem_body(pem, PEM_ENCRYPTED_HEADER, PEM_ENCRYPTED_FOOTER)
        .map_err(core_error_to_pyerr)?;
    let b64 = unwrap_pem_body(body);
    let blob = STANDARD
        .decode(&b64)
        .map_err(|_| {
            aegisq_core::error::AegisQError::KeySerializationError(
                "PEM ENCRYPTED body is not valid Base64 STANDARD",
            )
        })
        .map_err(core_error_to_pyerr)?;

    let result = py.detach(|| key_wrap::unwrap_secret_key(&blob, password));
    match result {
        Ok((sk, core_level)) => Ok((PyBytes::new(py, &sk), level_from_core(core_level))),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

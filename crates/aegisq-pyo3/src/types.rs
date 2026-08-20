//! Tipos Python expuestos via PyO3.
//!
//! Define las clases #[pyclass] que Python consume directamente:
//! - SecurityLevel: enum con los 3 niveles de seguridad
//! - KeyPair: par de claves (public_key, secret_key)

use base64::{Engine as _, engine::general_purpose::STANDARD};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use aegisq_core::kem::SecurityLevel as CoreSecurityLevel;
use aegisq_core::key_wrap;

use crate::error::core_error_to_pyerr;

/// Nivel de seguridad ML-KEM.
///
/// Python naming convention: UPPER_CASE via #[pyo3(name)].
#[pyclass(eq, eq_int, from_py_object)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// ML-KEM-512 — NIST Level 1
    #[pyo3(name = "ML_KEM_512")]
    MlKem512 = 512,

    /// ML-KEM-768 — NIST Level 3 (default)
    #[pyo3(name = "ML_KEM_768")]
    MlKem768 = 768,

    /// ML-KEM-1024 — NIST Level 5
    #[pyo3(name = "ML_KEM_1024")]
    MlKem1024 = 1024,
}

impl From<SecurityLevel> for aegisq_core::kem::SecurityLevel {
    fn from(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::MlKem512 => aegisq_core::kem::SecurityLevel::MlKem512,
            SecurityLevel::MlKem768 => aegisq_core::kem::SecurityLevel::MlKem768,
            SecurityLevel::MlKem1024 => aegisq_core::kem::SecurityLevel::MlKem1024,
        }
    }
}

/// Par de claves ML-KEM.
///
/// Contiene la clave publica y la clave secreta como `bytes` de Python.
#[pyclass(skip_from_py_object)]
#[derive(Clone)]
pub struct KeyPair {
    public_key_bytes: Vec<u8>,
    secret_key_bytes: Vec<u8>,
    level: SecurityLevel,
}

#[pymethods]
impl KeyPair {
    /// Clave publica como bytes.
    #[getter]
    fn public_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.public_key_bytes)
    }

    /// Clave secreta como bytes.
    #[getter]
    fn secret_key<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.secret_key_bytes)
    }

    /// Nivel de seguridad con el que se genero el par.
    #[getter]
    fn level(&self) -> SecurityLevel {
        self.level
    }

    fn __repr__(&self) -> String {
        // SAFE __repr__: muestra el nivel y un fingerprint publico de
        // la clave (primeros 8 bytes de SHA3-256(public_key) en hex).
        // Nunca expone bytes crudos de la clave secreta, y la clave
        // publica solo se identifica via su fingerprint truncado.
        // Detalles: ver `aegisq_core::kem::public_key_fingerprint`.
        let fp = aegisq_core::kem::public_key_fingerprint(&self.public_key_bytes);
        alloc::format!("KeyPair(level={:?}, fp={})", self.level, fp)
    }

    /// Serializa la clave publica a Base64 URL-safe sin padding.
    ///
    /// Returns:
    ///     str: La clave publica en formato Base64 URL-safe sin padding `=`.
    fn public_key_b64(&self) -> String {
        aegisq_core::kem::public_key_to_b64(&self.public_key_bytes)
    }

    // ── Serializacion v1.3.0 ────────────────────────────────────────

    /// Exporta la clave publica en formato PEM-like ML-KEM.
    ///
    /// Formato::
    ///
    ///     -----BEGIN ML-KEM PUBLIC KEY-----
    ///     <Base64 STANDARD, lineas de 64 chars>
    ///     -----END ML-KEM PUBLIC KEY-----
    ///
    /// No es DER/ASN.1. Es un formato propietario legible inspirado en PEM.
    ///
    /// Returns:
    ///     str: La clave publica en formato PEM.
    fn public_key_pem(&self) -> String {
        const HEADER: &str = "-----BEGIN ML-KEM PUBLIC KEY-----";
        const FOOTER: &str = "-----END ML-KEM PUBLIC KEY-----";
        let body = wrap_pem_lines(&STANDARD.encode(&self.public_key_bytes), 64);
        alloc::format!("{HEADER}\n{body}\n{FOOTER}\n")
    }

    /// Exporta la clave publica en formato JSON.
    ///
    /// JSON con campos: algorithm ("ML-KEM"), level ("ML_KEM_512/768/1024"),
    /// public_key (Base64 URL-safe sin padding).
    ///
    /// Returns:
    ///     str: La clave publica serializada como JSON.
    fn public_key_json(&self) -> String {
        let level_name = match self.level {
            SecurityLevel::MlKem512 => "ML_KEM_512",
            SecurityLevel::MlKem768 => "ML_KEM_768",
            SecurityLevel::MlKem1024 => "ML_KEM_1024",
        };
        let pk_b64 = aegisq_core::kem::public_key_to_b64(&self.public_key_bytes);
        alloc::format!(
            "{{\"algorithm\":\"ML-KEM\",\"level\":\"{}\",\"public_key\":\"{}\"}}",
            level_name,
            pk_b64
        )
    }

    /// Exporta la clave secreta cifrada como blob binario opaco.
    ///
    /// Layout del blob: magic("AQPK") | version(1) | level_id(1) | salt(16)
    /// | nonce(12) | ciphertext | tag(16). Se cifra con AES-256-GCM usando
    /// una clave derivada de `password` via HKDF-SHA3-256.
    ///
    /// Libera el GIL durante HKDF + AES-GCM.
    ///
    /// Args:
    ///     password (bytes): Contrasena para derivar la clave de cifrado.
    ///
    /// Returns:
    ///     bytes: Blob binario opaco listo para persistir.
    ///
    /// Raises:
    ///     RngError: Si el CSPRNG no esta disponible.
    ///     InvalidParameterError: Si la llave secreta tiene tamano incorrecto.
    fn export_secret_key_raw<'py>(
        &self,
        py: Python<'py>,
        password: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let blob = py
            .detach(|| self.wrap_secret_key_blob(password))
            .map_err(core_error_to_pyerr)?;
        Ok(PyBytes::new(py, &blob))
    }

    /// Exporta la clave secreta cifrada en formato PEM-like ENCRYPTED.
    ///
    /// Formato::
    ///
    ///     -----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----
    ///     <Base64 STANDARD del blob cifrado>
    ///     -----END ENCRYPTED ML-KEM PRIVATE KEY-----
    ///
    /// Args:
    ///     password (bytes): Contrasena para cifrar.
    ///
    /// Returns:
    ///     str: La clave privada cifrada como PEM.
    fn export_secret_key_pem<'py>(&self, py: Python<'py>, password: &[u8]) -> PyResult<String> {
        let blob = py
            .detach(|| self.wrap_secret_key_blob(password))
            .map_err(core_error_to_pyerr)?;
        const HEADER: &str = "-----BEGIN ENCRYPTED ML-KEM PRIVATE KEY-----";
        const FOOTER: &str = "-----END ENCRYPTED ML-KEM PRIVATE KEY-----";
        let body = wrap_pem_lines(&STANDARD.encode(&blob), 64);
        Ok(alloc::format!("{HEADER}\n{body}\n{FOOTER}\n"))
    }
}

extern crate alloc;

impl KeyPair {
    /// Constructor interno (no expuesto a Python directamente).
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>, level: SecurityLevel) -> Self {
        Self {
            public_key_bytes: public_key,
            secret_key_bytes: secret_key,
            level,
        }
    }

    /// Helper privado: cifra la secret_key con la contrasena y retorna el blob binario.
    /// Usado tanto por `export_secret_key_raw` como por `export_secret_key_pem`.
    ///
    /// Genera salt y nonce con `getrandom`, luego delega a `aegisq_core::key_wrap`.
    /// Esta funcion NO toca el GIL — el caller debe usar `py.detach(...)`.
    fn wrap_secret_key_blob(
        &self,
        password: &[u8],
    ) -> Result<alloc::vec::Vec<u8>, aegisq_core::error::AegisQError> {
        let core_level: CoreSecurityLevel = self.level.into();

        // Generar salt + nonce en Capa 2 (NO en Capa 1 — se mantiene pura).
        let mut salt = [0u8; key_wrap::SALT_SIZE];
        let mut nonce = [0u8; key_wrap::NONCE_SIZE];
        getrandom::fill(&mut salt).map_err(|_| aegisq_core::error::AegisQError::RngError)?;
        getrandom::fill(&mut nonce).map_err(|_| aegisq_core::error::AegisQError::RngError)?;

        key_wrap::wrap_secret_key(&self.secret_key_bytes, password, core_level, salt, nonce)
    }
}

/// Helper privado: divide un string Base64 en lineas de longitud `width`.
/// Usado por los metodos que generan PEM.
fn wrap_pem_lines(b64: &str, width: usize) -> alloc::string::String {
    let mut out = alloc::string::String::with_capacity(b64.len() + b64.len() / width);
    for (i, ch) in b64.chars().enumerate() {
        if i > 0 && i % width == 0 {
            out.push('\n');
        }
        out.push(ch);
    }
    out
}

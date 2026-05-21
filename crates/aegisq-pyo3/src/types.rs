//! Tipos Python expuestos via PyO3.
//!
//! Define las clases #[pyclass] que Python consume directamente:
//! - SecurityLevel: enum con los 3 niveles de seguridad
//! - KeyPair: par de claves (public_key, secret_key)

use pyo3::prelude::*;
use pyo3::types::PyBytes;

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
        format!(
            "KeyPair(level={:?}, pk_size={}, sk_size={})",
            self.level,
            self.public_key_bytes.len(),
            self.secret_key_bytes.len()
        )
    }

    /// Serializa la clave publica a Base64 URL-safe sin padding.
    ///
    /// Returns:
    ///     str: La clave publica en formato Base64 URL-safe sin padding `=`.
    fn public_key_b64(&self) -> String {
        aegisq_core::kem::public_key_to_b64(&self.public_key_bytes)
    }
}

impl KeyPair {
    /// Constructor interno (no expuesto a Python directamente).
    pub fn new(public_key: Vec<u8>, secret_key: Vec<u8>, level: SecurityLevel) -> Self {
        Self {
            public_key_bytes: public_key,
            secret_key_bytes: secret_key,
            level,
        }
    }
}

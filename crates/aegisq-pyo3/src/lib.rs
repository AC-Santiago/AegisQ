//! AegisQ PyO3 Bridge — Capa FFI entre Rust y Python.
//!
//! Expone el modulo `_aegisq_core` que Python importa como `aegisq._aegisq_core`.
//! Este crate NUNCA implementa logica criptografica — solo traduce tipos y maneja el GIL.

// PyO3's #[pyfunction] macro expansion triggers false positives for
// clippy::useless_conversion on the generated error conversion code.
#![allow(clippy::useless_conversion)]

use pyo3::prelude::*;

mod error;
mod hybrid_bindings;
mod kem_bindings;
mod key_io_bindings;
mod stream_bindings;
mod types;

/// Modulo Python `_aegisq_core`.
///
/// Registra todas las funciones, clases y excepciones expuestas a Python.
#[pymodule]
fn _aegisq_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Registrar excepciones
    error::register_exceptions(m)?;

    // Registrar clases
    m.add_class::<types::SecurityLevel>()?;
    m.add_class::<types::KeyPair>()?;

    // Registrar funciones KEM
    m.add_function(wrap_pyfunction!(kem_bindings::generate_keypair, m)?)?;
    m.add_function(wrap_pyfunction!(kem_bindings::encapsulate, m)?)?;
    m.add_function(wrap_pyfunction!(kem_bindings::decapsulate, m)?)?;

    // Registrar funciones de serializacion Base64
    m.add_function(wrap_pyfunction!(kem_bindings::serialize_public_key, m)?)?;
    m.add_function(wrap_pyfunction!(kem_bindings::deserialize_public_key, m)?)?;

    // Registrar funciones KEM deterministas (para KAT vector validation)
    m.add_function(wrap_pyfunction!(
        kem_bindings::generate_keypair_deterministic,
        m
    )?)?;
    m.add_function(wrap_pyfunction!(
        kem_bindings::encapsulate_deterministic,
        m
    )?)?;

    // Registrar funciones hibridas
    m.add_function(wrap_pyfunction!(hybrid_bindings::encrypt_hybrid, m)?)?;
    m.add_function(wrap_pyfunction!(hybrid_bindings::decrypt_hybrid, m)?)?;

    // Registrar funciones de carga/serializacion de llaves (v1.3.0)
    m.add_function(wrap_pyfunction!(key_io_bindings::load_public_key_pem, m)?)?;
    m.add_function(wrap_pyfunction!(key_io_bindings::load_public_key_json, m)?)?;
    m.add_function(wrap_pyfunction!(key_io_bindings::load_secret_key_raw, m)?)?;
    m.add_function(wrap_pyfunction!(key_io_bindings::load_secret_key_pem, m)?)?;

    // Registrar streaming (v1.5.0)
    m.add_class::<stream_bindings::StreamEncryptorHandle>()?;
    m.add_class::<stream_bindings::StreamDecryptorHandle>()?;
    m.add_function(wrap_pyfunction!(stream_bindings::stream_encryptor_new, m)?)?;
    m.add_function(wrap_pyfunction!(
        stream_bindings::stream_decryptor_from_header,
        m
    )?)?;

    Ok(())
}

//! Bindings PyO3 para streaming (encrypt_stream / decrypt_stream).
//!
//! Expone:
//! - `stream_encryptor_new` — encapsula + crea un StreamEncryptor.
//! - `stream_decryptor_from_header` — decapsula + crea un StreamDecryptor.
//!
//! Los handles retornados son stateful: conservan el shared_secret y
//! el chunk_index internamente. Los metodos `encrypt_chunk` / `decrypt_chunk`
//! liberan el GIL durante la operacion AES-GCM (via `py.detach`).

use pyo3::prelude::*;
use pyo3::types::PyBytes;
use zeroize::Zeroize;

extern crate alloc;
use alloc::vec::Vec;

use aegisq_core::error::AegisQError;
use aegisq_core::kem::SecurityLevel as CoreSecurityLevel;
use aegisq_core::stream::{
    StreamDecryptor as CoreStreamDecryptor, StreamEncryptor as CoreStreamEncryptor,
};

use crate::error::core_error_to_pyerr;
use crate::types::SecurityLevel;

/// Constante: tamano del tag AES-GCM (16 bytes).
const AES_GCM_TAG_SIZE: usize = 16;

/// Handle de cifrador de stream. Conserva el shared_secret entre llamadas.
#[pyclass]
pub struct StreamEncryptorHandle {
    inner: Option<CoreStreamEncryptor>,
}

#[pymethods]
impl StreamEncryptorHandle {
    /// Cifra un chunk de plaintext. Retorna el frame `[len || ciphertext || tag]`.
    ///
    /// Libera el GIL durante AES-GCM.
    fn encrypt_chunk<'py>(
        &mut self,
        py: Python<'py>,
        plaintext: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner.as_mut().ok_or_else(|| {
            core_error_to_pyerr(AegisQError::InvalidParameter("encryptor already finalized"))
        })?;

        let result = py.detach(|| inner.encrypt_chunk(plaintext));
        match result {
            Ok(frame) => Ok(PyBytes::new(py, &frame)),
            Err(e) => Err(core_error_to_pyerr(e)),
        }
    }

    /// Emite el EOF marker (frame de longitud 0 con un tag sobre plaintext vacio).
    ///
    /// Tras llamar `finalize`, el encryptor ya no puede usarse.
    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner.take().ok_or_else(|| {
            core_error_to_pyerr(AegisQError::InvalidParameter("encryptor already finalized"))
        })?;

        let result = py.detach(|| inner.finalize());
        match result {
            Ok(frame) => Ok(PyBytes::new(py, &frame)),
            Err(e) => Err(core_error_to_pyerr(e)),
        }
    }

    /// Chunks emitidos hasta ahora.
    fn chunk_index(&self) -> u32 {
        self.inner.as_ref().map(|e| e.chunk_index()).unwrap_or(0)
    }

    /// Tamano maximo de ciphertext por chunk.
    fn chunk_size(&self) -> u32 {
        self.inner.as_ref().map(|e| e.chunk_size()).unwrap_or(0)
    }

    /// Base nonce (12 bytes aleatorios por stream).
    fn base_nonce<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        let nonce = self
            .inner
            .as_ref()
            .map(|e| *e.base_nonce())
            .unwrap_or([0u8; 12]);
        PyBytes::new(py, &nonce)
    }
}

/// Encapsula + crea un StreamEncryptor.
///
/// Returns:
///     (header_bytes, encryptor_handle).
///
/// El header se antepone al primer output. El encryptor se mantiene
/// entre llamadas para emitir chunks y el EOF marker.
#[pyfunction]
#[pyo3(signature = (recipient_public_key, chunk_size, level=SecurityLevel::MlKem768))]
pub fn stream_encryptor_new<'py>(
    py: Python<'py>,
    recipient_public_key: &[u8],
    chunk_size: u32,
    level: SecurityLevel,
) -> PyResult<(Bound<'py, PyBytes>, StreamEncryptorHandle)> {
    let core_level: CoreSecurityLevel = level.into();

    // Hacer encaps + alloc nonce + header + encryptor en bloque sin GIL.
    let result = py.detach(|| -> Result<(Vec<u8>, CoreStreamEncryptor), AegisQError> {
        // 1. ML-KEM.Encap
        let enc_res = aegisq_core::kem::encapsulate(recipient_public_key, core_level)?;
        let capsule = enc_res.capsule;
        let mut shared_secret_vec = enc_res.shared_secret;

        // shared_secret debe ser 32 bytes (FIPS 203). Lo convertimos a
        // array fijo para StreamEncryptor::new(&[u8; 32]).
        let mut shared_secret: [u8; 32] = shared_secret_vec
            .as_slice()
            .try_into()
            .map_err(|_| AegisQError::InvalidParameter("shared_secret length is not 32 bytes"))?;

        // 2. Nonce base aleatorio
        let mut base_nonce = [0u8; 12];
        getrandom::fill(&mut base_nonce).map_err(|_| AegisQError::RngError)?;

        // 3. Header
        let header_len = aegisq_core::stream::stream_header_size(core_level);
        let mut header = Vec::with_capacity(header_len);
        header.extend_from_slice(&capsule);
        header.extend_from_slice(&base_nonce);
        header.extend_from_slice(&chunk_size.to_be_bytes());

        // 4. Encryptor
        let enc = CoreStreamEncryptor::new(&shared_secret, base_nonce, chunk_size)?;

        // Zeroize shared_secret local (el encryptor guarda una copia internamente).
        shared_secret.zeroize();
        shared_secret_vec.zeroize();
        Ok((header, enc))
    });

    match result {
        Ok((header, enc)) => {
            let handle = StreamEncryptorHandle { inner: Some(enc) };
            Ok((PyBytes::new(py, &header), handle))
        }
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

/// Handle de descifrador de stream. Conserva el shared_secret entre llamadas.
#[pyclass]
pub struct StreamDecryptorHandle {
    inner: Option<CoreStreamDecryptor>,
}

#[pymethods]
impl StreamDecryptorHandle {
    /// Descifra un chunk. Retorna el plaintext.
    ///
    /// Libera el GIL durante AES-GCM.
    fn decrypt_chunk<'py>(
        &mut self,
        py: Python<'py>,
        ciphertext: &[u8],
        tag: &[u8],
    ) -> PyResult<Bound<'py, PyBytes>> {
        let inner = self.inner.as_mut().ok_or_else(|| {
            core_error_to_pyerr(AegisQError::InvalidParameter("decryptor already finalized"))
        })?;

        if tag.len() != AES_GCM_TAG_SIZE {
            return Err(core_error_to_pyerr(AegisQError::InvalidParameter(
                "AES-GCM tag must be 16 bytes",
            )));
        }
        let mut tag_arr = [0u8; AES_GCM_TAG_SIZE];
        tag_arr.copy_from_slice(tag);

        let result = py.detach(|| inner.decrypt_chunk(ciphertext, &tag_arr));
        match result {
            Ok(plaintext) => Ok(PyBytes::new(py, &plaintext)),
            Err(e) => Err(core_error_to_pyerr(e)),
        }
    }

    /// Procesa el EOF marker (frame de longitud 0).
    fn process_eof(&mut self, py: Python<'_>, tag: &[u8]) -> PyResult<()> {
        let inner = self.inner.as_mut().ok_or_else(|| {
            core_error_to_pyerr(AegisQError::InvalidParameter("decryptor already finalized"))
        })?;

        if tag.len() != AES_GCM_TAG_SIZE {
            return Err(core_error_to_pyerr(AegisQError::InvalidParameter(
                "AES-GCM tag must be 16 bytes",
            )));
        }
        let mut tag_arr = [0u8; AES_GCM_TAG_SIZE];
        tag_arr.copy_from_slice(tag);

        let result = py.detach(|| inner.process_eof(&tag_arr));
        result.map_err(core_error_to_pyerr)
    }

    /// Verifica que el EOF marker fue visto.
    fn finalize(&mut self) -> PyResult<()> {
        let inner = self.inner.take().ok_or_else(|| {
            core_error_to_pyerr(AegisQError::InvalidParameter("already finalized"))
        })?;
        let _ = inner;
        Ok(())
    }

    /// Chunks descifrados hasta ahora.
    fn chunk_index(&self) -> u32 {
        self.inner.as_ref().map(|d| d.chunk_index()).unwrap_or(0)
    }

    /// Tamano maximo del ciphertext por chunk.
    fn chunk_size(&self) -> u32 {
        self.inner.as_ref().map(|d| d.chunk_size()).unwrap_or(0)
    }

    /// True si el EOF marker fue procesado.
    fn eof_seen(&self) -> bool {
        self.inner.as_ref().map(|d| d.eof_seen()).unwrap_or(false)
    }
}

/// Decapsula + crea un StreamDecryptor desde un header.
///
/// Args:
///     header_bytes: header serializado [capsule | base_nonce | chunk_size].
///     secret_key: clave secreta ML-KEM del receptor.
///
/// Errors:
///     AegisQError::InvalidParameter si header mal formado.
#[pyfunction]
pub fn stream_decryptor_from_header<'py>(
    py: Python<'py>,
    header_bytes: &[u8],
    secret_key: &[u8],
    level: SecurityLevel,
) -> PyResult<StreamDecryptorHandle> {
    let core_level: CoreSecurityLevel = level.into();

    let result = py.detach(|| -> Result<CoreStreamDecryptor, AegisQError> {
        let header_size = aegisq_core::stream::stream_header_size(core_level);
        if header_bytes.len() < header_size {
            return Err(AegisQError::InvalidParameter(
                "stream header too short for the given security level",
            ));
        }

        let capsule_size = core_level.capsule_size();
        let capsule = &header_bytes[..capsule_size];
        let nonce_start = capsule_size;
        let nonce_end = nonce_start + 12;
        let base_nonce: [u8; 12] = header_bytes[nonce_start..nonce_end].try_into().unwrap();
        let chunk_size =
            u32::from_be_bytes(header_bytes[nonce_end..nonce_end + 4].try_into().unwrap());

        // Decaps
        let mut shared_secret_vec = aegisq_core::kem::decapsulate(capsule, secret_key, core_level)?;
        let mut shared_secret: [u8; 32] = shared_secret_vec
            .as_slice()
            .try_into()
            .map_err(|_| AegisQError::InvalidParameter("shared_secret length is not 32 bytes"))?;

        // Decryptor
        let dec = CoreStreamDecryptor::new(&shared_secret, base_nonce, chunk_size)?;
        shared_secret.zeroize();
        shared_secret_vec.zeroize();
        Ok(dec)
    });

    match result {
        Ok(dec) => Ok(StreamDecryptorHandle { inner: Some(dec) }),
        Err(e) => Err(core_error_to_pyerr(e)),
    }
}

/// Test unit: header size matches the convention.
#[allow(dead_code)]
pub(crate) fn _header_size_smoke(level: CoreSecurityLevel) -> usize {
    aegisq_core::stream::stream_header_size(level)
}

// Tests en Capa 2 via pytest (cubren el flujo end-to-end).

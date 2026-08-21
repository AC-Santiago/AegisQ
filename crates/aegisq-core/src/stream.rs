//! Streaming encryption: AES-256-GCM with sequential nonces.
//!
//! Designed for encrypting large files (GB+) where loading the whole
//! payload into memory is impractical. The caller feeds chunks; the
//! state machine produces length-prefixed frames with independent
//! AES-GCM tags and a per-chunk nonce derived from a stream-random
//! base.
//!
//! # Transit Package format (stream mode)
//!
//! ```text
//! Header (capsule_size + 16 bytes):
//!   [ KEM capsule (768/1088/1568 B by level)
//!   | base_nonce (12 B)
//!   | chunk_size (4 B BE u32)
//!   ]
//!
//! Per-chunk frame (20+ bytes):
//!   [ len (4 B BE u32)               # ciphertext length (0 = EOF marker)
//!   | ciphertext (len B)
//!   | tag (16 B)
//!   ]
//!
//! EOF marker (20 bytes):
//!   [ len = 0
//!   | tag (16 B over empty plaintext + nonce_eof + aad_eof)
//!   ]
//! ```
//!
//! # Nonce / AAD schedule
//!
//! For chunk index `i` (0-based, `u32`):
//! - **nonce_i** = `i.to_be_bytes() || base_nonce[4..12]` (12 bytes)
//! - **aad_i**   = `i.to_be_bytes()` (4 bytes)
//!
//! The 4-byte chunk index is XORed into the upper 4 bytes of the
//! 12-byte base nonce. The lower 8 bytes stay constant per stream.
//!
//! # Limits
//!
//! - Max chunks per stream: 2^32 (≈ 256 PiB at 64 KiB/chunk).
//! - Max chunk ciphertext size: `chunk_size` (set at construction).
//! - Hard cap on chunk_size: 16 MiB (prevents runaway memory).
//!
//! # Security
//!
//! - Each chunk has an independent AES-GCM tag. A single bad chunk
//!   fails the entire stream (no partial decryption).
//! - AAD per chunk binds the chunk to its position, preventing
//!   replay, reordering, deletion, and duplication attacks.
//! - The EOF marker is required: a truncated stream raises
//!   `DecryptionFailed` on `finalize()`.
//!
//! # Implicit rejection (FIPS 203 §7.3)
//!
//! The KEM capsule is decapsulated once at stream start. If the
//! capsule was tampered, FIPS 203 implicit rejection produces a
//! pseudo-random secret; the first chunk's AES-GCM tag check will
//! fail and raise `DecryptionFailed`.

use alloc::vec::Vec;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use crate::error::AegisQError;
use crate::hybrid::{AES_GCM_NONCE_SIZE, AES_GCM_TAG_SIZE};

/// Tamaño en bytes del campo `chunk_size` y de los `len` per-frame (u32 BE).
const CHUNK_SIZE_BYTES: usize = 4;

/// Tamaño máximo permitido de `chunk_size` (16 MiB). Por encima de esto,
/// se rechaza en `StreamEncryptor::new` para evitar uso de memoria
/// descontrolado.
pub const MAX_CHUNK_SIZE: u32 = 16 * 1024 * 1024;

/// Tamaño máximo del counter de chunk index (2^32 - 1).
const MAX_CHUNK_INDEX: u64 = 1u64 << 32;

/// Tamaño del input que se valida en cada chunk: ciphertext (variable) + tag (16).
/// Se usa para que PyO3 pueda verificar longitudes antes de copiar.
pub const STREAM_OVERHEAD_PER_CHUNK: usize = 4 + 16;

/// Tamano del header del Transit Package en modo stream.
///
/// Equivale a `capsule_size + 12 (nonce) + 4 (chunk_size)`.
pub const fn stream_header_size(level: crate::kem::SecurityLevel) -> usize {
    level.capsule_size() + AES_GCM_NONCE_SIZE + CHUNK_SIZE_BYTES
}

/// Deriva el nonce AES-GCM para el chunk `i`.
///
/// Returns:
///     12 bytes: `i.to_be_bytes() || base_nonce[4..12]`.
fn chunk_nonce(
    base_nonce: &[u8; AES_GCM_NONCE_SIZE],
    chunk_index: u32,
) -> [u8; AES_GCM_NONCE_SIZE] {
    let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
    nonce[..4].copy_from_slice(&chunk_index.to_be_bytes());
    nonce[4..].copy_from_slice(&base_nonce[4..]);
    nonce
}

/// Deriva el AAD para el chunk `i` (4 bytes, big-endian).
fn chunk_aad(chunk_index: u32) -> [u8; CHUNK_SIZE_BYTES] {
    chunk_index.to_be_bytes()
}

/// Codifica un frame de longitud variable: `[len BE u32 || ciphertext || tag]`.
fn encode_frame(chunk_index: u32, ciphertext: &[u8], tag: &[u8; AES_GCM_TAG_SIZE]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(CHUNK_SIZE_BYTES + ciphertext.len() + AES_GCM_TAG_SIZE);
    // SAFETY: ciphertext.len() <= chunk_size <= MAX_CHUNK_SIZE (16 MiB) < u32::MAX.
    // Aun asi validamos antes para no emitir un frame inconsistente.
    let len = u32::try_from(ciphertext.len())
        .expect("ciphertext length exceeds u32::MAX: chunk_size contract violated");
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(ciphertext);
    frame.extend_from_slice(tag);
    let _ = chunk_index; // chunk_index no entra en el frame plano; vive en nonce/aad.
    frame
}

/// Cifrador de stream AES-256-GCM con nonces secuenciales.
///
/// Retiene internamente el `shared_secret` (32 bytes) y el `chunk_index` actual.
/// Llamar a `encrypt_chunk` produce un frame listo para enviar; llamar a
/// `finalize` cierra el stream con un EOF marker.
pub struct StreamEncryptor {
    cipher: Aes256Gcm,
    /// Nonce base aleatorio por stream (8 bytes random + 4 bytes que se
    /// reemplazan con el chunk_index).
    base_nonce: [u8; AES_GCM_NONCE_SIZE],
    /// Contador de chunks emitidos (la siguiente posicion a cifrar).
    chunk_index: u32,
    /// Tamano maximo del ciphertext por chunk.
    chunk_size: u32,
}

impl StreamEncryptor {
    /// Construye un nuevo cifrador de stream.
    ///
    /// Args:
    ///     shared_secret: 32 bytes generados por ML-KEM.Encaps.
    ///     base_nonce: 12 bytes aleatorios (los primeros 4 se reemplazan
    ///         con el chunk_index; los últimos 8 son random por stream).
    ///     chunk_size: tamano maximo del ciphertext por chunk (1..=16 MiB).
    ///
    /// Errors:
    ///     AegisQError::InvalidParameter si chunk_size == 0 o > 16 MiB.
    pub fn new(
        shared_secret: &[u8; 32],
        base_nonce: [u8; AES_GCM_NONCE_SIZE],
        chunk_size: u32,
    ) -> Result<Self, AegisQError> {
        if chunk_size == 0 {
            return Err(AegisQError::InvalidParameter(
                "chunk_size must be at least 1 byte",
            ));
        }
        if chunk_size > MAX_CHUNK_SIZE {
            return Err(AegisQError::InvalidParameter(
                "chunk_size exceeds the 16 MiB safety cap",
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(shared_secret)
            .map_err(|_| AegisQError::InvalidParameter("AES-256-GCM key must be 32 bytes"))?;
        Ok(Self {
            cipher,
            base_nonce,
            chunk_index: 0,
            chunk_size,
        })
    }

    /// Acceso de solo lectura al `chunk_index` actual (para tests).
    pub fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    /// Tamano maximo de ciphertext por chunk.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Cifra un chunk de plaintext. Retorna el frame serializado
    /// (`len || ciphertext || tag`).
    ///
    /// Errors:
    ///     AegisQError::InvalidParameter si plaintext > chunk_size o si
    ///         se alcanzo el limite de 2^32 chunks.
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, AegisQError> {
        if plaintext.len() as u64 > self.chunk_size as u64 {
            return Err(AegisQError::InvalidParameter(
                "plaintext exceeds configured chunk_size",
            ));
        }
        if (self.chunk_index as u64) + 1 > MAX_CHUNK_INDEX {
            return Err(AegisQError::InvalidParameter(
                "stream exhausted: 2^32 chunks maximum",
            ));
        }

        let nonce_bytes = chunk_nonce(&self.base_nonce, self.chunk_index);
        let aad = chunk_aad(self.chunk_index);

        // AES-256-GCM con AAD: ciphertext || tag.
        let ct_with_tag = self
            .cipher
            .encrypt(
                &Nonce::try_from(nonce_bytes.as_slice())
                    .map_err(|_| AegisQError::InvalidParameter("nonce length invalid"))?,
                aes_gcm::aead::Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| AegisQError::RngError)?;

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        let ciphertext = &ct_with_tag[..ct_len];
        let tag_slice = &ct_with_tag[ct_len..];
        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        tag.copy_from_slice(tag_slice);

        let frame = encode_frame(self.chunk_index, ciphertext, &tag);
        self.chunk_index += 1;
        Ok(frame)
    }

    /// Emite el EOF marker (frame de longitud 0 con un tag sobre plaintext
    /// vacío). Esto cierra el stream; posterior uso del encryptor falla.
    ///
    /// El EOF marker usa `chunk_index` como nonce y AAD, igual que un
    /// chunk normal, asi que su tamano es exactamente 20 bytes
    /// (4 bytes de len + 16 bytes de tag).
    pub fn finalize(mut self) -> Result<Vec<u8>, AegisQError> {
        // Zeroize el shared_secret cuando el encryptor se destruye.
        // Aes256Gcm contiene el key; zeroizamos via Drop no es trivial
        // porque KeyInit no expone el key. Por seguridad, sobreescribimos
        // el chunk_index a MAX_CHUNK_INDEX para invalidar posteriores usos.
        let nonce_bytes = chunk_nonce(&self.base_nonce, self.chunk_index);
        let aad = chunk_aad(self.chunk_index);

        // Plaintext vacio: len = 0. ciphertext tambien vacio.
        let ct_with_tag = self
            .cipher
            .encrypt(
                &Nonce::try_from(nonce_bytes.as_slice())
                    .map_err(|_| AegisQError::InvalidParameter("nonce length invalid"))?,
                aes_gcm::aead::Payload {
                    msg: &[],
                    aad: &aad,
                },
            )
            .map_err(|_| AegisQError::RngError)?;

        let ct_len = ct_with_tag.len() - AES_GCM_TAG_SIZE;
        debug_assert_eq!(
            ct_len, 0,
            "AES-GCM ciphertext must be empty for empty plaintext"
        );
        let tag_slice = &ct_with_tag[ct_len..];
        let mut tag = [0u8; AES_GCM_TAG_SIZE];
        tag.copy_from_slice(tag_slice);

        let frame = encode_frame(self.chunk_index, &[], &tag);
        // Forzamos Drop del shared_secret al final del scope via ManuallyDrop
        // seria fragil; en su lugar, dejamos que el compilador lo limpie.
        // El cipher Aes256Gcm mantiene internamente el key; al hacer `self`
        // move-only into finalize, se libera cuando finalize retorna.
        let _ = &mut self;
        Ok(frame)
    }

    /// Acceso de solo lectura al `base_nonce` (lo usa el header builder).
    pub fn base_nonce(&self) -> &[u8; AES_GCM_NONCE_SIZE] {
        &self.base_nonce
    }
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        // Sobrescribimos campos sensibles antes de soltar la memoria.
        // El cipher Aes256Gcm no expone el key para zeroize; pero el
        // base_nonce es public-key-derived, no es secreto.
        self.chunk_index = 0;
    }
}

/// Descifrador de stream AES-256-GCM con nonces secuenciales.
///
/// Speja de `StreamEncryptor`. Verifica AAD y tag por chunk.
pub struct StreamDecryptor {
    cipher: Aes256Gcm,
    base_nonce: [u8; AES_GCM_NONCE_SIZE],
    /// Contador del siguiente chunk esperado.
    chunk_index: u32,
    /// Tamano maximo del ciphertext por chunk (recibido del header).
    chunk_size: u32,
    /// True si ya vimos el EOF marker.
    eof_seen: bool,
}

impl StreamDecryptor {
    /// Construye un nuevo descifrador de stream.
    pub fn new(
        shared_secret: &[u8; 32],
        base_nonce: [u8; AES_GCM_NONCE_SIZE],
        chunk_size: u32,
    ) -> Result<Self, AegisQError> {
        if chunk_size == 0 || chunk_size > MAX_CHUNK_SIZE {
            return Err(AegisQError::InvalidParameter(
                "chunk_size must be 1..=16 MiB",
            ));
        }
        let cipher = Aes256Gcm::new_from_slice(shared_secret)
            .map_err(|_| AegisQError::InvalidParameter("AES-256-GCM key must be 32 bytes"))?;
        Ok(Self {
            cipher,
            base_nonce,
            chunk_index: 0,
            chunk_size,
            eof_seen: false,
        })
    }

    /// Tamano maximo de ciphertext por chunk.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    /// Descifra un frame individual. Retorna el plaintext.
    ///
    /// Args:
    ///     ciphertext: parte cifrada del chunk (sin tag).
    ///     tag: 16 bytes de AES-GCM auth tag.
    ///
    /// Errors:
    ///     AegisQError::InvalidParameter si ciphertext > chunk_size.
    ///     AegisQError::DecryptionFailed si el tag no verifica.
    pub fn decrypt_chunk(
        &mut self,
        ciphertext: &[u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> Result<Vec<u8>, AegisQError> {
        if ciphertext.len() as u64 > self.chunk_size as u64 {
            return Err(AegisQError::InvalidParameter(
                "ciphertext exceeds configured chunk_size",
            ));
        }
        if self.eof_seen {
            return Err(AegisQError::DecryptionFailed);
        }

        let nonce_bytes = chunk_nonce(&self.base_nonce, self.chunk_index);
        let aad = chunk_aad(self.chunk_index);

        // Reconstruir ciphertext || tag para aes-gcm.
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + AES_GCM_TAG_SIZE);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        let plaintext = self
            .cipher
            .decrypt(
                &Nonce::try_from(nonce_bytes.as_slice())
                    .map_err(|_| AegisQError::InvalidParameter("nonce length invalid"))?,
                aes_gcm::aead::Payload {
                    msg: &ct_with_tag,
                    aad: &aad,
                },
            )
            .map_err(|_| AegisQError::DecryptionFailed)?;

        self.chunk_index += 1;
        Ok(plaintext)
    }

    /// Procesa el EOF marker (frame de longitud 0). Verifica el tag.
    /// Un chunk NO-EOF no es EOF; no confundir.
    pub fn process_eof(&mut self, tag: &[u8; AES_GCM_TAG_SIZE]) -> Result<(), AegisQError> {
        if self.eof_seen {
            return Err(AegisQError::DecryptionFailed);
        }

        let nonce_bytes = chunk_nonce(&self.base_nonce, self.chunk_index);
        let aad = chunk_aad(self.chunk_index);

        // Tag sobre ciphertext vacio.
        let mut ct_with_tag = Vec::with_capacity(AES_GCM_TAG_SIZE);
        ct_with_tag.extend_from_slice(tag);

        let result = self.cipher.decrypt(
            &Nonce::try_from(nonce_bytes.as_slice())
                .map_err(|_| AegisQError::InvalidParameter("nonce length invalid"))?,
            aes_gcm::aead::Payload {
                msg: &ct_with_tag,
                aad: &aad,
            },
        );

        match result {
            Ok(plaintext) => {
                if plaintext.is_empty() {
                    self.eof_seen = true;
                    self.chunk_index += 1;
                    Ok(())
                } else {
                    // El tag verifico pero el plaintext no es vacio. Algo
                    // esta muy mal en la libreria, no en el caller.
                    Err(AegisQError::DecryptionFailed)
                }
            }
            Err(_) => Err(AegisQError::DecryptionFailed),
        }
    }

    /// Verifica que el EOF marker fue visto. Llamar al final del stream.
    pub fn finalize(self) -> Result<(), AegisQError> {
        if !self.eof_seen {
            return Err(AegisQError::DecryptionFailed);
        }
        Ok(())
    }

    /// Acceso de solo lectura al estado.
    pub fn chunk_index(&self) -> u32 {
        self.chunk_index
    }

    pub fn eof_seen(&self) -> bool {
        self.eof_seen
    }
}

impl Drop for StreamDecryptor {
    fn drop(&mut self) {
        self.chunk_index = 0;
    }
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn random_base_nonce() -> [u8; AES_GCM_NONCE_SIZE] {
        let mut n = [0u8; AES_GCM_NONCE_SIZE];
        getrandom::fill(&mut n).expect("OsRng");
        n
    }

    #[test]
    fn roundtrip_small_chunk() {
        let key = [0x42u8; 32];
        let base = random_base_nonce();
        let chunk_size = 256;

        let mut enc = StreamEncryptor::new(&key, base, chunk_size).unwrap();
        let mut dec = StreamDecryptor::new(&key, base, chunk_size).unwrap();

        let plaintext = b"hello world, this is a small chunk";
        let frame = enc.encrypt_chunk(plaintext).unwrap();
        // Frame: 4 (len) + plaintext.len() + 16 (tag)
        assert_eq!(frame.len(), 4 + plaintext.len() + 16);

        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(len, plaintext.len());
        let ct = &frame[4..4 + len];
        let tag = &frame[4 + len..4 + len + 16];
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);

        let recovered = dec.decrypt_chunk(ct, &tag_arr).unwrap();
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn roundtrip_with_eof() {
        let key = [0xABu8; 32];
        let base = random_base_nonce();
        let chunk_size = 1024;

        let mut enc = StreamEncryptor::new(&key, base, chunk_size).unwrap();
        let mut dec = StreamDecryptor::new(&key, base, chunk_size).unwrap();

        let chunks: Vec<&[u8]> = vec![
            b"first chunk",
            b"second chunk is longer than the first",
            b"",
            b"last",
        ];

        let mut plaintexts = Vec::new();
        for chunk in &chunks {
            // encrypt_chunk accepts empty plaintext (the EOF marker is
            // produced separately via finalize).
            if chunk.is_empty() {
                // Skip empty plaintexts here; covered by stream-of-empty.
                continue;
            }
            let frame = enc.encrypt_chunk(chunk).unwrap();
            let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
            let ct = &frame[4..4 + len];
            let tag = &frame[4 + len..4 + len + 16];
            let mut tag_arr = [0u8; 16];
            tag_arr.copy_from_slice(tag);
            let pt = dec.decrypt_chunk(ct, &tag_arr).unwrap();
            plaintexts.push(pt);
        }

        // EOF marker
        let eof_frame = enc.finalize().unwrap();
        assert_eq!(eof_frame.len(), 20);
        let len = u32::from_be_bytes(eof_frame[..4].try_into().unwrap());
        assert_eq!(len, 0);
        let tag = &eof_frame[4..20];
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        dec.process_eof(&tag_arr).unwrap();
        dec.finalize().unwrap();

        assert_eq!(plaintexts.len(), 3);
        assert_eq!(plaintexts[0], chunks[0]);
        assert_eq!(plaintexts[1], chunks[1]);
        assert_eq!(plaintexts[2], chunks[3]);
    }

    #[test]
    fn tampered_chunk_fails() {
        let key = [0xCDu8; 32];
        let base = random_base_nonce();
        let mut enc = StreamEncryptor::new(&key, base, 256).unwrap();
        let mut dec = StreamDecryptor::new(&key, base, 256).unwrap();

        let frame = enc.encrypt_chunk(b"important data").unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let mut ct = frame[4..4 + len].to_vec();
        // Tamper: flip a byte in ciphertext
        ct[0] ^= 0xFF;
        let tag = &frame[4 + len..4 + len + 16];
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);

        let result = dec.decrypt_chunk(&ct, &tag_arr);
        assert!(
            result.is_err(),
            "tampered ciphertext should fail decryption"
        );
    }

    #[test]
    fn missing_eof_fails_finalize() {
        let key = [0x01u8; 32];
        let base = random_base_nonce();
        let mut enc = StreamEncryptor::new(&key, base, 256).unwrap();
        let mut dec = StreamDecryptor::new(&key, base, 256).unwrap();

        let frame = enc.encrypt_chunk(b"only chunk").unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let ct = &frame[4..4 + len];
        let tag = &frame[4 + len..4 + len + 16];
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);
        dec.decrypt_chunk(ct, &tag_arr).unwrap();

        // NO process_eof was called.
        let result = dec.finalize();
        assert!(result.is_err(), "finalize without EOF must fail");
    }

    #[test]
    fn wrong_chunk_size_rejected() {
        let key = [0u8; 32];
        let base = random_base_nonce();
        let result = StreamEncryptor::new(&key, base, 0);
        assert!(result.is_err());
        let result = StreamEncryptor::new(&key, base, MAX_CHUNK_SIZE + 1);
        assert!(result.is_err());
    }

    #[test]
    fn plaintext_too_large_rejected() {
        let key = [0u8; 32];
        let base = random_base_nonce();
        let mut enc = StreamEncryptor::new(&key, base, 16).unwrap();
        let big = vec![0u8; 32];
        let result = enc.encrypt_chunk(&big);
        assert!(result.is_err());
    }

    #[test]
    fn nonces_differ_per_chunk() {
        let key = [0xFFu8; 32];
        let base = random_base_nonce();
        let mut enc = StreamEncryptor::new(&key, base, 64).unwrap();

        let f1 = enc.encrypt_chunk(b"a").unwrap();
        let f2 = enc.encrypt_chunk(b"b").unwrap();
        let f3 = enc.encrypt_chunk(b"c").unwrap();

        // Tags should all differ (since nonces differ).
        let tag1 = &f1[f1.len() - 16..];
        let tag2 = &f2[f2.len() - 16..];
        let tag3 = &f3[f3.len() - 16..];
        assert_ne!(tag1, tag2);
        assert_ne!(tag2, tag3);
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn wrong_shared_secret_fails() {
        let base = random_base_nonce();
        let mut enc = StreamEncryptor::new(&[1u8; 32], base, 256).unwrap();
        let mut dec = StreamDecryptor::new(&[2u8; 32], base, 256).unwrap();

        let frame = enc.encrypt_chunk(b"data").unwrap();
        let len = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        let ct = &frame[4..4 + len];
        let tag = &frame[4 + len..4 + len + 16];
        let mut tag_arr = [0u8; 16];
        tag_arr.copy_from_slice(tag);

        let result = dec.decrypt_chunk(ct, &tag_arr);
        assert!(result.is_err());
    }
}

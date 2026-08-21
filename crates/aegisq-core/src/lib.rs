//! AegisQ Core — Motor criptografico post-cuantico (ML-KEM + AES-256-GCM)
//!
//! Este crate implementa la capa criptografica pura de AegisQ:
//! - ML-KEM (FIPS 203) para encapsulacion de claves
//! - AES-256-GCM para cifrado autenticado (hibrido KEM-DEM)
//!
//! Disenado para ser `no_std` compatible. No depende de PyO3 ni de Python.

#![no_std]

extern crate alloc;

pub mod error;
pub mod hybrid;
pub mod kdf;
pub mod kem;
pub mod key_wrap;
pub mod mlkem;
pub mod stream;

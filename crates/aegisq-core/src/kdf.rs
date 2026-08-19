//! HKDF-SHA3-256 + HMAC-SHA3-256 manual implementation.
//!
//! Implementa HMAC y HKDF con SHA3-256 segun RFC 5869 y NIST SP 800-185,
//! usando solo el crate `sha3` (ya en el workspace). No agrega dependencias nuevas.
//!
//! **Block size para HMAC-SHA3-256 = 136 bytes (rate del sponge Keccak, 1088 bits).**
//! Esto difiere de SHA-2 (SHA-256 usa block size 64 bytes). El spec original de v1.3.0
//! decia "64-byte block size" — eso era un error. SHA3-256 es un sponge function,
//! no Merkle-Damgard. El block size es la capacidad del sponge.
//!
//! Referencia: NIST SP 800-185 (SHA-3 Derived Functions).
//!
//! Este modulo es `pub(crate)` — nunca se expone en `lib.rs`. Solo lo usa `key_wrap.rs`.

#![allow(dead_code)] // sera usado por key_wrap.rs en el mismo milestone

use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

/// Block size para HMAC-SHA3-256 = rate del sponge = 136 bytes (1088 bits).
/// NIST SP 800-185 §4.2.
const SHA3_256_BLOCK_SIZE: usize = 136;

/// HMAC-SHA3-256: implementacion manual con patron ipad/opad.
///
/// # Arguments
/// - `key`: clave de cualquier longitud
/// - `data`: datos a autenticar
///
/// # Returns
/// 32 bytes de tag de autenticacion.
pub(crate) fn hmac_sha3_256(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Step 1: normalizar la clave a B bytes (136).
    // - Si key.len() > B: K' = Hash(key) padded to B.
    // - Si key.len() <= B: K' = key || zeros to B.
    let mut key_block = [0u8; SHA3_256_BLOCK_SIZE];
    if key.len() > SHA3_256_BLOCK_SIZE {
        let hashed = Sha3_256::digest(key);
        key_block[..32].copy_from_slice(&hashed);
        // resto ya esta en zeros
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    // Step 2: construir ipad y opad (K' XOR constantes, ambos de B bytes)
    let mut ipad = [0x36u8; SHA3_256_BLOCK_SIZE];
    let mut opad = [0x5Cu8; SHA3_256_BLOCK_SIZE];
    for i in 0..SHA3_256_BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    // Step 3: inner hash = SHA3-256(ipad || data)
    let mut inner_hasher = Sha3_256::new();
    Digest::update(&mut inner_hasher, ipad);
    Digest::update(&mut inner_hasher, data);
    let inner = inner_hasher.finalize();

    // Step 4: outer hash = SHA3-256(opad || inner)
    let mut outer_hasher = Sha3_256::new();
    Digest::update(&mut outer_hasher, opad);
    Digest::update(&mut outer_hasher, inner);
    let result = outer_hasher.finalize();

    // Zeroizar temporales (defense in depth)
    key_block.zeroize();
    ipad.zeroize();
    opad.zeroize();

    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// HKDF-SHA3-256: Extract + Expand (un solo bloque, 32 bytes de salida).
///
/// Implementa RFC 5869 con SHA3-256 como funcion hash.
/// Longitud de salida fija en 32 bytes (un solo bloque T(1) — sin loop de counter).
///
/// # Arguments
/// - `password`: input keying material (IKM) — la contrasena del usuario
/// - `salt`: 16 bytes aleatorios
/// - `info`: context-specific info (ej: dominio "aegisq-key-wrap-v1")
///
/// # Returns
/// 32 bytes de output keying material (OKM).
pub(crate) fn hkdf_sha3_256(password: &[u8], salt: &[u8; 16], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-Hash(salt, IKM)
    let mut prk = hmac_sha3_256(salt, password);

    // Expand: OKM = T(1) = HMAC-Hash(PRK, info || 0x01)
    // Queremos exactamente 32 bytes = HashLen, un solo bloque T alcanza.
    let mut expand_input = Zeroizing::new([0u8; 256]); // tamano generoso
    let mut expand_len = 0;
    if info.len() < 255 {
        expand_input[..info.len()].copy_from_slice(info);
        expand_len = info.len();
        expand_input[expand_len] = 0x01;
        expand_len += 1;
    }
    let okm = hmac_sha3_256(&prk, &expand_input[..expand_len]);

    prk.zeroize();
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HMAC-SHA3-256 de clave vacia + data vacia — vector de prueba independiente.
    /// Verificado contra Python stdlib:
    ///   python3 -c "import hmac, hashlib; print(hmac.new(b'', b'', hashlib.sha3_256).hexdigest())"
    /// = e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea
    #[test]
    fn hmac_sha3_256_empty_inputs_matches_python_stdlib() {
        let result = hmac_sha3_256(b"", b"");
        let hex: alloc::string::String =
            result.iter().map(|b| alloc::format!("{:02x}", b)).collect();
        assert_eq!(
            hex, "e841c164e5b4f10c9f3985587962af72fd607a951196fc92fb3a5251941784ea",
            "HMAC-SHA3-256 de inputs vacios debe coincidir con hmac stdlib de Python (hashlib.sha3_256)"
        );
    }

    /// Vector RFC 4231 Test Case 1 adaptado a SHA3-256.
    /// Python: hmac.new(b"\x0b"*20, b"Hi There", hashlib.sha3_256).hexdigest()
    /// = ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb
    #[test]
    fn hmac_sha3_256_rfc4231_test_case_1_matches_python() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = hmac_sha3_256(&key, data);
        let hex: alloc::string::String =
            result.iter().map(|b| alloc::format!("{:02x}", b)).collect();
        assert_eq!(
            hex, "ba85192310dffa96e2a3a40e69774351140bb7185e1202cdcc917589f95e16bb",
            "HMAC-SHA3-256 con clave 0x0b*20 y data 'Hi There' debe coincidir con Python"
        );
    }

    #[test]
    fn hkdf_sha3_256_is_deterministic() {
        let salt = [1u8; 16];
        let info = b"aegisq-test";
        let a = hkdf_sha3_256(b"password", &salt, info);
        let b = hkdf_sha3_256(b"password", &salt, info);
        assert_eq!(a, b, "HKDF debe ser deterministico para los mismos inputs");
    }

    #[test]
    fn hkdf_sha3_256_changes_with_salt() {
        let info = b"aegisq-test";
        let a = hkdf_sha3_256(b"password", &[1u8; 16], info);
        let b = hkdf_sha3_256(b"password", &[2u8; 16], info);
        assert_ne!(a, b, "Diferentes salts deben producir diferente OKM");
    }

    #[test]
    fn hkdf_sha3_256_changes_with_info() {
        let salt = [1u8; 16];
        let a = hkdf_sha3_256(b"password", &salt, b"info-v1");
        let b = hkdf_sha3_256(b"password", &salt, b"info-v2");
        assert_ne!(a, b, "Diferentes info strings deben producir diferente OKM");
    }

    #[test]
    fn hkdf_sha3_256_changes_with_password() {
        let salt = [1u8; 16];
        let info = b"aegisq-test";
        let a = hkdf_sha3_256(b"password-A", &salt, info);
        let b = hkdf_sha3_256(b"password-B", &salt, info);
        assert_ne!(a, b, "Diferentes contrasenas deben producir diferente OKM");
    }

    /// HKDF con inputs vacios no debe panicar y debe producir un output fijo.
    /// (Smoke test para edge cases.)
    #[test]
    fn hkdf_sha3_256_empty_inputs_does_not_panic() {
        let salt = [0u8; 16];
        let info: &[u8] = b"";
        let _ = hkdf_sha3_256(b"", &salt, info);
    }
}

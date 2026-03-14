//! Parametros ML-KEM por nivel de seguridad (FIPS 203).
//!
//! Cada variante define los valores (k, eta1, eta2, du, dv)
//! que parametrizan las operaciones sobre retículos.

/// Modulo primo del campo Z_q.
pub const Q: u16 = 3329;

/// Grado del polinomio (X^256 + 1).
pub const N: usize = 256;

/// Raiz primitiva 256-esima de la unidad en Z_q.
pub const ZETA: u16 = 17;

/// Parametros para una variante especifica de ML-KEM.
#[derive(Debug, Clone, Copy)]
pub struct MlKemParams {
    /// Dimension de la matriz (numero de polinomios por vector).
    pub k: usize,
    /// Parametro de ruido para la clave secreta.
    pub eta1: usize,
    /// Parametro de ruido para el cifrado.
    pub eta2: usize,
    /// Bits de compresion para u (componente del ciphertext).
    pub du: usize,
    /// Bits de compresion para v (componente del ciphertext).
    pub dv: usize,
}

/// ML-KEM-512: Nivel NIST 1
pub const PARAMS_512: MlKemParams = MlKemParams {
    k: 2,
    eta1: 3,
    eta2: 2,
    du: 10,
    dv: 4,
};

/// ML-KEM-768: Nivel NIST 3 (default)
pub const PARAMS_768: MlKemParams = MlKemParams {
    k: 3,
    eta1: 2,
    eta2: 2,
    du: 10,
    dv: 4,
};

/// ML-KEM-1024: Nivel NIST 5
pub const PARAMS_1024: MlKemParams = MlKemParams {
    k: 4,
    eta1: 2,
    eta2: 2,
    du: 11,
    dv: 5,
};

/// Obtiene los parametros para un nivel de seguridad dado.
pub const fn params_for_level(level: crate::kem::SecurityLevel) -> MlKemParams {
    match level {
        crate::kem::SecurityLevel::MlKem512 => PARAMS_512,
        crate::kem::SecurityLevel::MlKem768 => PARAMS_768,
        crate::kem::SecurityLevel::MlKem1024 => PARAMS_1024,
    }
}

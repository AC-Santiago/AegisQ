//! ML-KEM (Module Lattice-based Key Encapsulation Mechanism) — FIPS 203
//!
//! Submodulos:
//! - `params`: Parametros por nivel de seguridad (k, eta1, eta2, du, dv)
//! - `math`: Aritmetica sobre Z_q y polinomios en R_q
//! - `sampling`: CBD y rejection sampling (SHAKE-128/256)
//! - `keygen`: ML-KEM.KeyGen (FIPS 203 Alg. 15)
//! - `encaps`: ML-KEM.Encaps (FIPS 203 Alg. 16)
//! - `decaps`: ML-KEM.Decaps con implicit rejection (FIPS 203 Alg. 17)

pub mod decaps;
pub mod encaps;
pub mod keygen;
pub mod math;
pub mod params;
pub mod sampling;

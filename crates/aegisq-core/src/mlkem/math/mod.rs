//! Modulos matematicos para ML-KEM.
//!
//! - `field`: Aritmetica en Z_q (q=3329), reduccion Barrett
//! - `ntt`: Number Theoretic Transform
//! - `poly`: Polinomios en R_q = Z_q[X]/(X^256+1)
//! - `compress`: Compresion/descompresion FIPS 203 §4.2.1

pub mod compress;
pub mod field;
pub mod ntt;
pub mod poly;

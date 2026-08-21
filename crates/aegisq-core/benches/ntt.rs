//! Benchmarks Criterion para operaciones NTT del modulo `math::ntt`.
//!
//! Cubre:
//! - `ntt` (forward, Algorithm 9 de FIPS 203)
//! - `ntt_inverse` (Algorithm 10)
//! - `basemul` (multiplicacion pointwise en dominio NTT)
//! - `ntt_multiply` (multiplicacion de polinomios via NTT)
//!
//! El NTT se aplica a un polinomio fijo de 256 coeficientes. Los
//! coeficientes se generan deterministamente con `FieldElement::new(i)`
//! para que cada corrida de bench use los mismos datos y la varianza
//! del bench refleje solo la varianza del algoritmo.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use aegisq_core::mlkem::math::field::FieldElement;
use aegisq_core::mlkem::math::ntt::{ntt, ntt_inverse, ntt_multiply};
use aegisq_core::mlkem::params::N;

/// Construye un polinomio de test con coeficientes 0..N.
fn make_test_poly() -> [FieldElement; N] {
    let mut p = [FieldElement::new(0); N];
    for (i, c) in p.iter_mut().enumerate() {
        *c = FieldElement::new(i as u16);
    }
    p
}

/// Bench `ntt` (forward).
fn bench_ntt(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt");
    // 256 coeficientes de 16 bits = 512 bytes procesados.
    group.throughput(Throughput::Bytes((N * 2) as u64));
    group.bench_function(BenchmarkId::from_parameter("forward"), |b| {
        b.iter(|| {
            let mut p = make_test_poly();
            ntt(&mut p);
        });
    });
    group.finish();
}

/// Bench `ntt_inverse`.
fn bench_ntt_inverse(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_inverse");
    group.throughput(Throughput::Bytes((N * 2) as u64));
    group.bench_function(BenchmarkId::from_parameter("inverse"), |b| {
        b.iter(|| {
            let mut p = make_test_poly();
            ntt_inverse(&mut p);
        });
    });
    group.finish();
}

/// Bench `ntt_multiply` (full polynomial multiplication via NTT).
/// Esto mide el costo total de la multiplicacion polinomica en R_q,
/// incluyendo 256 llamadas internas a `basemul`.
fn bench_ntt_multiply(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_multiply");
    group.throughput(Throughput::Bytes((N * 2) as u64));
    group.bench_function(BenchmarkId::from_parameter("full"), |b| {
        b.iter(|| {
            let a = make_test_poly();
            let b_poly = make_test_poly();
            let mut result = [FieldElement::new(0); N];
            ntt_multiply(&a, &b_poly, &mut result);
        });
    });
    group.finish();
}

/// Throughput alternativo: contar elementos de Z_q procesados.
fn bench_ntt_throughput_elements(c: &mut Criterion) {
    let mut group = c.benchmark_group("ntt_throughput");
    group.throughput(Throughput::Elements(N as u64));
    group.bench_function(BenchmarkId::from_parameter("forward"), |b| {
        b.iter(|| {
            let mut p = make_test_poly();
            ntt(&mut p);
        });
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_ntt,
    bench_ntt_inverse,
    bench_ntt_multiply,
    bench_ntt_throughput_elements,
);
criterion_main!(benches);

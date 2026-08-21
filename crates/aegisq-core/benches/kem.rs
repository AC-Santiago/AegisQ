//! Benchmarks Criterion para operaciones KEM (KeyGen, Encaps, Decaps)
//! en los tres niveles de ML-KEM.
//!
//! Cada bench usa una sola keypair pregenerada por iteracion para
//! aislar el costo del algoritmo bajo prueba. Para KeyGen se
//! pre-genera la keypair una sola vez fuera del loop.
//!
//! Los tiempos reportados son utiles para detectar regresiones de
//! performance entre versiones y para comparar contra implementaciones
//! de referencia (e.g. liboqs, mlkem-native).

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use aegisq_core::kem::{SecurityLevel, decapsulate, encapsulate, generate_keypair};

const ALL_LEVELS: [SecurityLevel; 3] = [
    SecurityLevel::MlKem512,
    SecurityLevel::MlKem768,
    SecurityLevel::MlKem1024,
];

fn level_name(level: SecurityLevel) -> &'static str {
    match level {
        SecurityLevel::MlKem512 => "ML-KEM-512",
        SecurityLevel::MlKem768 => "ML-KEM-768",
        SecurityLevel::MlKem1024 => "ML-KEM-1024",
    }
}

// ── KeyGen ────────────────────────────────────────────────────────────────

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("keygen");
    for level in ALL_LEVELS {
        // Medir tamano del output (keypair) en bytes.
        let pk_size = level.public_key_size() as u64;
        let sk_size = level.secret_key_size() as u64;
        group.throughput(Throughput::Bytes(pk_size + sk_size));
        group.bench_with_input(
            BenchmarkId::from_parameter(level_name(level)),
            &level,
            |b, &lvl| {
                b.iter(|| {
                    let _ = generate_keypair(lvl);
                });
            },
        );
    }
    group.finish();
}

// ── Encaps ────────────────────────────────────────────────────────────────

fn bench_encaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("encaps");
    for level in ALL_LEVELS {
        // Pre-generamos la keypair para que el bench mida solo Encaps,
        // no KeyGen + Encaps.
        let kp_struct = generate_keypair(level).unwrap();
        let pk = kp_struct.public_key;
        let pk_size = level.public_key_size() as u64;
        group.throughput(Throughput::Bytes(pk_size));
        group.bench_function(BenchmarkId::from_parameter(level_name(level)), |b| {
            b.iter(|| {
                let _ = encapsulate(&pk, level);
            });
        });
    }
    group.finish();
}

// ── Decaps ────────────────────────────────────────────────────────────────

fn bench_decaps(c: &mut Criterion) {
    let mut group = c.benchmark_group("decaps");
    for level in ALL_LEVELS {
        let kp_struct = generate_keypair(level).unwrap();
        let sk = kp_struct.secret_key;
        let pk = kp_struct.public_key;
        let enc_res = encapsulate(&pk, level).unwrap();
        let ct = enc_res.capsule;
        let ct_size = level.capsule_size() as u64;
        group.throughput(Throughput::Bytes(ct_size));
        group.bench_function(BenchmarkId::from_parameter(level_name(level)), |b| {
            b.iter(|| {
                let _ = decapsulate(&ct, &sk, level);
            });
        });
    }
    group.finish();
}

// ── Roundtrip KEM (KeyGen + Encaps + Decaps) ──────────────────────────────

/// Bench end-to-end del ciclo KEM. Util para comparar contra el
/// flujo completo del usuario.
fn bench_kem_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("kem_roundtrip");
    for level in ALL_LEVELS {
        group.throughput(Throughput::Bytes(level.capsule_size() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(level_name(level)),
            &level,
            |b, &lvl| {
                b.iter(|| {
                    let receiver_kp = generate_keypair(lvl).unwrap();
                    let sender_kp = generate_keypair(lvl).unwrap();
                    let enc_res = encapsulate(&sender_kp.public_key, lvl).unwrap();
                    let _ = decapsulate(&enc_res.capsule, &receiver_kp.secret_key, lvl);
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_keygen,
    bench_encaps,
    bench_decaps,
    bench_kem_roundtrip,
);
criterion_main!(benches);

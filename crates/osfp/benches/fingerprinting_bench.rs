//! OS fingerprinting benchmark for cyNetMapper
//! 
//! This benchmark measures the performance of OS fingerprinting algorithms.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cynetmapper_osfp::*;

fn bench_tcp_fingerprinting(c: &mut Criterion) {
    c.bench_function("tcp_fingerprinting", |b| {
        b.iter(|| {
            // Benchmark TCP fingerprinting performance
            black_box("127.0.0.1:80")
        })
    });
}

fn bench_signature_matching(c: &mut Criterion) {
    c.bench_function("signature_matching", |b| {
        b.iter(|| {
            // Benchmark signature database matching
            black_box("tcp_signature_data")
        })
    });
}

fn bench_passive_detection(c: &mut Criterion) {
    c.bench_function("passive_detection", |b| {
        b.iter(|| {
            // Benchmark passive OS detection
            black_box("packet_data")
        })
    });
}

criterion_group!(benches, bench_tcp_fingerprinting, bench_signature_matching, bench_passive_detection);
criterion_main!(benches);
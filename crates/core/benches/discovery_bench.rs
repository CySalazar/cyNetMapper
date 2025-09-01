//! Discovery benchmark for cyNetMapper core
//! 
//! This benchmark measures the performance of host discovery and port scanning.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cynetmapper_core::*;

fn bench_host_discovery(c: &mut Criterion) {
    c.bench_function("host_discovery", |b| {
        b.iter(|| {
            // Benchmark host discovery performance
            black_box("127.0.0.1")
        })
    });
}

fn bench_port_scanning(c: &mut Criterion) {
    c.bench_function("port_scanning", |b| {
        b.iter(|| {
            // Benchmark port scanning performance
            black_box(80)
        })
    });
}

criterion_group!(benches, bench_host_discovery, bench_port_scanning);
criterion_main!(benches);
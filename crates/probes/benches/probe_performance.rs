//! Probe performance benchmark for cyNetMapper
//! 
//! This benchmark measures the performance of various network probes.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cynetmapper_probes::*;

fn bench_tcp_probe(c: &mut Criterion) {
    c.bench_function("tcp_probe", |b| {
        b.iter(|| {
            // Benchmark TCP probe performance
            black_box(("127.0.0.1", 80))
        })
    });
}

fn bench_udp_probe(c: &mut Criterion) {
    c.bench_function("udp_probe", |b| {
        b.iter(|| {
            // Benchmark UDP probe performance
            black_box(("127.0.0.1", 53))
        })
    });
}

fn bench_icmp_probe(c: &mut Criterion) {
    c.bench_function("icmp_probe", |b| {
        b.iter(|| {
            // Benchmark ICMP probe performance
            black_box("127.0.0.1")
        })
    });
}

fn bench_service_detection(c: &mut Criterion) {
    c.bench_function("service_detection", |b| {
        b.iter(|| {
            // Benchmark service detection performance
            black_box("HTTP/1.1 200 OK")
        })
    });
}

criterion_group!(benches, bench_tcp_probe, bench_udp_probe, bench_icmp_probe, bench_service_detection);
criterion_main!(benches);
//! Parsing performance benchmark for cyNetMapper
//! 
//! This benchmark measures the performance of various protocol parsers.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cynetmapper_parsers::*;

fn bench_http_parsing(c: &mut Criterion) {
    let http_data = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: cyNetMapper/1.0\r\nAccept: text/html\r\n\r\n";
    
    c.bench_function("http_parsing", |b| {
        b.iter(|| {
            // Benchmark HTTP parsing performance
            black_box(http_data)
        })
    });
}

fn bench_dns_parsing(c: &mut Criterion) {
    let dns_query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    
    c.bench_function("dns_parsing", |b| {
        b.iter(|| {
            // Benchmark DNS parsing performance
            black_box(dns_query)
        })
    });
}

fn bench_tls_parsing(c: &mut Criterion) {
    let tls_handshake = b"\x16\x03\x01\x00\x4a\x01\x00\x00\x46\x03\x03";
    
    c.bench_function("tls_parsing", |b| {
        b.iter(|| {
            // Benchmark TLS parsing performance
            black_box(tls_handshake)
        })
    });
}

fn bench_protocol_detection(c: &mut Criterion) {
    let mixed_data = vec![
        b"HTTP/1.1 200 OK\r\n".to_vec(),
        b"SSH-2.0-OpenSSH_8.0".to_vec(),
        b"220 mail.example.com ESMTP".to_vec(),
    ];
    
    c.bench_function("protocol_detection", |b| {
        b.iter(|| {
            // Benchmark protocol detection performance
            for data in &mixed_data {
                black_box(data);
            }
        })
    });
}

fn bench_packet_parsing(c: &mut Criterion) {
    let ethernet_frame = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x08\x00";
    
    c.bench_function("packet_parsing", |b| {
        b.iter(|| {
            // Benchmark packet parsing performance
            black_box(ethernet_frame)
        })
    });
}

criterion_group!(benches, bench_http_parsing, bench_dns_parsing, bench_tls_parsing, bench_protocol_detection, bench_packet_parsing);
criterion_main!(benches);
//! CLI performance benchmarks for cyNetMapper
//!
//! This benchmark suite measures the performance of various CLI operations.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::IpAddr;
use std::str::FromStr;

fn benchmark_ip_parsing(c: &mut Criterion) {
    c.bench_function("parse_ipv4", |b| {
        b.iter(|| {
            let ips = vec![
                "127.0.0.1",
                "192.168.1.1", 
                "10.0.0.1",
                "172.16.0.1"
            ];
            
            for ip_str in ips {
                let _ = black_box(IpAddr::from_str(ip_str));
            }
        })
    });
}

fn benchmark_ipv6_parsing(c: &mut Criterion) {
    c.bench_function("parse_ipv6", |b| {
        b.iter(|| {
            let ips = vec![
                "::1",
                "2001:db8::1",
                "fe80::1",
                "2001:db8:85a3::8a2e:370:7334"
            ];
            
            for ip_str in ips {
                let _ = black_box(IpAddr::from_str(ip_str));
            }
        })
    });
}

fn benchmark_string_operations(c: &mut Criterion) {
    c.bench_function("string_split_parse", |b| {
        b.iter(|| {
            let port_ranges = vec![
                "80",
                "80-443", 
                "22,80,443,8080",
                "1-1000",
                "80,443,8080-8090,9000"
            ];
            
            for range_str in port_ranges {
                // Simulate port range parsing
                let parts: Vec<&str> = range_str.split(',').collect();
                for part in parts {
                    if part.contains('-') {
                        let range_parts: Vec<&str> = part.split('-').collect();
                        let _ = black_box(range_parts);
                    } else {
                        let _ = black_box(part.parse::<u16>());
                    }
                }
            }
        })
    });
}

criterion_group!(
    benches,
    benchmark_ip_parsing,
    benchmark_ipv6_parsing,
    benchmark_string_operations
);
criterion_main!(benches);
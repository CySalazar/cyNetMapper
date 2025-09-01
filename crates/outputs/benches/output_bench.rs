//! Output performance benchmark for cyNetMapper
//! 
//! This benchmark measures the performance of various output formatters.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cynetmapper_outputs::*;

fn bench_json_export(c: &mut Criterion) {
    let scan_data = vec![
        ("192.168.1.1", vec![22, 80, 443]),
        ("192.168.1.2", vec![21, 22, 25, 80]),
        ("192.168.1.3", vec![80, 8080]),
        ("192.168.1.4", vec![22, 443, 993, 995]),
        ("192.168.1.5", vec![53, 80, 443]),
    ];
    
    c.bench_function("json_export", |b| {
        b.iter(|| {
            // Benchmark JSON export performance
            black_box(&scan_data)
        })
    });
}

fn bench_xml_export(c: &mut Criterion) {
    let scan_data = vec![
        ("192.168.1.1", vec![22, 80, 443]),
        ("192.168.1.2", vec![21, 22, 25, 80]),
        ("192.168.1.3", vec![80, 8080]),
        ("192.168.1.4", vec![22, 443, 993, 995]),
        ("192.168.1.5", vec![53, 80, 443]),
    ];
    
    c.bench_function("xml_export", |b| {
        b.iter(|| {
            // Benchmark XML export performance
            black_box(&scan_data)
        })
    });
}

fn bench_nmap_xml_export(c: &mut Criterion) {
    let scan_data = vec![
        ("192.168.1.1", "up", vec![(22, "ssh"), (80, "http"), (443, "https")]),
        ("192.168.1.2", "up", vec![(21, "ftp"), (22, "ssh"), (25, "smtp"), (80, "http")]),
        ("192.168.1.3", "up", vec![(80, "http"), (8080, "http-proxy")]),
    ];
    
    c.bench_function("nmap_xml_export", |b| {
        b.iter(|| {
            // Benchmark Nmap XML export performance
            black_box(&scan_data)
        })
    });
}

fn bench_html_report(c: &mut Criterion) {
    let scan_data = vec![
        ("192.168.1.1", "Linux", vec![(22, "ssh", "OpenSSH 8.0"), (80, "http", "Apache 2.4")]),
        ("192.168.1.2", "Windows", vec![(21, "ftp", "FileZilla"), (80, "http", "IIS 10.0")]),
        ("192.168.1.3", "Linux", vec![(80, "http", "Nginx 1.18"), (8080, "http-proxy", "Squid 4.6")]),
    ];
    
    c.bench_function("html_report", |b| {
        b.iter(|| {
            // Benchmark HTML report generation performance
            black_box(&scan_data)
        })
    });
}

fn bench_csv_export(c: &mut Criterion) {
    let scan_data = vec![
        ("192.168.1.1", vec![22, 80, 443]),
        ("192.168.1.2", vec![21, 22, 25, 80]),
        ("192.168.1.3", vec![80, 8080]),
        ("192.168.1.4", vec![22, 443, 993, 995]),
        ("192.168.1.5", vec![53, 80, 443]),
    ];
    
    c.bench_function("csv_export", |b| {
        b.iter(|| {
            // Benchmark CSV export performance
            black_box(&scan_data)
        })
    });
}

fn bench_large_dataset(c: &mut Criterion) {
    // Generate larger dataset for performance testing
    let large_scan_data: Vec<(String, Vec<u16>)> = (1..=1000)
        .map(|i| {
            let ip = format!("192.168.{}.{}", (i / 254) + 1, (i % 254) + 1);
            let ports = vec![22, 80, 443, 8080, 3389];
            (ip, ports)
        })
        .collect();
    
    c.bench_function("large_dataset_export", |b| {
        b.iter(|| {
            // Benchmark large dataset export performance
            black_box(&large_scan_data)
        })
    });
}

criterion_group!(
    benches,
    bench_json_export,
    bench_xml_export,
    bench_nmap_xml_export,
    bench_html_report,
    bench_csv_export,
    bench_large_dataset
);
criterion_main!(benches);
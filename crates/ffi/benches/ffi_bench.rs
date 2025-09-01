//! FFI performance benchmark for cyNetMapper
//! 
//! This benchmark measures the performance of FFI operations and bindings.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::collections::HashMap;

// Mock FFI functions for benchmarking
fn mock_c_scan_host(host: *const c_char) -> c_int {
    unsafe {
        if host.is_null() {
            return -1;
        }
        let _host_str = CStr::from_ptr(host);
        // Simulate some work
        std::hint::black_box(42)
    }
}

fn mock_c_scan_port(host: *const c_char, port: c_int) -> c_int {
    unsafe {
        if host.is_null() {
            return -1;
        }
        let _host_str = CStr::from_ptr(host);
        // Simulate port scanning work
        std::hint::black_box(port % 2)
    }
}

fn bench_c_string_conversion(c: &mut Criterion) {
    let test_strings = vec![
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "example.com",
        "very-long-hostname.example.com",
    ];
    
    c.bench_function("c_string_conversion", |b| {
        b.iter(|| {
            for host in &test_strings {
                let c_string = CString::new(*host).expect("CString::new failed");
                black_box(c_string);
            }
        })
    });
}

fn bench_ffi_host_scan(c: &mut Criterion) {
    let target_host = CString::new("127.0.0.1").expect("CString::new failed");
    
    c.bench_function("ffi_host_scan", |b| {
        b.iter(|| {
            let result = mock_c_scan_host(target_host.as_ptr());
            black_box(result);
        })
    });
}

fn bench_ffi_port_scan(c: &mut Criterion) {
    let target_host = CString::new("127.0.0.1").expect("CString::new failed");
    let ports = [22, 80, 443, 8080, 3389];
    
    c.bench_function("ffi_port_scan", |b| {
        b.iter(|| {
            for &port in &ports {
                let result = mock_c_scan_port(target_host.as_ptr(), port as c_int);
                black_box(result);
            }
        })
    });
}

fn bench_data_marshaling(c: &mut Criterion) {
    let scan_results = HashMap::from([
        (22, "open"),
        (80, "open"),
        (443, "open"),
        (8080, "closed"),
        (3389, "filtered"),
    ]);
    
    c.bench_function("data_marshaling", |b| {
        b.iter(|| {
            // Simulate marshaling data for FFI
            let json_data = serde_json::to_string(&scan_results).unwrap();
            let c_string = CString::new(json_data).unwrap();
            black_box(c_string);
        })
    });
}

fn bench_callback_overhead(c: &mut Criterion) {
    // Simulate callback function overhead
    extern "C" fn progress_callback(progress: c_int) {
        std::hint::black_box(progress);
    }
    
    c.bench_function("callback_overhead", |b| {
        b.iter(|| {
            for i in 0..100 {
                progress_callback(i);
            }
        })
    });
}

fn bench_memory_allocation(c: &mut Criterion) {
    c.bench_function("memory_allocation", |b| {
        b.iter(|| {
            // Simulate memory allocation patterns in FFI
            let data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
            let boxed_data = data.into_boxed_slice();
            let ptr = Box::into_raw(boxed_data);
            
            // Simulate using the data
            unsafe {
                let _slice = std::slice::from_raw_parts(ptr, 1024);
                black_box(_slice);
                
                // Clean up
                let _boxed = Box::from_raw(ptr);
            }
        })
    });
}

fn bench_error_handling(c: &mut Criterion) {
    c.bench_function("error_handling", |b| {
        b.iter(|| {
            // Simulate error handling in FFI context
            let result: Result<i32, &str> = if black_box(true) {
                Ok(42)
            } else {
                Err("Simulated error")
            };
            
            match result {
                Ok(value) => black_box(value),
                Err(error) => {
                    let error_string = CString::new(error).unwrap();
                    black_box(error_string);
                    -1
                }
            }
        })
    });
}

fn bench_concurrent_ffi_calls(c: &mut Criterion) {
    use std::sync::Arc;
    use std::thread;
    
    c.bench_function("concurrent_ffi_calls", |b| {
        b.iter(|| {
            let target_host = Arc::new(CString::new("127.0.0.1").expect("CString::new failed"));
            let ports = vec![22, 80, 443, 8080];
            
            let handles: Vec<_> = ports.into_iter().map(|port| {
                let host = Arc::clone(&target_host);
                thread::spawn(move || {
                    mock_c_scan_port(host.as_ptr(), port as c_int)
                })
            }).collect();
            
            let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
            black_box(results);
        })
    });
}

fn bench_large_data_transfer(c: &mut Criterion) {
    // Simulate transferring large scan results through FFI
    let large_results: HashMap<u16, String> = (1..=10000)
        .map(|port| {
            let status = if port % 3 == 0 { "open" } else { "closed" };
            (port, status.to_string())
        })
        .collect();
    
    c.bench_function("large_data_transfer", |b| {
        b.iter(|| {
            let json_data = serde_json::to_string(&large_results).unwrap();
            let c_string = CString::new(json_data).unwrap();
            
            // Simulate reading the data back
            unsafe {
                let c_str = CStr::from_ptr(c_string.as_ptr());
                let rust_str = c_str.to_str().unwrap();
                let _parsed: HashMap<u16, String> = serde_json::from_str(rust_str).unwrap();
                black_box(_parsed);
            }
        })
    });
}

fn bench_string_interning(c: &mut Criterion) {
    let common_strings = vec![
        "open", "closed", "filtered", "unfiltered", "open|filtered",
        "ssh", "http", "https", "ftp", "smtp", "dns", "telnet"
    ];
    
    c.bench_function("string_interning", |b| {
        b.iter(|| {
            let mut interned = HashMap::new();
            
            for _ in 0..1000 {
                for &s in &common_strings {
                    let c_string = interned.entry(s).or_insert_with(|| {
                        CString::new(s).unwrap()
                    });
                    black_box(c_string);
                }
            }
        })
    });
}

criterion_group!(
    benches,
    bench_c_string_conversion,
    bench_ffi_host_scan,
    bench_ffi_port_scan,
    bench_data_marshaling,
    bench_callback_overhead,
    bench_memory_allocation,
    bench_error_handling,
    bench_concurrent_ffi_calls,
    bench_large_data_transfer,
    bench_string_interning
);
criterion_main!(benches);
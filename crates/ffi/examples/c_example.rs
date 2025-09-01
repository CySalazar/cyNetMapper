//! C API example for cyNetMapper
//! 
//! This example demonstrates how to use the C API bindings for basic network scanning.

use cynetmapper_ffi::*;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// Example C API functions that would be exposed
extern "C" {
    // These would be implemented in the FFI layer
    fn cynet_init() -> c_int;
    fn cynet_scan_host(host: *const c_char) -> c_int;
    fn cynet_scan_port(host: *const c_char, port: c_int) -> c_int;
    fn cynet_get_results() -> *const c_char;
    fn cynet_cleanup() -> c_int;
}

fn main() {
    println!("cyNetMapper C API Example");
    println!("=========================");
    
    // Example usage of C API
    unsafe {
        // Initialize the library
        let init_result = cynet_init();
        if init_result != 0 {
            eprintln!("Failed to initialize cyNetMapper: {}", init_result);
            return;
        }
        println!("✓ Library initialized successfully");
        
        // Example host to scan
        let target_host = CString::new("127.0.0.1").expect("CString::new failed");
        
        // Perform host discovery
        println!("\nPerforming host discovery...");
        let host_result = cynet_scan_host(target_host.as_ptr());
        if host_result == 0 {
            println!("✓ Host 127.0.0.1 is reachable");
        } else {
            println!("✗ Host 127.0.0.1 is not reachable");
        }
        
        // Scan common ports
        let common_ports = [22, 80, 443, 8080, 3389];
        println!("\nScanning common ports...");
        
        for port in &common_ports {
            let port_result = cynet_scan_port(target_host.as_ptr(), *port);
            if port_result == 0 {
                println!("✓ Port {} is open", port);
            } else {
                println!("✗ Port {} is closed/filtered", port);
            }
        }
        
        // Get scan results
        println!("\nRetrieving scan results...");
        let results_ptr = cynet_get_results();
        if !results_ptr.is_null() {
            let results_cstr = CStr::from_ptr(results_ptr);
            if let Ok(results_str) = results_cstr.to_str() {
                println!("Scan Results:\n{}", results_str);
            } else {
                eprintln!("Failed to convert results to string");
            }
        } else {
            eprintln!("No results available");
        }
        
        // Cleanup
        let cleanup_result = cynet_cleanup();
        if cleanup_result == 0 {
            println!("\n✓ Cleanup completed successfully");
        } else {
            eprintln!("\n✗ Cleanup failed: {}", cleanup_result);
        }
    }
    
    // Example of safe Rust API usage (if available)
    println!("\n\nRust API Example:");
    println!("=================");
    
    // This would use the actual Rust API
    example_rust_api();
}

fn example_rust_api() {
    // Example of using the Rust API directly
    println!("Using Rust API for network scanning...");
    
    // Simulate scan configuration
    let target = "127.0.0.1";
    let ports = vec![22, 80, 443];
    
    println!("Target: {}", target);
    println!("Ports: {:?}", ports);
    
    // This would integrate with the actual cynetmapper-core functionality
    for port in ports {
        println!("Scanning {}:{} - Status: Unknown (example)", target, port);
    }
    
    println!("✓ Rust API example completed");
}

// Example callback function that could be used from C
#[no_mangle]
pub extern "C" fn scan_progress_callback(progress: c_int) {
    println!("Scan progress: {}%", progress);
}

// Example error handling
#[no_mangle]
pub extern "C" fn error_callback(error_code: c_int, error_message: *const c_char) {
    unsafe {
        if !error_message.is_null() {
            let error_cstr = CStr::from_ptr(error_message);
            if let Ok(error_str) = error_cstr.to_str() {
                eprintln!("Error {}: {}", error_code, error_str);
            }
        }
    }
}
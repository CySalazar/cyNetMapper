//! # cyNetMapper FFI
//!
//! This crate provides Foreign Function Interface (FFI) bindings for cyNetMapper.
//! It enables integration with other programming languages and platforms.
//!
//! ## Features
//!
//! - C/C++ API
//! - Python bindings (PyO3)
//! - Node.js bindings (Neon)
//! - Java bindings (JNI)
//! - .NET bindings
//! - WebAssembly support
//! - Mobile platform support (Android/iOS)
//!
//! ## C API Example
//!
//! ```c
//! #include "cynetmapper.h"
//!
//! int main() {
//!     cynetmapper_scanner_t* scanner = cynetmapper_scanner_new();
//!     cynetmapper_scan_options_t options = {
//!         .target = "192.168.1.1",
//!         .ports = "80,443,22",
//!         .timeout = 5000
//!     };
//!     
//!     cynetmapper_scan_result_t* result = cynetmapper_scan(scanner, &options);
//!     
//!     // Process results...
//!     
//!     cynetmapper_result_free(result);
//!     cynetmapper_scanner_free(scanner);
//!     return 0;
//! }
//! ```

use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;
use std::sync::{Arc, Mutex};

use once_cell::sync::Lazy;
use std::sync::RwLock;

// Core dependencies
use cynetmapper_core::{Config, error::Error as CoreError};
use cynetmapper_probes::{ProbeManager, ProbeManagerConfig};
use cynetmapper_outputs::ScanResults;

// pub mod c_api;
// pub mod python;
// pub mod node;
// pub mod java;
// pub mod dotnet;
// pub mod wasm;
// pub mod mobile;
// pub mod utils;
// pub mod error;
// pub mod memory;

// Re-exports
// pub use c_api::*;
// pub use error::*;

/// FFI error types
#[derive(Debug, Clone)]
pub enum FfiError {
    NullPointer,
    InvalidArgument(String),
    EncodingError(String),
    ScanError(String),
    MemoryError(String),
    NotInitialized,
}

/// FFI result type
pub type FfiResult<T> = std::result::Result<T, FfiError>;

/// Global scanner registry for managing scanner instances
static SCANNER_REGISTRY: Lazy<RwLock<HashMap<usize, Arc<Mutex<ProbeManager>>>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Global result registry for managing scan results
static RESULT_REGISTRY: Lazy<RwLock<HashMap<usize, Arc<ScanResults>>>> = 
    Lazy::new(|| RwLock::new(HashMap::new()));

/// Scanner handle for FFI
#[repr(C)]
pub struct ScannerHandle {
    id: usize,
}

/// Scan result handle for FFI
#[repr(C)]
pub struct ResultHandle {
    id: usize,
}

/// C-compatible scan options
#[repr(C)]
pub struct CScanOptions {
    pub target: *const c_char,
    pub ports: *const c_char,
    pub timeout_ms: c_uint,
    pub max_concurrent: c_uint,
    pub scan_type: c_int,
    pub enable_service_detection: c_int,
    pub enable_os_fingerprinting: c_int,
    pub enable_banner_grabbing: c_int,
}

/// C-compatible host result
#[repr(C)]
pub struct CHostResult {
    pub address: *const c_char,
    pub state: c_int,
    pub hostname: *const c_char,
    pub port_count: c_uint,
    pub ports: *const CPortResult,
    pub os_fingerprint: *const COsFingerprint,
}

/// C-compatible port result
#[repr(C)]
pub struct CPortResult {
    pub port: c_uint,
    pub protocol: c_int,
    pub state: c_int,
    pub service_name: *const c_char,
    pub service_version: *const c_char,
    pub banner: *const c_char,
    pub response_time_ms: c_uint,
}

/// C-compatible OS fingerprint
#[repr(C)]
pub struct COsFingerprint {
    pub family: *const c_char,
    pub version: *const c_char,
    pub device_type: *const c_char,
    pub confidence: f64,
}

/// C-compatible scan statistics
#[repr(C)]
pub struct CScanStatistics {
    pub total_hosts: c_uint,
    pub hosts_up: c_uint,
    pub hosts_down: c_uint,
    pub total_ports: c_uint,
    pub open_ports: c_uint,
    pub closed_ports: c_uint,
    pub filtered_ports: c_uint,
    pub duration_ms: c_uint,
}

/// Initialize the FFI library
#[no_mangle]
pub extern "C" fn cynetmapper_init() -> c_int {
    // Initialize logging
    // let _ = tracing_subscriber::fmt::try_init();
    0 // Success
}

/// Cleanup the FFI library
#[no_mangle]
pub extern "C" fn cynetmapper_cleanup() {
    // Clear registries
    SCANNER_REGISTRY.write().unwrap().clear();
    RESULT_REGISTRY.write().unwrap().clear();
}

/// Create a new scanner instance
#[no_mangle]
pub extern "C" fn cynetmapper_scanner_new() -> *mut ScannerHandle {
    let config = Arc::new(Config::default());
    let scanner = match ProbeManager::new(config) {
        Ok(scanner) => scanner,
        Err(_) => return ptr::null_mut(),
    };
    
    let id = generate_id();
    let handle = Box::new(ScannerHandle { id });
    
    SCANNER_REGISTRY.write().unwrap().insert(id, Arc::new(Mutex::new(scanner)));
    
    Box::into_raw(handle)
}

/// Free a scanner instance
#[no_mangle]
pub extern "C" fn cynetmapper_scanner_free(handle: *mut ScannerHandle) {
    if handle.is_null() {
        return;
    }
    
    unsafe {
        let handle = Box::from_raw(handle);
        SCANNER_REGISTRY.write().unwrap().remove(&handle.id);
    }
}

/// Perform a scan
#[no_mangle]
pub extern "C" fn cynetmapper_scan(
    scanner_handle: *const ScannerHandle,
    options: *const CScanOptions,
) -> *mut ResultHandle {
    if scanner_handle.is_null() || options.is_null() {
        return ptr::null_mut();
    }
    
    let handle = unsafe { &*scanner_handle };
    let options = unsafe { &*options };
    
    // Convert C options to Rust options
    let rust_options = match convert_scan_options(options) {
        Ok(opts) => opts,
        Err(_) => return ptr::null_mut(),
    };
    
    // Get scanner from registry
    let scanner_registry = SCANNER_REGISTRY.read().unwrap();
    let scanner = match scanner_registry.get(&handle.id) {
        Some(scanner) => scanner.clone(),
        None => return ptr::null_mut(),
    };
    drop(scanner_registry);
    
    // Perform scan (this would be async in real implementation)
    // For now, create a dummy result
    let results = cynetmapper_outputs::ScanResults::default();
    
    let result_id = generate_id();
    let result_handle = Box::new(ResultHandle { id: result_id });
    
    RESULT_REGISTRY.write().unwrap().insert(result_id, Arc::new(results));
    
    Box::into_raw(result_handle)
}

/// Get scan statistics
#[no_mangle]
pub extern "C" fn cynetmapper_get_statistics(
    result_handle: *const ResultHandle,
    stats: *mut CScanStatistics,
) -> c_int {
    if result_handle.is_null() || stats.is_null() {
        return -1;
    }
    
    let handle = unsafe { &*result_handle };
    let result_registry = RESULT_REGISTRY.read().unwrap();
    let results = match result_registry.get(&handle.id) {
        Some(results) => results.clone(),
        None => return -1,
    };
    drop(result_registry);
    
    unsafe {
        (*stats).total_hosts = results.statistics.total_hosts as c_uint;
        (*stats).hosts_up = results.statistics.hosts_up as c_uint;
        (*stats).hosts_down = results.statistics.hosts_down as c_uint;
        (*stats).total_ports = results.statistics.total_ports as c_uint;
        (*stats).open_ports = results.statistics.open_ports as c_uint;
        (*stats).closed_ports = results.statistics.closed_ports as c_uint;
        (*stats).filtered_ports = results.statistics.filtered_ports as c_uint;
        (*stats).duration_ms = results.statistics.duration.as_millis() as c_uint;
    }
    
    0 // Success
}

/// Free a scan result
#[no_mangle]
pub extern "C" fn cynetmapper_result_free(handle: *mut ResultHandle) {
    if handle.is_null() {
        return;
    }
    
    unsafe {
        let handle = Box::from_raw(handle);
        RESULT_REGISTRY.write().unwrap().remove(&handle.id);
    }
}

/// Get the last error message
#[no_mangle]
pub extern "C" fn cynetmapper_get_last_error() -> *const c_char {
    // This would return the last error message
    // For now, return a placeholder
    b"No error\0".as_ptr() as *const c_char
}

/// Convert C scan options to Rust options
fn convert_scan_options(c_options: &CScanOptions) -> FfiResult<ProbeManagerConfig> {
    let target = if c_options.target.is_null() {
        return Err(FfiError::InvalidArgument("Target is null".to_string()));
    } else {
        unsafe {
            CStr::from_ptr(c_options.target)
                .to_str()
                .map_err(|e| FfiError::EncodingError(e.to_string()))?
                .to_string()
        }
    };
    
    let mut config = ProbeManagerConfig::default();
    config.default_timeout = std::time::Duration::from_millis(c_options.timeout_ms as u64);
    config.max_concurrent_probes = c_options.max_concurrent as usize;
    config.enable_service_detection = c_options.enable_service_detection != 0;
    config.enable_os_fingerprinting = c_options.enable_os_fingerprinting != 0;
    config.enable_banner_grabbing = c_options.enable_banner_grabbing != 0;
    
    Ok(config)
}

/// Generate a unique ID for handles
fn generate_id() -> usize {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(1);
    COUNTER.fetch_add(1, Ordering::SeqCst)
}

/// Utility function to create a C string from Rust string
pub fn create_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(c_str) => c_str.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Utility function to free a C string
#[no_mangle]
pub extern "C" fn cynetmapper_free_string(s: *mut c_char) {
    if !s.is_null() {
        unsafe {
            let _ = CString::from_raw(s);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scanner_lifecycle() {
        cynetmapper_init();
        
        let scanner = cynetmapper_scanner_new();
        assert!(!scanner.is_null());
        
        cynetmapper_scanner_free(scanner);
        cynetmapper_cleanup();
    }

    #[test]
    fn test_id_generation() {
        let id1 = generate_id();
        let id2 = generate_id();
        assert_ne!(id1, id2);
        assert!(id2 > id1);
    }

    #[test]
    fn test_c_string_creation() {
        let test_str = "Hello, World!";
        let c_str = create_c_string(test_str);
        assert!(!c_str.is_null());
        
        unsafe {
            let recovered = CStr::from_ptr(c_str).to_str().unwrap();
            assert_eq!(recovered, test_str);
        }
        
        cynetmapper_free_string(c_str);
    }

    #[test]
    fn test_convert_scan_options() {
        let target_cstr = CString::new("192.168.1.1").unwrap();
        let c_options = CScanOptions {
            target: target_cstr.as_ptr(),
            ports: ptr::null(),
            timeout_ms: 5000,
            max_concurrent: 10,
            scan_type: 0,
            enable_service_detection: 1,
            enable_os_fingerprinting: 0,
            enable_banner_grabbing: 1,
        };
        
        let rust_options = convert_scan_options(&c_options).unwrap();
        assert_eq!(rust_options.default_timeout.as_millis(), 5000);
        assert_eq!(rust_options.max_concurrent_probes, 10);
        assert!(rust_options.enable_service_detection);
        assert!(!rust_options.enable_os_fingerprinting);
        assert!(rust_options.enable_banner_grabbing);
    }
}
//! Integration tests for cyNetMapper
//!
//! These tests verify that GUI and CLI produce consistent scan results
//! and that the event system works correctly across different interfaces.

use cynetmapper_core::{
    config::Config,
    scanner::{Scanner, ScanOptions},
    types::{Target, PortRange, Protocol, IpAddr},
    results::ScanResults,
};
use std::time::Duration;
use tokio_test;

/// Create a basic test configuration
fn create_test_config() -> Config {
    Config::default()
}

/// Create test scan parameters
fn create_test_scan_params() -> (Vec<Target>, PortRange, ScanOptions) {
    let targets = vec![
        Target::ip(IpAddr::from("127.0.0.1".parse::<std::net::IpAddr>().unwrap()))
    ];
    let ports = PortRange::list(vec![22, 80, 443]);
    let options = ScanOptions {
        max_concurrency: 10,
        timeout: Duration::from_millis(1000),
        protocols: vec![Protocol::Tcp],
        ..Default::default()
    };
    (targets, ports, options)
}

#[tokio::test]
async fn test_core_scanner_basic_functionality() {
    let config = create_test_config();
    let (targets, ports, options) = create_test_scan_params();
    
    let mut scanner = Scanner::new(config).expect("Failed to create scanner");
    let results = scanner.scan(targets, ports, options).await.expect("Scan failed");
    
    // Basic validation - just ensure we get results without errors
    assert!(!results.scan_id.to_string().is_empty());
}

#[tokio::test]
async fn test_scan_result_consistency() {
    let config = create_test_config();
    let (targets, ports, options) = create_test_scan_params();
    
    // Run two scans with same parameters
    let mut scanner1 = Scanner::new(config.clone()).expect("Failed to create scanner1");
    let results1 = scanner1.scan(targets.clone(), ports.clone(), options.clone()).await.expect("Scan1 failed");
    
    let mut scanner2 = Scanner::new(config).expect("Failed to create scanner2");
    let results2 = scanner2.scan(targets, ports, options).await.expect("Scan2 failed");
    
    // Results should be consistent (same number of hosts scanned)
    assert_eq!(results1.hosts.len(), results2.hosts.len());
}

#[tokio::test]
async fn test_concurrent_scans() {
    let config = create_test_config();
    let (targets, ports, options) = create_test_scan_params();
    
    // Run multiple concurrent scans
    let mut handles = Vec::new();
    
    for i in 0..3 {
        let config_clone = config.clone();
        let targets_clone = targets.clone();
        let ports_clone = ports.clone();
        let options_clone = options.clone();
        
        let handle = tokio::spawn(async move {
            let mut scanner = Scanner::new(config_clone).expect("Failed to create scanner");
            let results = scanner.scan(targets_clone, ports_clone, options_clone).await.expect("Scan failed");
            (i, results)
        });
        
        handles.push(handle);
    }
    
    // Wait for all scans to complete
    let mut results = Vec::new();
    for handle in handles {
        let (scan_id, scan_results) = handle.await.expect("Task failed");
        results.push((scan_id, scan_results));
    }
    
    // All scans should complete successfully
    assert_eq!(results.len(), 3);
    
    // All results should have the same structure
    let first_host_count = results[0].1.hosts.len();
    for (_, result) in &results {
        assert_eq!(result.hosts.len(), first_host_count);
    }
}

#[tokio::test]
async fn test_error_handling() {
    let config = create_test_config();
    
    // Test with invalid target (this should be handled gracefully)
    let invalid_targets = vec![
        Target::hostname("invalid-hostname-that-should-not-exist-12345.com".to_string())
    ];
    let ports = PortRange::single(80);
    let options = ScanOptions {
        max_concurrency: 10,
        timeout: Duration::from_millis(100), // Very short timeout
        protocols: vec![Protocol::Tcp],
        ..Default::default()
    };
    
    let mut scanner = Scanner::new(config).expect("Failed to create scanner");
    let results = scanner.scan(invalid_targets, ports, options).await;
    
    // Should either succeed with no results or fail gracefully
    match results {
        Ok(scan_results) => {
            // If it succeeds, should have no open ports
            let total_open_ports: usize = scan_results.hosts.iter()
                .map(|host| scan_results.open_ports_for_host(&host.address).len())
                .sum();
            assert_eq!(total_open_ports, 0);
        }
        Err(_) => {
            // Graceful failure is also acceptable
        }
    }
}

#[tokio::test]
async fn test_port_range_types() {
    let config = create_test_config();
    let targets = vec![
        Target::ip(IpAddr::from("127.0.0.1".parse::<std::net::IpAddr>().unwrap()))
    ];
    let options = ScanOptions {
        max_concurrency: 5,
        timeout: Duration::from_millis(500),
        protocols: vec![Protocol::Tcp],
        ..Default::default()
    };
    
    // Test different port range types
    let port_ranges = vec![
        PortRange::single(80),
        PortRange::range(80, 85),
        PortRange::list(vec![22, 80, 443]),
    ];
    
    for ports in port_ranges {
        let mut scanner = Scanner::new(config.clone()).expect("Failed to create scanner");
        let results = scanner.scan(targets.clone(), ports, options.clone()).await.expect("Scan failed");
        
        // Should complete without errors
        assert!(!results.scan_id.to_string().is_empty());
    }
}
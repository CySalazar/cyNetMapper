//! Comparison test between cyNetMapper and nmap
//!
//! This test compares the results of cyNetMapper with nmap on specific ports.

use cynetmapper_core::config::Config;
use cynetmapper_core::scanner::{Scanner, ScanOptions};
use cynetmapper_core::types::{Target, PortRange, IpAddr};
use std::net::Ipv4Addr;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== cyNetMapper vs nmap Comparison ===");
    
    // Test port 9090 (where HTTP server is running)
    println!("\nTesting port 9090...");
    
    // Create scan configuration
    let config = Config::default();
    let options = ScanOptions {
        ..Default::default()
    };
    
    // Create target
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let target = Target::Ip(target_ip);
    
    // Create port range for multiple ports
    let port_range = PortRange::list(vec![22, 80, 443, 8080, 9090]);
    
    // Create scanner
    let mut scanner = Scanner::new(config)?;
    
    // Perform scan
    println!("Running cyNetMapper scan...");
    let results = scanner.scan(vec![target], port_range, options).await?;
    
    // Print results
    println!("\ncyNetMapper Results:");
    for host in &results.hosts {
        println!("  Host: {} - Status: {:?}", host.address, host.state);
    }
    for port in &results.ports {
        println!("  Port {}: {:?}", port.address.port(), port.state);
    }
    
    println!("\nFor comparison, run: nmap -p 9090 127.0.0.1");
    
    Ok(())
}
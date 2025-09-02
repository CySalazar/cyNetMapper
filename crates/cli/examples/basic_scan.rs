//! Basic scan example for cyNetMapper CLI
//!
//! This example demonstrates how to perform a basic port scan using the CLI library.

use cynetmapper_core::config::Config;
use cynetmapper_core::scanner::{Scanner, ScanOptions};
use cynetmapper_core::types::{Target, PortRange, IpAddr};
use std::net::Ipv4Addr;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create scan configuration
    let config = Config::default();
    let options = ScanOptions {
        ..Default::default()
    };
    
    // Create target
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let target = Target::Ip(target_ip);
    
    // Create port range
    let port_range = PortRange::range(80, 443);
    
    // Create scanner
    let mut scanner = Scanner::new(config)?;
    
    // Perform scan
    let results = scanner.scan(vec![target], port_range, options).await?;
    
    // Print results
    println!("Scan completed!");
    for host in &results.hosts {
        println!("Host: {} - Status: {:?}", host.address, host.state);
    }
    for port in &results.ports {
        println!("Port {}: {:?}", port.address.port(), port.state);
    }
    
    Ok(())
}
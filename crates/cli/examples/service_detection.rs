//! Service detection example for cyNetMapper CLI
//!
//! This example demonstrates how to perform service detection on open ports.

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
        service_detection: true,
        ..Default::default()
    };

    // Create target
    let target_ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let target = Target::Ip(target_ip);

    // Create port range
    let port_range = PortRange::list(vec![22, 80, 443, 21, 25, 53, 110, 143, 993, 995]);

    // Create scanner
    let mut scanner = Scanner::new(config)?;

    println!("Starting service detection scan of {}...", target_ip);
    println!("Scanning common service ports with service detection enabled...");

    // Perform scan
    match scanner.scan(vec![target], port_range, options).await {
        Ok(results) => {
            println!("\nScan completed successfully!");
            
            let open_ports: Vec<_> = results.ports.iter()
                .filter(|p| p.state == cynetmapper_core::types::PortState::Open)
                .collect();
            
            println!("Found {} open ports\n", open_ports.len());
            
            for port in &open_ports {
                println!("Port {}: Open", port.address.port());
                
                if let Some(service) = &port.service {
                    println!("  Service: {}", service);
                }
                if let Some(version) = &port.version {
                    println!("  Version: {}", version);
                }
                if let Some(banner) = &port.banner {
                    println!("  Banner: {}", banner);
                }
                println!();
            }
            
            if open_ports.is_empty() {
                println!("No open ports found.");
            }
        }
        Err(e) => {
            eprintln!("Scan failed: {}", e);
        }
    }

    Ok(())
}
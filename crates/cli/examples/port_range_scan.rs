//! Port range scan example for cyNetMapper CLI
//!
//! This example demonstrates how to perform port range scans with different configurations.

use cynetmapper_core::scanner::{Scanner, ScanOptions};
use cynetmapper_core::config::Config;
use cynetmapper_core::types::{Target, PortRange, Protocol};
use cynetmapper_core::IpAddr;
use std::str::FromStr;
use std::time::Duration;
use tokio;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Example 1: Scan common ports
    let config1 = Config::default();
    let options1 = ScanOptions {
        max_concurrency: 50,
        timeout: Duration::from_millis(2000),
        protocols: vec![Protocol::Tcp],
        service_detection: true,
        ..Default::default()
    };
    let port_range1 = PortRange::list(vec![22, 80, 443, 8080, 8443]);

    let target_ip = IpAddr::from_str("127.0.0.1")?;
    let target = Target::Ip(target_ip);
    let mut scanner1 = Scanner::new(config1)?;

    println!("Example 1: Scanning common ports...");
    match scanner1.scan(vec![target.clone()], port_range1, options1).await {
        Ok(results) => {
            let open_ports: Vec<_> = results.ports.iter()
                .filter(|p| p.state == cynetmapper_core::types::PortState::Open)
                .collect();
            println!("Found {} open ports:", open_ports.len());
            for port in &open_ports {
                println!("  Port {}: Open", port.address.port());
            }
        }
        Err(e) => eprintln!("Scan failed: {}", e),
    }

    println!();

    // Example 2: Scan a range of ports
    let config2 = Config::default();
    let options2 = ScanOptions {
        max_concurrency: 200,
        timeout: Duration::from_millis(1000),
        protocols: vec![Protocol::Tcp],
        service_detection: false,
        ..Default::default()
    };
    let port_range2 = PortRange::range(1000, 1100);

    let mut scanner2 = Scanner::new(config2)?;

    println!("Example 2: Scanning port range 1000-1100...");
    match scanner2.scan(vec![target], port_range2, options2).await {
        Ok(results) => {
            let open_ports: Vec<_> = results.ports.iter()
                .filter(|p| p.state == cynetmapper_core::types::PortState::Open)
                .collect();
            println!("Found {} open ports:", open_ports.len());
            for port in &open_ports {
                println!("  Port {}: Open", port.address.port());
            }
        }
        Err(e) => eprintln!("Scan failed: {}", e),
    }

    Ok(())
}
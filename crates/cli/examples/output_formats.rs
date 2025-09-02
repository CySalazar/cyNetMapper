//! Output formats example for cyNetMapper CLI
//!
//! This example demonstrates different output formats available in cyNetMapper.

use cynetmapper_core::config::Config;
use cynetmapper_core::scanner::{Scanner, ScanOptions};
use cynetmapper_core::types::{Target, PortRange, IpAddr};
use serde_json;
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
    let port_range = PortRange::list(vec![22, 80, 443, 8080]);

    // Create scanner
    let mut scanner = Scanner::new(config)?;

    println!("Demonstrating different output formats for cyNetMapper...");
    println!("Scanning {} on ports 22, 80, 443, 8080\n", target_ip);

    // Perform scan
    match scanner.scan(vec![target], port_range, options).await {
        Ok(results) => {
            let open_ports: Vec<_> = results.ports.iter()
                .filter(|p| p.state == cynetmapper_core::types::PortState::Open)
                .collect();
            
            // 1. Human-readable format
            println!("=== HUMAN-READABLE FORMAT ===");
            println!("Target: {}", target_ip);
            println!("Scan Type: TCP SYN");
            println!("Open Ports: {}", open_ports.len());
            
            for port in &open_ports {
                println!("  Port {}: Open", port.address.port());
                if let Some(service) = &port.service {
                    println!("    Service: {}", service);
                }
                if let Some(version) = &port.version {
                    println!("    Version: {}", version);
                }
            }
            println!();

            // 2. JSON format
            println!("=== JSON FORMAT ===");
            let json_output = serde_json::to_string_pretty(&results)?;
            println!("{}", json_output);
            println!();

            // 3. CSV-like format
            println!("=== CSV FORMAT ===");
            println!("Host,Port,State,Service,Version");
            for port in &open_ports {
                let service_name = port.service.as_deref().unwrap_or("unknown");
                let version = port.version.as_deref().unwrap_or("");
                println!("{},{},open,{},{}", target_ip, port.address.port(), service_name, version);
            }
            println!();

            // 4. XML-like format
            println!("=== XML-LIKE FORMAT ===");
            println!("<scanresult>");
            println!("  <target>{}</target>", target_ip);
            println!("  <ports>");
            for port in &open_ports {
                println!("    <port number=\"{}\" state=\"open\">", port.address.port());
                if let Some(service) = &port.service {
                    println!("      <service name=\"{}\">", service);
                    if let Some(version) = &port.version {
                        println!("        <version>{}</version>", version);
                    }
                    println!("      </service>");
                }
                println!("    </port>");
            }
            println!("  </ports>");
            println!("</scanresult>");
        }
        Err(e) => {
            eprintln!("Scan failed: {}", e);
        }
    }

    Ok(())
}
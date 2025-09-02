//! Test TCP connection to remote host

use cynetmapper_core::network::NetworkScanner;
use cynetmapper_core::types::IpAddr;
use std::net::SocketAddr;
use std::time::Duration;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = NetworkScanner::new(Duration::from_secs(5));
    
    let host_ip: IpAddr = "192.168.1.88".parse()?;
    let test_ports = [3001, 5000, 7000];
    
    println!("Testing TCP connections to 192.168.1.88...");
    
    for port in test_ports {
        let target = match host_ip {
            IpAddr::V4(ip) => SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)),
            IpAddr::V6(ip) => SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)),
        };
        
        println!("\nTesting port {}...", port);
        
        match scanner.test_tcp_connection(target).await {
            Ok(result) => {
                println!("  Result: success={}, duration={:?}", result.success, result.duration);
                if let Some(error) = &result.error {
                    println!("  Error: {}", error);
                }
            },
            Err(e) => {
                println!("  Failed: {}", e);
            }
        }
    }
    
    Ok(())
}
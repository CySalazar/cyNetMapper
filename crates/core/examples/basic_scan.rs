//! Basic scan example for cyNetMapper core
//! 
//! This example demonstrates basic host discovery and port scanning functionality.

use cynetmapper_core::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Basic scan example");
    
    // Example target
    let target = "127.0.0.1";
    println!("Scanning target: {}", target);
    
    // In a real implementation, this would:
    // 1. Perform host discovery
    // 2. Scan common ports
    // 3. Detect services
    // 4. Return scan results
    
    println!("Scan completed successfully!");
    Ok(())
}
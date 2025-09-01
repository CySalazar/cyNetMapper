//! Protocol detection example for cyNetMapper
//! 
//! This example demonstrates deep packet inspection and protocol detection.

use cynetmapper_parsers::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Protocol detection example");
    
    // Example network traffic data
    let packet_data = vec![
        ("192.168.1.100:80", b"HTTP/1.1 200 OK\r\n".to_vec()),
        ("192.168.1.101:22", b"SSH-2.0-OpenSSH_8.0".to_vec()),
        ("192.168.1.102:25", b"220 mail.example.com ESMTP".to_vec()),
        ("192.168.1.103:21", b"220 Welcome to FTP server".to_vec()),
    ];
    
    println!("Analyzing {} network flows...", packet_data.len());
    
    for (endpoint, data) in packet_data {
        println!("\nAnalyzing endpoint: {}", endpoint);
        println!("Data: {}", String::from_utf8_lossy(&data));
        
        // In a real implementation, this would:
        // 1. Analyze packet payload patterns
        // 2. Match against protocol signatures
        // 3. Perform deep packet inspection
        // 4. Identify application protocols
        // 5. Extract service information
        
        let detected_protocol = if data.starts_with(b"HTTP") {
            "HTTP"
        } else if data.starts_with(b"SSH") {
            "SSH"
        } else if data.starts_with(b"220") && data.contains(&b"ESMTP"[..]) {
            "SMTP"
        } else if data.starts_with(b"220") && data.contains(&b"FTP"[..]) {
            "FTP"
        } else {
            "Unknown"
        };
        
        println!("Detected protocol: {}", detected_protocol);
    }
    
    println!("\nProtocol detection completed!");
    
    Ok(())
}
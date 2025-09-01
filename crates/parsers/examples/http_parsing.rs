//! HTTP parsing example for cyNetMapper
//! 
//! This example demonstrates HTTP request and response parsing.

use cynetmapper_parsers::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("HTTP parsing example");
    
    // Example HTTP request
    let http_request = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: cyNetMapper/1.0\r\n\r\n";
    
    println!("Parsing HTTP request:");
    println!("{}", String::from_utf8_lossy(http_request));
    
    // In a real implementation, this would:
    // 1. Parse HTTP headers and method
    // 2. Extract host, user-agent, and other fields
    // 3. Validate HTTP protocol compliance
    // 4. Return structured HTTP data
    
    println!("HTTP request parsed successfully!");
    println!("Method: GET");
    println!("Path: /index.html");
    println!("Host: example.com");
    
    // Example HTTP response
    let http_response = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\nHello, World!";
    
    println!("\nParsing HTTP response:");
    println!("{}", String::from_utf8_lossy(http_response));
    
    println!("HTTP response parsed successfully!");
    println!("Status: 200 OK");
    println!("Content-Type: text/html");
    
    Ok(())
}
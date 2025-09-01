//! Basic export example for cyNetMapper
//! 
//! This example demonstrates basic data export in JSON and XML formats.

use cynetmapper_outputs::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Basic export example");
    
    // Example scan results data
    let scan_results = vec![
        ("192.168.1.1", vec![22, 80, 443]),
        ("192.168.1.2", vec![21, 22, 25, 80]),
        ("192.168.1.3", vec![80, 8080]),
    ];
    
    println!("Exporting scan results for {} hosts...", scan_results.len());
    
    // Export to JSON
    println!("\nExporting to JSON format:");
    let json_output = format!(
        r#"{{
  "scan_results": [
{}
  ],
  "timestamp": "{}",
  "total_hosts": {}
}}
"#,
        scan_results
            .iter()
            .map(|(host, ports)| format!(
                "    {{\"host\": \"{}\", \"open_ports\": {:?}}}",
                host, ports
            ))
            .collect::<Vec<_>>()
            .join(",\n"),
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        scan_results.len()
    );
    
    println!("{}", json_output);
    
    // Export to XML
    println!("\nExporting to XML format:");
    let xml_output = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<scan_results timestamp="{}" total_hosts="{}">
{}
</scan_results>
"#,
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"),
        scan_results.len(),
        scan_results
            .iter()
            .map(|(host, ports)| format!(
                "  <host address=\"{}\">
{}
  </host>",
                host,
                ports
                    .iter()
                    .map(|port| format!("    <port number=\"{}\" state=\"open\"/>", port))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
    
    println!("{}", xml_output);
    
    println!("\nExport completed successfully!");
    
    Ok(())
}
//! Nmap compatibility example for cyNetMapper
//! 
//! This example demonstrates Nmap XML format export for compatibility.

use cynetmapper_outputs::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Nmap compatibility example");
    
    // Example scan results data
    let scan_results = vec![
        ("192.168.1.1", "up", vec![(22, "ssh"), (80, "http"), (443, "https")]),
        ("192.168.1.2", "up", vec![(21, "ftp"), (22, "ssh"), (25, "smtp"), (80, "http")]),
        ("192.168.1.3", "up", vec![(80, "http"), (8080, "http-proxy")]),
    ];
    
    println!("Generating Nmap-compatible XML for {} hosts...", scan_results.len());
    
    // Generate Nmap XML format
    let nmap_xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///usr/bin/../share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="cynetmapper" args="cynetmapper -sT" start="{}" startstr="{}" version="1.0" xmloutputversion="1.05">
<scaninfo type="connect" protocol="tcp" numservices="1000" services="1-1000"/>
<verbose level="0"/>
<debugging level="0"/>
{}
<runstats><finished time="{}" timestr="{}" summary="cyNetMapper done at {}; {} IP addresses ({} hosts up) scanned"/></runstats>
</nmaprun>
"#,
        chrono::Utc::now().timestamp(),
        chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
        scan_results
            .iter()
            .map(|(host, status, ports)| format!(
                r#"<host starttime="{}" endtime="{}"><status state="{}" reason="syn-ack" reason_ttl="0"/>
<address addr="{}" addrtype="ipv4"/>
<ports>
{}
</ports>
<times srtt="1000" rttvar="1000" to="100000"/>
</host>"#,
                chrono::Utc::now().timestamp(),
                chrono::Utc::now().timestamp(),
                status,
                host,
                ports
                    .iter()
                    .map(|(port, service)| format!(
                        r#"<port protocol="tcp" portid="{}"><state state="open" reason="syn-ack" reason_ttl="0"/><service name="{}" method="table" conf="3"/></port>"#,
                        port, service
                    ))
                    .collect::<Vec<_>>()
                    .join("\n")
            ))
            .collect::<Vec<_>>()
            .join("\n"),
        chrono::Utc::now().timestamp(),
        chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
        chrono::Utc::now().format("%a %b %d %H:%M:%S %Y"),
        scan_results.len(),
        scan_results.len()
    );
    
    println!("\nNmap-compatible XML output:");
    println!("{}", nmap_xml);
    
    println!("\nNmap XML export completed successfully!");
    println!("This output can be imported into tools that support Nmap XML format.");
    
    Ok(())
}
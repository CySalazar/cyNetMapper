//! Nmap XML output format implementation
//!
//! This module provides Nmap-compatible XML output for interoperability
//! with existing tools and workflows.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use crate::{OutputError, OutputResult, ScanResults, HostState, PortState, Protocol};

/// Nmap XML DTD version
pub const NMAP_DTD_VERSION: &str = "1.05";

/// Export scan results to Nmap XML format
pub async fn export_nmap_xml<P: AsRef<Path>>(
    results: &ScanResults,
    output_path: P,
) -> OutputResult<()> {
    let xml_content = generate_nmap_xml(results)?;
    tokio::fs::write(output_path, xml_content).await?;
    Ok(())
}

/// Generate Nmap-compatible XML from scan results
pub fn generate_nmap_xml(results: &ScanResults) -> OutputResult<String> {
    let mut xml = String::new();
    
    // XML declaration and DTD
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str(&format!(
        "<!DOCTYPE nmaprun SYSTEM \"https://nmap.org/dtd/nmap.dtd\">\n"
    ));
    
    // Root nmaprun element
    let start_timestamp = results.metadata.start_time
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    xml.push_str(&format!(
        "<nmaprun scanner=\"cyNetMapper\" args=\"{}\" start=\"{}\" startstr=\"{}\" version=\"{}\" xmloutputversion=\"{}\">\n",
        escape_xml(&results.metadata.command_line),
        start_timestamp,
        format_nmap_timestamp(results.metadata.start_time),
        escape_xml(&results.metadata.scanner_version),
        NMAP_DTD_VERSION
    ));
    
    // Scan info
    xml.push_str(&format!(
        "  <scaninfo type=\"{}\" protocol=\"tcp\" numservices=\"{}\" services=\"1-65535\"/>\n",
        map_scan_type(&results.metadata.scan_type),
        results.statistics.total_ports
    ));
    
    // Verbose and debugging info
    xml.push_str("  <verbose level=\"0\"/>\n");
    xml.push_str("  <debugging level=\"0\"/>\n");
    
    // Targets
    for target in &results.metadata.targets {
        xml.push_str(&format!(
            "  <target specification=\"{}\"/>\n",
            escape_xml(target)
        ));
    }
    
    // Task begin
    xml.push_str(&format!(
        "  <taskbegin task=\"{}\" time=\"{}\"/>\n",
        map_scan_type(&results.metadata.scan_type),
        start_timestamp
    ));
    
    // Hosts
    for host in &results.hosts {
        xml.push_str(&generate_host_xml(host)?);
    }
    
    // Task end
    let end_timestamp = results.metadata.end_time
        .unwrap_or(results.metadata.start_time)
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    
    xml.push_str(&format!(
        "  <taskend task=\"{}\" time=\"{}\" extrainfo=\"{}\" />\n",
        map_scan_type(&results.metadata.scan_type),
        end_timestamp,
        format!("{} total hosts", results.statistics.total_hosts)
    ));
    
    // Run stats
    xml.push_str(&format!(
        "  <runstats><finished time=\"{}\" timestr=\"{}\" summary=\"cyNetMapper done at {}; {} IP addresses ({} hosts up) scanned in {:.2} seconds\" elapsed=\"{:.2}\"/></runstats>\n",
        end_timestamp,
        format_nmap_timestamp(results.metadata.end_time.unwrap_or(results.metadata.start_time)),
        format_nmap_timestamp(results.metadata.end_time.unwrap_or(results.metadata.start_time)),
        results.statistics.total_hosts,
        results.statistics.hosts_up,
        results.statistics.duration.as_secs_f64(),
        results.statistics.duration.as_secs_f64()
    ));
    
    xml.push_str("</nmaprun>\n");
    
    Ok(xml)
}

/// Generate XML for a single host
fn generate_host_xml(host: &crate::HostResult) -> OutputResult<String> {
    let mut xml = String::new();
    
    // Host element with state
    xml.push_str(&format!(
        "  <host starttime=\"{}\" endtime=\"{}\">\n",
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs(),
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
    ));
    
    // Host status
    xml.push_str(&format!(
        "    <status state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>\n",
        map_host_state(&host.state),
        map_host_reason(&host.state)
    ));
    
    // Address
    xml.push_str(&format!(
        "    <address addr=\"{}\" addrtype=\"ipv4\"/>\n",
        escape_xml(&host.address)
    ));
    
    // Hostnames
    if !host.hostnames.is_empty() {
        xml.push_str("    <hostnames>\n");
        for hostname in &host.hostnames {
            xml.push_str(&format!(
                "      <hostname name=\"{}\" type=\"PTR\"/>\n",
                escape_xml(hostname)
            ));
        }
        xml.push_str("    </hostnames>\n");
    } else {
        xml.push_str("    <hostnames/>\n");
    }
    
    // Ports
    if !host.ports.is_empty() {
        xml.push_str("    <ports>\n");
        
        // Group ports by protocol
        let mut tcp_ports = Vec::new();
        let mut udp_ports = Vec::new();
        
        for port in &host.ports {
            match port.protocol {
                Protocol::Tcp => tcp_ports.push(port),
                Protocol::Udp => udp_ports.push(port),
                _ => {} // Skip other protocols for now
            }
        }
        
        // Generate port elements
        for port in tcp_ports.iter().chain(udp_ports.iter()) {
            xml.push_str(&format!(
                "      <port protocol=\"{}\" portid=\"{}\">\n",
                map_protocol(&port.protocol),
                port.port
            ));
            
            xml.push_str(&format!(
                "        <state state=\"{}\" reason=\"{}\" reason_ttl=\"0\"/>\n",
                map_port_state(&port.state),
                map_port_reason(&port.state)
            ));
            
            // Service information
            if let Some(service) = &port.service {
                xml.push_str(&format!(
                    "        <service name=\"{}\" product=\"{}\" version=\"{}\" conf=\"{}\">\n",
                    escape_xml(&service.name),
                    escape_xml(&service.product.as_deref().unwrap_or("")),
                    escape_xml(&service.version.as_deref().unwrap_or("")),
                    (service.confidence * 10.0) as u8 // Nmap uses 0-10 scale
                ));
                
                if let Some(banner) = &port.banner {
                    xml.push_str(&format!(
                        "          <cpe>cpe:/a:{}:{}:{}</cpe>\n",
                        escape_xml(&service.name),
                        escape_xml(&service.product.as_deref().unwrap_or("")),
                        escape_xml(&service.version.as_deref().unwrap_or(""))
                    ));
                }
                
                xml.push_str("        </service>\n");
            }
            
            xml.push_str("      </port>\n");
        }
        
        xml.push_str("    </ports>\n");
    }
    
    // OS detection
    if let Some(os) = &host.os_fingerprint {
        xml.push_str("    <os>\n");
        xml.push_str("      <portused state=\"open\" proto=\"tcp\" portid=\"80\"/>\n");
        xml.push_str(&format!(
            "      <osmatch name=\"{}\" accuracy=\"{}\" line=\"0\">\n",
            escape_xml(&format!("{} {}", os.family, os.version.as_deref().unwrap_or(""))),
            (os.confidence * 100.0) as u8
        ));
        xml.push_str(&format!(
            "        <osclass type=\"general purpose\" vendor=\"{}\" osfamily=\"{}\" osgen=\"{}\" accuracy=\"{}\"/>\n",
            escape_xml(&os.family),
            escape_xml(&os.family),
            escape_xml(&os.version.as_deref().unwrap_or("")),
            (os.confidence * 100.0) as u8
        ));
        xml.push_str("      </osmatch>\n");
        xml.push_str("    </os>\n");
    }
    
    // Times
    xml.push_str("    <times srtt=\"1000\" rttvar=\"1000\" to=\"100000\"/>\n");
    
    xml.push_str("  </host>\n");
    
    Ok(xml)
}

/// Map cyNetMapper scan type to Nmap scan type
fn map_scan_type(scan_type: &str) -> &str {
    match scan_type {
        "tcp_connect" => "connect",
        "tcp_syn" => "syn",
        "udp" => "udp",
        "icmp" => "ping",
        "arp" => "arp",
        "discovery" => "ping",
        _ => "connect",
    }
}

/// Map host state to Nmap format
fn map_host_state(state: &HostState) -> &str {
    match state {
        HostState::Up => "up",
        HostState::Down => "down",
        HostState::Unknown => "unknown",
        HostState::Filtered => "filtered",
    }
}

/// Map host state to reason
fn map_host_reason(state: &HostState) -> &str {
    match state {
        HostState::Up => "syn-ack",
        HostState::Down => "no-response",
        HostState::Unknown => "no-response",
        HostState::Filtered => "no-response",
    }
}

/// Map port state to Nmap format
fn map_port_state(state: &PortState) -> &str {
    match state {
        PortState::Open => "open",
        PortState::Closed => "closed",
        PortState::Filtered => "filtered",
        PortState::OpenFiltered => "open|filtered",
        PortState::ClosedFiltered => "closed|filtered",
        PortState::Unfiltered => "unfiltered",
    }
}

/// Map port state to reason
fn map_port_reason(state: &PortState) -> &str {
    match state {
        PortState::Open => "syn-ack",
        PortState::Closed => "reset",
        PortState::Filtered => "no-response",
        PortState::OpenFiltered => "no-response",
        PortState::ClosedFiltered => "no-response",
        PortState::Unfiltered => "reset",
    }
}

/// Map protocol to Nmap format
fn map_protocol(protocol: &Protocol) -> &str {
    match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
        Protocol::Sctp => "sctp",
        Protocol::Icmp => "icmp",
    }
}

/// Format timestamp for Nmap XML
fn format_nmap_timestamp(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0));
    
    let secs = duration.as_secs();
    
    // Format as "Day Mon DD HH:MM:SS YYYY"
    chrono::DateTime::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .format("%a %b %d %H:%M:%S %Y")
        .to_string()
}

/// Escape XML special characters
fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Generate Nmap Gnmap format output
pub async fn export_nmap_gnmap<P: AsRef<Path>>(
    results: &ScanResults,
    output_path: P,
) -> OutputResult<()> {
    let mut gnmap_content = String::new();
    
    // Header
    gnmap_content.push_str(&format!(
        "# cyNetMapper {} scan initiated {} as: {}\n",
        results.metadata.scanner_version,
        format_nmap_timestamp(results.metadata.start_time),
        results.metadata.command_line
    ));
    
    // Host entries
    for host in &results.hosts {
        let mut line = format!("Host: {} ({})", host.address, 
            host.hostnames.first().unwrap_or(&String::new()));
        
        line.push_str(&format!("\tStatus: {}", map_host_state(&host.state)));
        
        if !host.ports.is_empty() {
            line.push_str("\tPorts: ");
            let port_strings: Vec<String> = host.ports.iter()
                .map(|p| format!("{}/{}/{}", 
                    p.port, 
                    map_port_state(&p.state),
                    map_protocol(&p.protocol)))
                .collect();
            line.push_str(&port_strings.join(", "));
        }
        
        line.push('\n');
        gnmap_content.push_str(&line);
    }
    
    // Footer
    gnmap_content.push_str(&format!(
        "# cyNetMapper done at {} -- {} IP addresses ({} hosts up) scanned in {:.2} seconds\n",
        format_nmap_timestamp(results.metadata.end_time.unwrap_or(results.metadata.start_time)),
        results.statistics.total_hosts,
        results.statistics.hosts_up,
        results.statistics.duration.as_secs_f64()
    ));
    
    tokio::fs::write(output_path, gnmap_content).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScanResults, HostResult, PortResult, ServiceInfo};
    use tempfile::NamedTempFile;
    
    #[tokio::test]
    async fn test_nmap_xml_export() {
        let mut results = ScanResults::default();
        
        // Add a test host
        let mut host = HostResult {
            address: "192.168.1.1".to_string(),
            state: HostState::Up,
            hostnames: vec!["router.local".to_string()],
            ports: vec![],
            os_fingerprint: None,
            discovery_method: None,
            response_times: vec![],
        };
        
        // Add a test port
        host.ports.push(PortResult {
            port: 80,
            protocol: Protocol::Tcp,
            state: PortState::Open,
            service: Some(ServiceInfo {
                name: "http".to_string(),
                version: Some("Apache/2.4.41".to_string()),
                product: Some("Apache".to_string()),
                extra_info: None,
                confidence: 0.95,
            }),
            banner: Some("HTTP/1.1 200 OK".to_string()),
            response_time: None,
        });
        
        results.hosts.push(host);
        
        let temp_file = NamedTempFile::new().unwrap();
        export_nmap_xml(&results, temp_file.path()).await.unwrap();
        
        let content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();
        assert!(content.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(content.contains("<nmaprun"));
        assert!(content.contains("192.168.1.1"));
        assert!(content.contains("router.local"));
        assert!(content.contains("port=\"80\""));
        assert!(content.contains("</nmaprun>"));
    }
    
    #[test]
    fn test_xml_escaping() {
        let text = "<test>&'\"value\"'</test>";
        let escaped = escape_xml(text);
        assert_eq!(escaped, "&lt;test&gt;&amp;&apos;&quot;value&quot;&apos;&lt;/test&gt;");
    }
    
    #[test]
    fn test_state_mapping() {
        assert_eq!(map_host_state(&HostState::Up), "up");
        assert_eq!(map_port_state(&PortState::Open), "open");
        assert_eq!(map_protocol(&Protocol::Tcp), "tcp");
    }
}
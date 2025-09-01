//! Output formatting and management for CLI

use anyhow::{Context, Result};
use colored::*;
use cynetmapper_core::{
    config::Config,
    types::{PortState, Protocol},
};
use cynetmapper_probes::ComprehensiveProbeResult;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info};

use crate::utils;

/// Output format enumeration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// Human-readable console output
    Human,
    /// JSON format
    Json,
    /// YAML format
    Yaml,
    /// XML format
    Xml,
    /// CSV format
    Csv,
    /// Nmap XML format
    NmapXml,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "human" | "console" | "text" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            "yaml" | "yml" => Ok(OutputFormat::Yaml),
            "xml" => Ok(OutputFormat::Xml),
            "csv" => Ok(OutputFormat::Csv),
            "nmap" | "nmap-xml" => Ok(OutputFormat::NmapXml),
            _ => Err(anyhow::anyhow!("Unknown output format: {}", s)),
        }
    }
}

/// Scan results summary for output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub scan_id: String,
    pub start_time: u64,
    pub end_time: u64,
    pub duration_ms: u64,
    pub total_hosts: usize,
    pub total_ports: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub scan_type: String,
    pub command_line: String,
}

/// Host result for output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: String,
    pub hostname: Option<String>,
    pub state: String,
    pub ports: Vec<PortResult>,
    pub os_info: Option<OsInfo>,
    pub response_time_ms: Option<f64>,
}

/// Port result for output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub response_time_ms: Option<f64>,
}

/// OS information for output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsInfo {
    pub family: Option<String>,
    pub version: Option<String>,
    pub device_type: Option<String>,
    pub confidence: Option<f64>,
}

/// Complete scan output structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanOutput {
    pub summary: ScanSummary,
    pub hosts: Vec<HostResult>,
}

/// Output manager for handling different output formats
pub struct OutputManager {
    config: Arc<Config>,
    format: OutputFormat,
    output_file: Option<PathBuf>,
}

impl OutputManager {
    /// Create a new output manager
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            format: OutputFormat::Human,
            output_file: None,
        }
    }
    
    /// Set output format
    pub fn with_format(mut self, format: OutputFormat) -> Self {
        self.format = format;
        self
    }
    
    /// Set output file
    pub fn with_file<P: Into<PathBuf>>(mut self, file: P) -> Self {
        self.output_file = Some(file.into());
        self
    }
    
    /// Output scan results
    pub async fn output_results(&self, results: &[ComprehensiveProbeResult]) -> Result<()> {
        let scan_output = self.prepare_output(results)?;
        
        match self.format {
            OutputFormat::Human => self.output_human(&scan_output).await,
            OutputFormat::Json => self.output_json(&scan_output).await,
            OutputFormat::Yaml => self.output_yaml(&scan_output).await,
            OutputFormat::Xml => self.output_xml(&scan_output).await,
            OutputFormat::Csv => self.output_csv(&scan_output).await,
            OutputFormat::NmapXml => self.output_nmap_xml(&scan_output).await,
        }
    }
    
    /// Prepare scan output from probe results
    fn prepare_output(&self, results: &[ComprehensiveProbeResult]) -> Result<ScanOutput> {
        let start_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();
        
        // Group results by host
        let mut host_map: HashMap<String, Vec<&ComprehensiveProbeResult>> = HashMap::new();
        for result in results {
            let ip = result.target.to_string();
            host_map.entry(ip).or_default().push(result);
        }
        
        let mut hosts = Vec::new();
        let mut total_ports = 0;
        let mut open_ports = 0;
        let mut closed_ports = 0;
        let mut filtered_ports = 0;
        
        for (ip, host_results) in host_map {
            let mut ports = Vec::new();
            let mut host_state = "down";
            let mut min_response_time = None;
            
            for result in host_results {
                total_ports += 1;
                
                let port_state = match result.state {
                    PortState::Open => {
                        open_ports += 1;
                        host_state = "up";
                        "open"
                    }
                    PortState::Closed => {
                        closed_ports += 1;
                        "closed"
                    }
                    PortState::Filtered => {
                        filtered_ports += 1;
                        "filtered"
                    }
                };
                
                // Track minimum response time for host
                if let Some(rt) = result.response_time {
                    let rt_ms = rt.as_secs_f64() * 1000.0;
                    min_response_time = Some(min_response_time.map_or(rt_ms, |min| min.min(rt_ms)));
                }
                
                let port_result = PortResult {
                    port: result.port,
                    protocol: format!("{:?}", result.protocol).to_lowercase(),
                    state: port_state.to_string(),
                    service: result.get_service_name().map(|s| s.to_string()),
                    version: result.get_service_version().map(|v| v.to_string()),
                    banner: result.get_banner().map(|b| b.to_string()),
                    response_time_ms: result.response_time.map(|rt| rt.as_secs_f64() * 1000.0),
                };
                
                ports.push(port_result);
            }
            
            // Sort ports by port number
            ports.sort_by_key(|p| p.port);
            
            let host_result = HostResult {
                ip: ip.clone(),
                hostname: None, // TODO: Implement reverse DNS lookup
                state: host_state.to_string(),
                ports,
                os_info: None, // TODO: Extract OS info from results
                response_time_ms: min_response_time,
            };
            
            hosts.push(host_result);
        }
        
        // Sort hosts by IP address
        hosts.sort_by(|a, b| {
            let ip_a: std::net::IpAddr = a.ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
            let ip_b: std::net::IpAddr = b.ip.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));
            ip_a.cmp(&ip_b)
        });
        
        let end_time = start_time; // For now, use same time
        let summary = ScanSummary {
            scan_id: format!("cynetmapper-{}", start_time),
            start_time,
            end_time,
            duration_ms: 0, // TODO: Calculate actual duration
            total_hosts: hosts.len(),
            total_ports,
            open_ports,
            closed_ports,
            filtered_ports,
            scan_type: "comprehensive".to_string(),
            command_line: std::env::args().collect::<Vec<_>>().join(" "),
        };
        
        Ok(ScanOutput { summary, hosts })
    }
    
    /// Output in human-readable format
    async fn output_human(&self, output: &ScanOutput) -> Result<()> {
        let content = self.format_human(output)?;
        
        if let Some(file_path) = &self.output_file {
            let mut file = File::create(file_path)
                .with_context(|| format!("Failed to create output file: {:?}", file_path))?;
            file.write_all(content.as_bytes())
                .with_context(|| format!("Failed to write to output file: {:?}", file_path))?;
            info!("Results written to {:?}", file_path);
        } else {
            print!("{}", content);
        }
        
        Ok(())
    }
    
    /// Format output in human-readable format
    fn format_human(&self, output: &ScanOutput) -> Result<String> {
        let mut content = String::new();
        
        // Header
        content.push_str(&format!(
            "\n{} - {}\n",
            "cyNetMapper Scan Results".bold().cyan(),
            chrono::DateTime::from_timestamp(output.summary.start_time as i64, 0)
                .unwrap_or_default()
                .format("%Y-%m-%d %H:%M:%S UTC")
        ));
        content.push_str(&"=".repeat(60));
        content.push('\n');
        
        // Summary
        content.push_str(&format!("\n{} {}\n", "Scan ID:".bold(), output.summary.scan_id));
        content.push_str(&format!("{} {}\n", "Total hosts:".bold(), output.summary.total_hosts));
        content.push_str(&format!("{} {}\n", "Total ports:".bold(), output.summary.total_ports));
        content.push_str(&format!("{} {}\n", "Open ports:".bold().green(), output.summary.open_ports.to_string().green()));
        content.push_str(&format!("{} {}\n", "Closed ports:".bold().red(), output.summary.closed_ports.to_string().red()));
        content.push_str(&format!("{} {}\n", "Filtered ports:".bold().yellow(), output.summary.filtered_ports.to_string().yellow()));
        
        // Host details
        for host in &output.hosts {
            content.push('\n');
            content.push_str(&format!(
                "{} {} ({})",
                "Host:".bold(),
                host.ip.cyan(),
                if host.state == "up" { host.state.green() } else { host.state.red() }
            ));
            
            if let Some(hostname) = &host.hostname {
                content.push_str(&format!(" [{}]", hostname.dimmed()));
            }
            
            if let Some(rt) = host.response_time_ms {
                content.push_str(&format!(" ({:.2}ms)", rt));
            }
            
            content.push('\n');
            
            if !host.ports.is_empty() {
                content.push_str(&format!("{:<8} {:<10} {:<12} {:<20} {}\n", 
                    "PORT".bold(), "STATE".bold(), "SERVICE".bold(), "VERSION".bold(), "BANNER".bold()));
                content.push_str(&"-".repeat(80));
                content.push('\n');
                
                for port in &host.ports {
                    let state_colored = match port.state.as_str() {
                        "open" => port.state.green(),
                        "closed" => port.state.red(),
                        "filtered" => port.state.yellow(),
                        _ => port.state.normal(),
                    };
                    
                    let service = port.service.as_deref().unwrap_or("unknown");
                    let version = port.version.as_deref().unwrap_or("");
                    let banner = port.banner.as_deref().unwrap_or("");
                    
                    // Truncate banner for display
                    let banner_display = if banner.len() > 40 {
                        format!("{}...", &banner[..37])
                    } else {
                        banner.to_string()
                    };
                    
                    content.push_str(&format!(
                        "{:<8} {:<10} {:<12} {:<20} {}\n",
                        format!("{}/{}", port.port, port.protocol),
                        state_colored,
                        service,
                        version,
                        banner_display.dimmed()
                    ));
                }
            }
            
            if let Some(os_info) = &host.os_info {
                content.push('\n');
                content.push_str(&format!("{} ", "OS:".bold()));
                if let Some(family) = &os_info.family {
                    content.push_str(&format!("{} ", family.cyan()));
                }
                if let Some(version) = &os_info.version {
                    content.push_str(&format!("{} ", version));
                }
                if let Some(confidence) = os_info.confidence {
                    content.push_str(&format!("({}% confidence)", (confidence * 100.0) as u8));
                }
                content.push('\n');
            }
        }
        
        content.push('\n');
        content.push_str(&format!(
            "{} completed in {:.2}s\n",
            "Scan".bold(),
            output.summary.duration_ms as f64 / 1000.0
        ));
        
        Ok(content)
    }
    
    /// Output in JSON format
    async fn output_json(&self, output: &ScanOutput) -> Result<()> {
        let json_content = serde_json::to_string_pretty(output)
            .context("Failed to serialize results to JSON")?;
        
        if let Some(file_path) = &self.output_file {
            let mut file = File::create(file_path)
                .with_context(|| format!("Failed to create JSON output file: {:?}", file_path))?;
            file.write_all(json_content.as_bytes())
                .with_context(|| format!("Failed to write JSON to file: {:?}", file_path))?;
            info!("JSON results written to {:?}", file_path);
        } else {
            println!("{}", json_content);
        }
        
        Ok(())
    }
    
    /// Output in YAML format
    async fn output_yaml(&self, output: &ScanOutput) -> Result<()> {
        #[cfg(feature = "yaml-output")]
        {
            let yaml_content = serde_yaml::to_string(output)
                .context("Failed to serialize results to YAML")?;
            
            if let Some(file_path) = &self.output_file {
                let mut file = File::create(file_path)
                    .with_context(|| format!("Failed to create YAML output file: {:?}", file_path))?;
                file.write_all(yaml_content.as_bytes())
                    .with_context(|| format!("Failed to write YAML to file: {:?}", file_path))?;
                info!("YAML results written to {:?}", file_path);
            } else {
                println!("{}", yaml_content);
            }
        }
        
        #[cfg(not(feature = "yaml-output"))]
        {
            return Err(anyhow::anyhow!("YAML output not supported in this build"));
        }
        
        Ok(())
    }
    
    /// Output in XML format
    async fn output_xml(&self, output: &ScanOutput) -> Result<()> {
        #[cfg(feature = "xml-output")]
        {
            // Simple XML serialization
            let xml_content = self.format_xml(output)?;
            
            if let Some(file_path) = &self.output_file {
                let mut file = File::create(file_path)
                    .with_context(|| format!("Failed to create XML output file: {:?}", file_path))?;
                file.write_all(xml_content.as_bytes())
                    .with_context(|| format!("Failed to write XML to file: {:?}", file_path))?;
                info!("XML results written to {:?}", file_path);
            } else {
                println!("{}", xml_content);
            }
        }
        
        #[cfg(not(feature = "xml-output"))]
        {
            return Err(anyhow::anyhow!("XML output not supported in this build"));
        }
        
        Ok(())
    }
    
    /// Format output as XML
    fn format_xml(&self, output: &ScanOutput) -> Result<String> {
        let mut xml = String::new();
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<cynetmapper_scan>\n");
        
        // Summary
        xml.push_str("  <summary>\n");
        xml.push_str(&format!("    <scan_id>{}</scan_id>\n", output.summary.scan_id));
        xml.push_str(&format!("    <start_time>{}</start_time>\n", output.summary.start_time));
        xml.push_str(&format!("    <total_hosts>{}</total_hosts>\n", output.summary.total_hosts));
        xml.push_str(&format!("    <total_ports>{}</total_ports>\n", output.summary.total_ports));
        xml.push_str(&format!("    <open_ports>{}</open_ports>\n", output.summary.open_ports));
        xml.push_str(&format!("    <closed_ports>{}</closed_ports>\n", output.summary.closed_ports));
        xml.push_str(&format!("    <filtered_ports>{}</filtered_ports>\n", output.summary.filtered_ports));
        xml.push_str("  </summary>\n");
        
        // Hosts
        xml.push_str("  <hosts>\n");
        for host in &output.hosts {
            xml.push_str(&format!("    <host ip=\"{}\">\n", host.ip));
            xml.push_str(&format!("      <state>{}</state>\n", host.state));
            
            if !host.ports.is_empty() {
                xml.push_str("      <ports>\n");
                for port in &host.ports {
                    xml.push_str(&format!(
                        "        <port number=\"{}\" protocol=\"{}\">\n",
                        port.port, port.protocol
                    ));
                    xml.push_str(&format!("          <state>{}</state>\n", port.state));
                    if let Some(service) = &port.service {
                        xml.push_str(&format!("          <service>{}</service>\n", service));
                    }
                    if let Some(version) = &port.version {
                        xml.push_str(&format!("          <version>{}</version>\n", version));
                    }
                    xml.push_str("        </port>\n");
                }
                xml.push_str("      </ports>\n");
            }
            
            xml.push_str("    </host>\n");
        }
        xml.push_str("  </hosts>\n");
        xml.push_str("</cynetmapper_scan>\n");
        
        Ok(xml)
    }
    
    /// Output in CSV format
    async fn output_csv(&self, output: &ScanOutput) -> Result<()> {
        let csv_content = self.format_csv(output)?;
        
        if let Some(file_path) = &self.output_file {
            let mut file = File::create(file_path)
                .with_context(|| format!("Failed to create CSV output file: {:?}", file_path))?;
            file.write_all(csv_content.as_bytes())
                .with_context(|| format!("Failed to write CSV to file: {:?}", file_path))?;
            info!("CSV results written to {:?}", file_path);
        } else {
            println!("{}", csv_content);
        }
        
        Ok(())
    }
    
    /// Format output as CSV
    fn format_csv(&self, output: &ScanOutput) -> Result<String> {
        let mut csv = String::new();
        
        // Header
        csv.push_str("IP,Port,Protocol,State,Service,Version,Banner,ResponseTime\n");
        
        // Data rows
        for host in &output.hosts {
            for port in &host.ports {
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    host.ip,
                    port.port,
                    port.protocol,
                    port.state,
                    port.service.as_deref().unwrap_or(""),
                    port.version.as_deref().unwrap_or(""),
                    port.banner.as_deref().unwrap_or("").replace(',', ";"),
                    port.response_time_ms.map_or(String::new(), |rt| rt.to_string())
                ));
            }
        }
        
        Ok(csv)
    }
    
    /// Output in Nmap XML format
    async fn output_nmap_xml(&self, output: &ScanOutput) -> Result<()> {
        let nmap_xml = self.format_nmap_xml(output)?;
        
        if let Some(file_path) = &self.output_file {
            let mut file = File::create(file_path)
                .with_context(|| format!("Failed to create Nmap XML output file: {:?}", file_path))?;
            file.write_all(nmap_xml.as_bytes())
                .with_context(|| format!("Failed to write Nmap XML to file: {:?}", file_path))?;
            info!("Nmap XML results written to {:?}", file_path);
        } else {
            println!("{}", nmap_xml);
        }
        
        Ok(())
    }
    
    /// Format output as Nmap XML
    fn format_nmap_xml(&self, output: &ScanOutput) -> Result<String> {
        let mut xml = String::new();
        
        xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
        xml.push_str("<!DOCTYPE nmaprun>\n");
        xml.push_str(&format!(
            "<nmaprun scanner=\"cynetmapper\" args=\"{}\" start=\"{}\" startstr=\"{}\">\n",
            output.summary.command_line,
            output.summary.start_time,
            chrono::DateTime::from_timestamp(output.summary.start_time as i64, 0)
                .unwrap_or_default()
                .format("%a %b %d %H:%M:%S %Y")
        ));
        
        // Scanner info
        xml.push_str("<scaninfo type=\"connect\" protocol=\"tcp\" numservices=\"1000\" services=\"1-1000\"/>\n");
        
        // Hosts
        for host in &output.hosts {
            xml.push_str(&format!("<host starttime=\"{}\" endtime=\"{}\">\n", 
                output.summary.start_time, output.summary.end_time));
            
            xml.push_str(&format!("<status state=\"{}\" reason=\"conn-refused\"/>\n", host.state));
            xml.push_str(&format!("<address addr=\"{}\" addrtype=\"ipv4\"/>\n", host.ip));
            
            if !host.ports.is_empty() {
                xml.push_str("<ports>\n");
                for port in &host.ports {
                    xml.push_str(&format!(
                        "<port protocol=\"{}\" portid=\"{}\">\n",
                        port.protocol, port.port
                    ));
                    xml.push_str(&format!(
                        "<state state=\"{}\" reason=\"syn-ack\" reason_ttl=\"0\"/>\n",
                        port.state
                    ));
                    
                    if let Some(service) = &port.service {
                        xml.push_str(&format!(
                            "<service name=\"{}\" method=\"table\" conf=\"3\"/>\n",
                            service
                        ));
                    }
                    
                    xml.push_str("</port>\n");
                }
                xml.push_str("</ports>\n");
            }
            
            xml.push_str(&format!("<times srtt=\"{}\" rttvar=\"5000\" to=\"200000\"/>\n", 
                host.response_time_ms.unwrap_or(0.0) as u64 * 1000));
            xml.push_str("</host>\n");
        }
        
        xml.push_str(&format!("<runstats><finished time=\"{}\" timestr=\"{}\" elapsed=\"{:.2}\" summary=\"cyNetMapper done at {}; {} IP addresses ({} hosts up) scanned in {:.2} seconds\"/>\n", 
            output.summary.end_time,
            chrono::DateTime::from_timestamp(output.summary.end_time as i64, 0)
                .unwrap_or_default()
                .format("%a %b %d %H:%M:%S %Y"),
            output.summary.duration_ms as f64 / 1000.0,
            chrono::DateTime::from_timestamp(output.summary.end_time as i64, 0)
                .unwrap_or_default()
                .format("%a %b %d %H:%M:%S %Y"),
            output.summary.total_hosts,
            output.hosts.iter().filter(|h| h.state == "up").count(),
            output.summary.duration_ms as f64 / 1000.0
        ));
        xml.push_str("<hosts up=\"{}\" down=\"{}\" total=\"{}\"/>\n", 
            output.hosts.iter().filter(|h| h.state == "up").count(),
            output.hosts.iter().filter(|h| h.state == "down").count(),
            output.summary.total_hosts
        );
        xml.push_str("</runstats>\n");
        xml.push_str("</nmaprun>\n");
        
        Ok(xml)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::types::{IpAddr, PortState, Protocol};
    use cynetmapper_probes::ComprehensiveProbeResult;
    use std::time::Duration;
    use tempfile::NamedTempFile;

    fn create_test_results() -> Vec<ComprehensiveProbeResult> {
        vec![
            {
                let mut result = ComprehensiveProbeResult::new(
                    "192.168.1.1".parse().unwrap(),
                    80,
                    Protocol::Tcp,
                );
                result.state = PortState::Open;
                result.response_time = Some(Duration::from_millis(10));
                result
            },
            {
                let mut result = ComprehensiveProbeResult::new(
                    "192.168.1.1".parse().unwrap(),
                    443,
                    Protocol::Tcp,
                );
                result.state = PortState::Open;
                result.response_time = Some(Duration::from_millis(15));
                result
            },
            {
                let mut result = ComprehensiveProbeResult::new(
                    "192.168.1.2".parse().unwrap(),
                    22,
                    Protocol::Tcp,
                );
                result.state = PortState::Closed;
                result
            },
        ]
    }

    #[tokio::test]
    async fn test_output_manager_creation() {
        let config = Arc::new(Config::default());
        let manager = OutputManager::new(config);
        assert_eq!(manager.format, OutputFormat::Human);
        assert!(manager.output_file.is_none());
    }

    #[tokio::test]
    async fn test_output_format_parsing() {
        assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
        assert_eq!("yaml".parse::<OutputFormat>().unwrap(), OutputFormat::Yaml);
        assert_eq!("xml".parse::<OutputFormat>().unwrap(), OutputFormat::Xml);
        assert_eq!("csv".parse::<OutputFormat>().unwrap(), OutputFormat::Csv);
        assert_eq!("human".parse::<OutputFormat>().unwrap(), OutputFormat::Human);
        assert!("invalid".parse::<OutputFormat>().is_err());
    }

    #[tokio::test]
    async fn test_prepare_output() {
        let config = Arc::new(Config::default());
        let manager = OutputManager::new(config);
        let results = create_test_results();
        
        let output = manager.prepare_output(&results).unwrap();
        
        assert_eq!(output.summary.total_hosts, 2);
        assert_eq!(output.summary.total_ports, 3);
        assert_eq!(output.summary.open_ports, 2);
        assert_eq!(output.summary.closed_ports, 1);
        assert_eq!(output.hosts.len(), 2);
    }

    #[tokio::test]
    async fn test_json_output() {
        let config = Arc::new(Config::default());
        let temp_file = NamedTempFile::new().unwrap();
        let manager = OutputManager::new(config)
            .with_format(OutputFormat::Json)
            .with_file(temp_file.path());
        
        let results = create_test_results();
        let result = manager.output_results(&results).await;
        
        assert!(result.is_ok());
        assert!(temp_file.path().exists());
        
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("summary"));
        assert!(content.contains("hosts"));
    }

    #[tokio::test]
    async fn test_csv_output() {
        let config = Arc::new(Config::default());
        let temp_file = NamedTempFile::new().unwrap();
        let manager = OutputManager::new(config)
            .with_format(OutputFormat::Csv)
            .with_file(temp_file.path());
        
        let results = create_test_results();
        let result = manager.output_results(&results).await;
        
        assert!(result.is_ok());
        assert!(temp_file.path().exists());
        
        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("IP,Port,Protocol,State"));
        assert!(content.contains("192.168.1.1,80,tcp,open"));
    }

    #[test]
    fn test_format_human() {
        let config = Arc::new(Config::default());
        let manager = OutputManager::new(config);
        let results = create_test_results();
        let output = manager.prepare_output(&results).unwrap();
        
        let human_output = manager.format_human(&output).unwrap();
        
        assert!(human_output.contains("cyNetMapper Scan Results"));
        assert!(human_output.contains("192.168.1.1"));
        assert!(human_output.contains("80/tcp"));
        assert!(human_output.contains("open"));
    }

    #[test]
    fn test_format_xml() {
        let config = Arc::new(Config::default());
        let manager = OutputManager::new(config);
        let results = create_test_results();
        let output = manager.prepare_output(&results).unwrap();
        
        let xml_output = manager.format_xml(&output).unwrap();
        
        assert!(xml_output.contains("<?xml version"));
        assert!(xml_output.contains("<cynetmapper_scan>"));
        assert!(xml_output.contains("<summary>"));
        assert!(xml_output.contains("<hosts>"));
    }

    #[test]
    fn test_format_csv() {
        let config = Arc::new(Config::default());
        let manager = OutputManager::new(config);
        let results = create_test_results();
        let output = manager.prepare_output(&results).unwrap();
        
        let csv_output = manager.format_csv(&output).unwrap();
        
        assert!(csv_output.contains("IP,Port,Protocol,State"));
        assert!(csv_output.contains("192.168.1.1,80,tcp,open"));
        assert!(csv_output.contains("192.168.1.2,22,tcp,closed"));
    }

    #[test]
    fn test_format_nmap_xml() {
        let config = Arc::new(Config::default());
        let manager = OutputManager::new(config);
        let results = create_test_results();
        let output = manager.prepare_output(&results).unwrap();
        
        let nmap_xml = manager.format_nmap_xml(&output).unwrap();
        
        assert!(nmap_xml.contains("<nmaprun scanner=\"cynetmapper\""));
        assert!(nmap_xml.contains("<host"));
        assert!(nmap_xml.contains("<port protocol=\"tcp\""));
        assert!(nmap_xml.contains("</nmaprun>"));
    }
}
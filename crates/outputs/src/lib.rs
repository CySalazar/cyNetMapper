//! cyNetMapper Output Formats
//!
//! This crate provides multiple output formats for cyNetMapper scan results,
//! including JSON, XML, CSV, HTML, and Nmap-compatible formats.
//!
//! # Features
//!
//! - **JSON**: Structured JSON output with optional schema validation
//! - **XML**: Nmap-compatible XML format
//! - **CSV**: Comma-separated values for spreadsheet import
//! - **HTML**: Interactive HTML reports with charts and filtering
//! - **Gnmap**: Nmap greppable format
//! - **Custom**: Extensible format system
//!
//! # Example
//!
//! ```rust
//! use cynetmapper_outputs::{OutputManager, OutputFormat, ScanResults};
//!
//! let results = ScanResults::default();
//! let manager = OutputManager::new();
//!
//! // Export as JSON
//! manager.export(&results, OutputFormat::Json, "scan_results.json")?;
//!
//! // Export as Nmap XML
//! manager.export(&results, OutputFormat::NmapXml, "scan_results.xml")?;
//! ```

use std::collections::HashMap;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod json;
pub mod nmap;
pub mod utils;

pub use json::*;
pub use nmap::*;
pub use utils::*;

/// Errors that can occur during output operations
#[derive(Error, Debug)]
pub enum OutputError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Template error: {0}")]
    Template(String),
    
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),
    
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

/// Result type for output operations
pub type OutputResult<T> = Result<T, OutputError>;

/// Supported output formats
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum OutputFormat {
    /// JSON format
    Json,
    /// Pretty-printed JSON
    JsonPretty,
    /// XML format
    Xml,
    /// YAML format
    Yaml,
    /// CSV format
    Csv,
    /// HTML report
    Html,
    /// Markdown report
    Markdown,
    /// PDF report
    Pdf,
    /// Nmap XML format
    NmapXml,
    /// Nmap Gnmap format
    NmapGnmap,
    /// Nmap normal format
    NmapNormal,
    /// SQLite database
    Sqlite,
    /// PostgreSQL database
    Postgres,
    /// Network diagram (SVG)
    NetworkDiagram,
    /// Custom template
    Custom(String),
}

/// Scan results data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Scan metadata
    pub metadata: ScanMetadata,
    /// Host results
    pub hosts: Vec<HostResult>,
    /// Scan statistics
    pub statistics: ScanStatistics,
}

/// Scan metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Scan start time
    pub start_time: SystemTime,
    /// Scan end time
    pub end_time: Option<SystemTime>,
    /// Scanner version
    pub scanner_version: String,
    /// Command line arguments
    pub command_line: String,
    /// Scan type
    pub scan_type: String,
    /// Target specification
    pub targets: Vec<String>,
}

/// Host scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    /// Host address
    pub address: String,
    /// Host state (up, down, unknown)
    pub state: HostState,
    /// Hostnames
    pub hostnames: Vec<String>,
    /// Port scan results
    pub ports: Vec<PortResult>,
    /// OS fingerprint
    pub os_fingerprint: Option<OsFingerprint>,
    /// Host discovery method
    pub discovery_method: Option<String>,
    /// Response times
    pub response_times: Vec<Duration>,
}

/// Host state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostState {
    Up,
    Down,
    Unknown,
    Filtered,
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// Port number
    pub port: u16,
    /// Protocol (TCP, UDP, SCTP)
    pub protocol: Protocol,
    /// Port state
    pub state: PortState,
    /// Service information
    pub service: Option<ServiceInfo>,
    /// Banner information
    pub banner: Option<String>,
    /// Response time
    pub response_time: Option<Duration>,
}

/// Network protocol
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
    Icmp,
}

/// Port state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenFiltered,
    ClosedFiltered,
    Unfiltered,
}

/// Service information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name
    pub name: String,
    /// Service version
    pub version: Option<String>,
    /// Service product
    pub product: Option<String>,
    /// Extra information
    pub extra_info: Option<String>,
    /// Confidence level
    pub confidence: f64,
}

/// OS fingerprint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    /// OS family
    pub family: String,
    /// OS version
    pub version: Option<String>,
    /// Device type
    pub device_type: Option<String>,
    /// Confidence level
    pub confidence: f64,
    /// Detection method
    pub method: String,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Total hosts scanned
    pub total_hosts: usize,
    /// Hosts up
    pub hosts_up: usize,
    /// Hosts down
    pub hosts_down: usize,
    /// Total ports scanned
    pub total_ports: usize,
    /// Open ports
    pub open_ports: usize,
    /// Closed ports
    pub closed_ports: usize,
    /// Filtered ports
    pub filtered_ports: usize,
    /// Scan duration
    pub duration: Duration,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Output file path
    pub file_path: Option<String>,
    /// Include timing information
    pub include_timing: bool,
    /// Include raw data
    pub include_raw_data: bool,
    /// Compress output
    pub compress: bool,
    /// Template file for custom formats
    pub template_file: Option<String>,
    /// Additional options
    pub options: HashMap<String, String>,
}

/// Main output manager
#[derive(Debug)]
pub struct OutputManager {
    config: OutputConfig,
}

impl OutputManager {
    /// Create a new output manager with default configuration
    pub fn new() -> Self {
        Self {
            config: OutputConfig::default(),
        }
    }
    
    /// Create a new output manager with custom configuration
    pub fn with_config(config: OutputConfig) -> Self {
        Self { config }
    }
    
    /// Export scan results to the specified format and file
    pub async fn export<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        format: OutputFormat,
        output_path: P,
    ) -> OutputResult<()> {
        let content = match format {
            OutputFormat::Json => {
                json::to_canonical_json(results)?
                    .to_string()
            }
            OutputFormat::JsonPretty => {
                serde_json::to_string_pretty(results)
                    .map_err(|e| OutputError::Serialization(e.to_string()))?
            }
            OutputFormat::NmapXml => {
                nmap::generate_nmap_xml(results)?
            }
            OutputFormat::NmapGnmap => {
                // For Gnmap, we need to use the async export function
                return nmap::export_nmap_gnmap(results, output_path).await;
            }
            OutputFormat::Csv => {
                return self.export_csv(results, output_path).await;
            }
            OutputFormat::Html => {
                return self.export_html(results, output_path).await;
            }
            OutputFormat::Xml => {
                return self.export_xml(results, output_path).await;
            }
            OutputFormat::Yaml => {
                return self.export_yaml(results, output_path).await;
            }
            _ => return Err(OutputError::UnsupportedFormat(format!("{:?}", format))),
        };

        tokio::fs::write(output_path, content).await?;
        Ok(())
    }
    
    /// Export to JSON format
    async fn export_json<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        output_path: P,
        pretty: bool,
    ) -> OutputResult<()> {
        let json_data = if pretty {
            serde_json::to_string_pretty(results)
        } else {
            serde_json::to_string(results)
        }
        .map_err(|e| OutputError::Serialization(e.to_string()))?;
        
        tokio::fs::write(output_path, json_data).await?;
        Ok(())
    }
    
    /// Export to XML format
    async fn export_xml<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        output_path: P,
    ) -> OutputResult<()> {
        // Implementation would use quick-xml to generate XML
        // This is a placeholder
        let xml_data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<scan_results></scan_results>";
        tokio::fs::write(output_path, xml_data).await?;
        Ok(())
    }
    
    /// Export to YAML format
    async fn export_yaml<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        output_path: P,
    ) -> OutputResult<()> {
        let yaml_data = serde_yaml::to_string(results)
            .map_err(|e| OutputError::Serialization(e.to_string()))?;
        
        tokio::fs::write(output_path, yaml_data).await?;
        Ok(())
    }
    
    /// Export to CSV format
    async fn export_csv<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        output_path: P,
    ) -> OutputResult<()> {
        // Implementation would generate CSV from results
        // This is a placeholder
        let csv_data = "host,port,protocol,state,service\n";
        tokio::fs::write(output_path, csv_data).await?;
        Ok(())
    }
    
    /// Export to HTML format
    async fn export_html<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        output_path: P,
    ) -> OutputResult<()> {
        // Implementation would use templates to generate HTML
        // This is a placeholder
        let html_data = "<html><head><title>Scan Results</title></head><body><h1>Scan Results</h1></body></html>";
        tokio::fs::write(output_path, html_data).await?;
        Ok(())
    }
    
    /// Export to Nmap XML format
    async fn export_nmap_xml<P: AsRef<Path>>(
        &self,
        results: &ScanResults,
        output_path: P,
    ) -> OutputResult<()> {
        // Implementation would generate Nmap-compatible XML
        // This is a placeholder
        let nmap_xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nmaprun></nmaprun>";
        tokio::fs::write(output_path, nmap_xml).await?;
        Ok(())
    }
}

impl Default for OutputManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            file_path: None,
            include_timing: true,
            include_raw_data: false,
            compress: false,
            template_file: None,
            options: HashMap::new(),
        }
    }
}

impl Default for ScanResults {
    fn default() -> Self {
        Self {
            metadata: ScanMetadata {
                start_time: SystemTime::now(),
                end_time: None,
                scanner_version: "cyNetMapper 0.1.0".to_string(),
                command_line: "".to_string(),
                scan_type: "tcp_connect".to_string(),
                targets: vec![],
            },
            hosts: vec![],
            statistics: ScanStatistics {
                total_hosts: 0,
                hosts_up: 0,
                hosts_down: 0,
                total_ports: 0,
                open_ports: 0,
                closed_ports: 0,
                filtered_ports: 0,
                duration: Duration::from_secs(0),
                packets_sent: 0,
                packets_received: 0,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_json_export() {
        let output_manager = OutputManager::new();
        let results = ScanResults::default();
        let temp_file = NamedTempFile::new().unwrap();
        
        output_manager
            .export(&results, OutputFormat::Json, temp_file.path())
            .await
            .unwrap();
        
        let content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();
        assert!(!content.is_empty());
        
        // Verify it's valid JSON
        let _: ScanResults = serde_json::from_str(&content).unwrap();
    }

    #[test]
    fn test_output_config_default() {
        let config = OutputConfig::default();
        assert_eq!(config.format, OutputFormat::Json);
        assert!(config.include_timing);
        assert!(!config.include_raw_data);
        assert!(!config.compress);
    }

    #[test]
    fn test_scan_results_serialization() {
        let results = ScanResults::default();
        let json = serde_json::to_string(&results).unwrap();
        let deserialized: ScanResults = serde_json::from_str(&json).unwrap();
        
        assert_eq!(results.metadata.scanner_version, deserialized.metadata.scanner_version);
        assert_eq!(results.hosts.len(), deserialized.hosts.len());
    }
}
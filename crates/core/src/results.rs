//! Scan results and data structures for cyNetMapper

use crate::types::{HostState, IpAddr, PortState, Protocol};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Complete scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Unique scan ID
    pub scan_id: Uuid,
    /// Scan metadata
    pub metadata: ScanMetadata,
    /// Host discovery results
    pub hosts: Vec<HostResult>,
    /// Port scan results
    pub ports: Vec<PortResult>,
    /// Service detection results
    pub services: Vec<ServiceResult>,
    /// OS fingerprinting results
    pub os_fingerprints: Vec<OsFingerprint>,
    /// Scan statistics
    pub statistics: ScanStatistics,
    /// Scan errors and warnings
    pub errors: Vec<ScanError>,
}

/// Scan metadata and configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Scan start time
    pub start_time: SystemTime,
    /// Scan end time
    pub end_time: Option<SystemTime>,
    /// Total scan duration
    pub duration: Option<Duration>,
    /// Scanner version
    pub scanner_version: String,
    /// Scan profile used
    pub scan_profile: String,
    /// Command line arguments
    pub command_line: Option<String>,
    /// Target specification
    pub targets: Vec<String>,
    /// Port specification
    pub ports: String,
    /// Protocols scanned
    pub protocols: Vec<Protocol>,
    /// Scan options
    pub options: HashMap<String, String>,
    /// User who ran the scan
    pub user: Option<String>,
    /// Hostname where scan was run
    pub hostname: Option<String>,
}

/// Host discovery result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostResult {
    /// Host IP address
    pub address: IpAddr,
    /// Hostname (if resolved)
    pub hostname: Option<String>,
    /// Host state
    pub state: HostState,
    /// Response time for host discovery
    pub response_time: Option<Duration>,
    /// Discovery method used
    pub discovery_method: DiscoveryMethod,
    /// MAC address (if available)
    pub mac_address: Option<String>,
    /// Vendor information (if available)
    pub vendor: Option<String>,
    /// Distance (TTL-based)
    pub distance: Option<u8>,
    /// Timestamp of discovery
    pub timestamp: SystemTime,
}

/// Port scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortResult {
    /// Target address
    pub address: SocketAddr,
    /// Protocol used
    pub protocol: Protocol,
    /// Port state
    pub state: PortState,
    /// Response time
    pub response_time: Option<Duration>,
    /// Service name (if detected)
    pub service: Option<String>,
    /// Service version (if detected)
    pub version: Option<String>,
    /// Banner information
    pub banner: Option<String>,
    /// Additional port information
    pub extra_info: HashMap<String, String>,
    /// Timestamp of scan
    pub timestamp: SystemTime,
}

/// Service detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceResult {
    /// Target address
    pub address: SocketAddr,
    /// Protocol used
    pub protocol: Protocol,
    /// Service name
    pub service: String,
    /// Service version
    pub version: Option<String>,
    /// Product name
    pub product: Option<String>,
    /// Extra version information
    pub extra_info: Option<String>,
    /// Service fingerprint
    pub fingerprint: Option<String>,
    /// Confidence level (0-100)
    pub confidence: u8,
    /// Detection method
    pub method: DetectionMethod,
    /// Timestamp of detection
    pub timestamp: SystemTime,
}

/// OS fingerprinting result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    /// Target IP address
    pub address: IpAddr,
    /// OS matches
    pub os_matches: Vec<OsMatch>,
    /// TCP sequence prediction
    pub tcp_sequence: Option<TcpSequence>,
    /// IP ID sequence
    pub ip_id_sequence: Option<IpIdSequence>,
    /// TCP timestamp option
    pub tcp_ts_sequence: Option<TcpTsSequence>,
    /// Fingerprint accuracy
    pub accuracy: u8,
    /// Timestamp of fingerprinting
    pub timestamp: SystemTime,
}

/// OS match information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsMatch {
    /// OS name
    pub name: String,
    /// OS family
    pub family: Option<String>,
    /// OS generation
    pub generation: Option<String>,
    /// Vendor
    pub vendor: Option<String>,
    /// Accuracy percentage
    pub accuracy: u8,
    /// OS classes
    pub os_classes: Vec<OsClass>,
}

/// OS class information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsClass {
    /// OS type (general purpose, router, etc.)
    pub os_type: String,
    /// Vendor
    pub vendor: String,
    /// OS family
    pub os_family: String,
    /// OS generation
    pub os_gen: Option<String>,
    /// Accuracy
    pub accuracy: u8,
}

/// TCP sequence prediction information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpSequence {
    /// Sequence index
    pub index: u32,
    /// Difficulty
    pub difficulty: String,
    /// Values
    pub values: Vec<u32>,
}

/// IP ID sequence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpIdSequence {
    /// Sequence class
    pub class: String,
    /// Values
    pub values: Vec<u16>,
}

/// TCP timestamp sequence information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpTsSequence {
    /// Sequence class
    pub class: String,
    /// Values
    pub values: Vec<u32>,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    /// Total hosts scanned
    pub hosts_total: u32,
    /// Hosts found up
    pub hosts_up: u32,
    /// Hosts found down
    pub hosts_down: u32,
    /// Total ports scanned
    pub ports_total: u32,
    /// Open ports found
    pub ports_open: u32,
    /// Closed ports found
    pub ports_closed: u32,
    /// Filtered ports found
    pub ports_filtered: u32,
    /// Services detected
    pub services_detected: u32,
    /// OS fingerprints collected
    pub os_fingerprints: u32,
    /// Total scan time
    pub scan_time: Duration,
    /// Average response time
    pub avg_response_time: Option<Duration>,
    /// Packets sent
    pub packets_sent: u64,
    /// Packets received
    pub packets_received: u64,
    /// Packet loss percentage
    pub packet_loss: f64,
    /// Scan rate (packets per second)
    pub scan_rate: f64,
}

/// Scan error information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    /// Error severity
    pub severity: ErrorSeverity,
    /// Error message
    pub message: String,
    /// Target that caused the error
    pub target: Option<String>,
    /// Error code
    pub code: Option<String>,
    /// Timestamp of error
    pub timestamp: SystemTime,
}

/// Discovery methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// ICMP Echo (ping)
    IcmpEcho,
    /// ICMP Timestamp
    IcmpTimestamp,
    /// ICMP Address Mask
    IcmpAddressMask,
    /// TCP SYN to common ports
    TcpSyn,
    /// TCP ACK
    TcpAck,
    /// UDP probe
    UdpProbe,
    /// ARP request (local network)
    Arp,
    /// Connect scan
    TcpConnect,
    /// DNS resolution
    DnsResolution,
    /// DNS lookup
    DnsLookup,
}

/// Service detection methods
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectionMethod {
    /// Banner grabbing
    BannerGrab,
    /// Service probe
    ServiceProbe,
    /// Version detection
    VersionDetection,
    /// SSL/TLS certificate
    SslCertificate,
    /// HTTP headers
    HttpHeaders,
    /// SNMP community strings
    SnmpCommunity,
}

/// Error severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    /// Informational message
    Info,
    /// Warning message
    Warning,
    /// Error message
    Error,
    /// Critical error
    Critical,
}

impl Default for ScanResults {
    fn default() -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            metadata: ScanMetadata::default(),
            hosts: Vec::new(),
            ports: Vec::new(),
            services: Vec::new(),
            os_fingerprints: Vec::new(),
            statistics: ScanStatistics::default(),
            errors: Vec::new(),
        }
    }
}

impl Default for ScanMetadata {
    fn default() -> Self {
        Self {
            start_time: SystemTime::now(),
            end_time: None,
            duration: None,
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_profile: "default".to_string(),
            command_line: None,
            targets: Vec::new(),
            ports: "default".to_string(),
            protocols: vec![Protocol::Tcp],
            options: HashMap::new(),
            user: None,
            hostname: None,
        }
    }
}

impl Default for ScanStatistics {
    fn default() -> Self {
        Self {
            hosts_total: 0,
            hosts_up: 0,
            hosts_down: 0,
            ports_total: 0,
            ports_open: 0,
            ports_closed: 0,
            ports_filtered: 0,
            services_detected: 0,
            os_fingerprints: 0,
            scan_time: Duration::from_secs(0),
            avg_response_time: None,
            packets_sent: 0,
            packets_received: 0,
            packet_loss: 0.0,
            scan_rate: 0.0,
        }
    }
}

impl ScanResults {
    /// Create new scan results with metadata
    pub fn new(metadata: ScanMetadata) -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            metadata,
            hosts: Vec::new(),
            ports: Vec::new(),
            services: Vec::new(),
            os_fingerprints: Vec::new(),
            statistics: ScanStatistics::default(),
            errors: Vec::new(),
        }
    }

    /// Add a host result
    pub fn add_host(&mut self, host: HostResult) {
        self.hosts.push(host);
        self.update_statistics();
    }

    /// Add a port result
    pub fn add_port(&mut self, port: PortResult) {
        self.ports.push(port);
        self.update_statistics();
    }

    /// Add a service result
    pub fn add_service(&mut self, service: ServiceResult) {
        self.services.push(service);
        self.update_statistics();
    }

    /// Add an OS fingerprint
    pub fn add_os_fingerprint(&mut self, fingerprint: OsFingerprint) {
        self.os_fingerprints.push(fingerprint);
        self.update_statistics();
    }

    /// Add an error
    pub fn add_error(&mut self, error: ScanError) {
        self.errors.push(error);
    }

    /// Mark scan as completed
    pub fn complete(&mut self) {
        let now = SystemTime::now();
        self.metadata.end_time = Some(now);
        self.metadata.duration = now.duration_since(self.metadata.start_time).ok();
        self.update_statistics();
    }

    /// Update scan statistics
    fn update_statistics(&mut self) {
        self.statistics.hosts_total = self.hosts.len() as u32;
        self.statistics.hosts_up = self.hosts.iter()
            .filter(|h| h.state == HostState::Up)
            .count() as u32;
        self.statistics.hosts_down = self.statistics.hosts_total - self.statistics.hosts_up;

        self.statistics.ports_total = self.ports.len() as u32;
        self.statistics.ports_open = self.ports.iter()
            .filter(|p| p.state == PortState::Open)
            .count() as u32;
        self.statistics.ports_closed = self.ports.iter()
            .filter(|p| p.state == PortState::Closed)
            .count() as u32;
        self.statistics.ports_filtered = self.ports.iter()
            .filter(|p| p.state == PortState::Filtered)
            .count() as u32;

        self.statistics.services_detected = self.services.len() as u32;
        self.statistics.os_fingerprints = self.os_fingerprints.len() as u32;

        // Calculate average response time
        let response_times: Vec<Duration> = self.ports.iter()
            .filter_map(|p| p.response_time)
            .collect();
        
        if !response_times.is_empty() {
            let total_time: Duration = response_times.iter().sum();
            self.statistics.avg_response_time = Some(total_time / response_times.len() as u32);
        }

        // Update scan time
        if let Some(end_time) = self.metadata.end_time {
            if let Ok(duration) = end_time.duration_since(self.metadata.start_time) {
                self.statistics.scan_time = duration;
            }
        }
    }

    /// Get hosts by state
    pub fn hosts_by_state(&self, state: HostState) -> Vec<&HostResult> {
        self.hosts.iter().filter(|h| h.state == state).collect()
    }

    /// Get ports by state
    pub fn ports_by_state(&self, state: PortState) -> Vec<&PortResult> {
        self.ports.iter().filter(|p| p.state == state).collect()
    }

    /// Get open ports for a specific host
    pub fn open_ports_for_host(&self, address: &IpAddr) -> Vec<&PortResult> {
        self.ports.iter()
            .filter(|p| p.address.ip() == *address && p.state == PortState::Open)
            .collect()
    }

    /// Get services for a specific host
    pub fn services_for_host(&self, address: &IpAddr) -> Vec<&ServiceResult> {
        self.services.iter()
            .filter(|s| s.address.ip() == *address)
            .collect()
    }

    /// Get errors by severity
    pub fn errors_by_severity(&self, severity: ErrorSeverity) -> Vec<&ScanError> {
        self.errors.iter().filter(|e| e.severity == severity).collect()
    }

    /// Check if scan has critical errors
    pub fn has_critical_errors(&self) -> bool {
        self.errors.iter().any(|e| e.severity == ErrorSeverity::Critical)
    }

    /// Get scan summary
    pub fn summary(&self) -> String {
        format!(
            "Scan {} completed in {:?}. Found {} hosts ({} up, {} down), {} ports ({} open, {} closed, {} filtered), {} services detected.",
            self.scan_id,
            self.statistics.scan_time,
            self.statistics.hosts_total,
            self.statistics.hosts_up,
            self.statistics.hosts_down,
            self.statistics.ports_total,
            self.statistics.ports_open,
            self.statistics.ports_closed,
            self.statistics.ports_filtered,
            self.statistics.services_detected
        )
    }
}

impl HostResult {
    /// Create a new host result
    pub fn new(address: IpAddr, state: HostState, method: DiscoveryMethod) -> Self {
        Self {
            address,
            hostname: None,
            state,
            response_time: None,
            discovery_method: method,
            mac_address: None,
            vendor: None,
            distance: None,
            timestamp: SystemTime::now(),
        }
    }

    /// Set hostname
    pub fn with_hostname(mut self, hostname: String) -> Self {
        self.hostname = Some(hostname);
        self
    }

    /// Set response time
    pub fn with_response_time(mut self, response_time: Duration) -> Self {
        self.response_time = Some(response_time);
        self
    }

    /// Set MAC address
    pub fn with_mac_address(mut self, mac_address: String) -> Self {
        self.mac_address = Some(mac_address);
        self
    }
}

impl PortResult {
    /// Create a new port result
    pub fn new(address: SocketAddr, protocol: Protocol, state: PortState) -> Self {
        Self {
            address,
            protocol,
            state,
            response_time: None,
            service: None,
            version: None,
            banner: None,
            extra_info: HashMap::new(),
            timestamp: SystemTime::now(),
        }
    }

    /// Set response time
    pub fn with_response_time(mut self, response_time: Duration) -> Self {
        self.response_time = Some(response_time);
        self
    }

    /// Set service information
    pub fn with_service(mut self, service: String, version: Option<String>) -> Self {
        self.service = Some(service);
        self.version = version;
        self
    }

    /// Set banner
    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner);
        self
    }

    /// Add extra information
    pub fn with_extra_info(mut self, key: String, value: String) -> Self {
        self.extra_info.insert(key, value);
        self
    }
}

impl ScanError {
    /// Create a new scan error
    pub fn new(severity: ErrorSeverity, message: String) -> Self {
        Self {
            severity,
            message,
            target: None,
            code: None,
            timestamp: SystemTime::now(),
        }
    }

    /// Set target
    pub fn with_target(mut self, target: String) -> Self {
        self.target = Some(target);
        self
    }

    /// Set error code
    pub fn with_code(mut self, code: String) -> Self {
        self.code = Some(code);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_scan_results_creation() {
        let metadata = ScanMetadata::default();
        let mut results = ScanResults::new(metadata);
        
        assert_eq!(results.hosts.len(), 0);
        assert_eq!(results.ports.len(), 0);
        assert_eq!(results.statistics.hosts_total, 0);
    }

    #[test]
    fn test_adding_results() {
        let mut results = ScanResults::default();
        
        let host = HostResult::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            HostState::Up,
            DiscoveryMethod::TcpConnect
        );
        results.add_host(host);
        
        let port = PortResult::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
            Protocol::Tcp,
            PortState::Open
        );
        results.add_port(port);
        
        assert_eq!(results.statistics.hosts_total, 1);
        assert_eq!(results.statistics.hosts_up, 1);
        assert_eq!(results.statistics.ports_total, 1);
        assert_eq!(results.statistics.ports_open, 1);
    }

    #[test]
    fn test_host_result_builder() {
        let host = HostResult::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            HostState::Up,
            DiscoveryMethod::IcmpEcho
        )
        .with_hostname("test.local".to_string())
        .with_response_time(Duration::from_millis(10))
        .with_mac_address("00:11:22:33:44:55".to_string());
        
        assert_eq!(host.hostname, Some("test.local".to_string()));
        assert_eq!(host.response_time, Some(Duration::from_millis(10)));
        assert_eq!(host.mac_address, Some("00:11:22:33:44:55".to_string()));
    }

    #[test]
    fn test_port_result_builder() {
        let port = PortResult::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
            Protocol::Tcp,
            PortState::Open
        )
        .with_response_time(Duration::from_millis(5))
        .with_service("http".to_string(), Some("Apache/2.4".to_string()))
        .with_banner("HTTP/1.1 200 OK".to_string())
        .with_extra_info("ssl".to_string(), "false".to_string());
        
        assert_eq!(port.response_time, Some(Duration::from_millis(5)));
        assert_eq!(port.service, Some("http".to_string()));
        assert_eq!(port.version, Some("Apache/2.4".to_string()));
        assert_eq!(port.banner, Some("HTTP/1.1 200 OK".to_string()));
        assert_eq!(port.extra_info.get("ssl"), Some(&"false".to_string()));
    }

    #[test]
    fn test_scan_error_builder() {
        let error = ScanError::new(
            ErrorSeverity::Warning,
            "Connection timeout".to_string()
        )
        .with_target("192.168.1.1:80".to_string())
        .with_code("TIMEOUT".to_string());
        
        assert_eq!(error.severity, ErrorSeverity::Warning);
        assert_eq!(error.message, "Connection timeout");
        assert_eq!(error.target, Some("192.168.1.1:80".to_string()));
        assert_eq!(error.code, Some("TIMEOUT".to_string()));
    }

    #[test]
    fn test_results_filtering() {
        let mut results = ScanResults::default();
        
        // Add some test data
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        results.add_host(HostResult::new(ip, HostState::Up, DiscoveryMethod::TcpConnect));
        results.add_port(PortResult::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 80)),
            Protocol::Tcp,
            PortState::Open
        ));
        results.add_port(PortResult::new(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 1, 1), 443)),
            Protocol::Tcp,
            PortState::Closed
        ));
        
        let up_hosts = results.hosts_by_state(HostState::Up);
        assert_eq!(up_hosts.len(), 1);
        
        let open_ports = results.ports_by_state(PortState::Open);
        assert_eq!(open_ports.len(), 1);
        
        let host_ports = results.open_ports_for_host(&ip);
        assert_eq!(host_ports.len(), 1);
        assert_eq!(host_ports[0].address.port(), 80);
    }

    #[test]
    fn test_scan_completion() {
        let mut results = ScanResults::default();
        let start_time = results.metadata.start_time;
        
        // Simulate some scan time
        std::thread::sleep(Duration::from_millis(10));
        
        results.complete();
        
        assert!(results.metadata.end_time.is_some());
        assert!(results.metadata.duration.is_some());
        assert!(results.metadata.end_time.unwrap() > start_time);
    }
}
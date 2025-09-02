//! Common types and utilities for network probes

use cynetmapper_core::{
    types::{IpAddr, Protocol, PortState},
    error::{Error, Result},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime};
use thiserror::Error;

/// Common probe error types
#[derive(Error, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProbeError {
    #[error("Connection timeout")]
    Timeout,
    
    #[error("Connection refused")]
    ConnectionRefused,
    
    #[error("Host unreachable")]
    HostUnreachable,
    
    #[error("Network unreachable")]
    NetworkUnreachable,
    
    #[error("Permission denied")]
    PermissionDenied,
    
    #[error("Invalid target: {0}")]
    InvalidTarget(String),
    
    #[error("Protocol not supported: {0:?}")]
    UnsupportedProtocol(Protocol),
    
    #[error("Raw socket operation failed: {0}")]
    RawSocketError(String),
    
    #[error("Parse error: {0}")]
    ParseError(String),
    
    #[error("IO error: {0}")]
    IoError(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Common probe options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeOptions {
    /// Probe timeout
    pub timeout: Duration,
    
    /// Number of retries
    pub retries: u32,
    
    /// Delay between retries
    pub retry_delay: Duration,
    
    /// Source port (0 for random)
    pub source_port: u16,
    
    /// Source IP address (None for auto)
    pub source_ip: Option<IpAddr>,
    
    /// Custom payload
    pub payload: Option<Vec<u8>>,
    
    /// Additional options
    pub extra_options: HashMap<String, String>,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            retries: 0,
            retry_delay: Duration::from_millis(100),
            source_port: 0,
            source_ip: None,
            payload: None,
            extra_options: HashMap::new(),
        }
    }
}

/// Common probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeResult {
    /// Target address
    pub target: SocketAddr,
    
    /// Protocol used
    pub protocol: Protocol,
    
    /// Port state
    pub state: PortState,
    
    /// Response time
    pub response_time: Option<Duration>,
    
    /// Probe timestamp
    pub timestamp: SystemTime,
    
    /// Error if probe failed
    pub error: Option<ProbeError>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    
    /// Raw response data
    pub raw_response: Option<Vec<u8>>,
}

impl ProbeResult {
    /// Create a new successful probe result
    pub fn success(
        target: SocketAddr,
        protocol: Protocol,
        state: PortState,
        response_time: Duration,
    ) -> Self {
        Self {
            target,
            protocol,
            state,
            response_time: Some(response_time),
            timestamp: SystemTime::now(),
            error: None,
            metadata: HashMap::new(),
            raw_response: None,
        }
    }
    
    /// Create a new failed probe result
    pub fn failure(
        target: SocketAddr,
        protocol: Protocol,
        error: ProbeError,
    ) -> Self {
        Self {
            target,
            protocol,
            state: PortState::Filtered, // Default for failed probes
            response_time: None,
            timestamp: SystemTime::now(),
            error: Some(error),
            metadata: HashMap::new(),
            raw_response: None,
        }
    }
    
    /// Check if probe was successful
    pub fn is_success(&self) -> bool {
        self.error.is_none() && matches!(self.state, PortState::Open | PortState::Closed)
    }
    
    /// Check if port is open
    pub fn is_open(&self) -> bool {
        matches!(self.state, PortState::Open)
    }
    
    /// Check if port is closed
    pub fn is_closed(&self) -> bool {
        matches!(self.state, PortState::Closed)
    }
    
    /// Check if port is filtered
    pub fn is_filtered(&self) -> bool {
        matches!(self.state, PortState::Filtered)
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Add raw response data
    pub fn with_raw_response(mut self, data: Vec<u8>) -> Self {
        self.raw_response = Some(data);
        self
    }
    
    /// Get metadata value
    pub fn get_metadata(&self, key: &str) -> Option<&String> {
        self.metadata.get(key)
    }
}

/// Probe statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProbeStats {
    /// Total probes sent
    pub probes_sent: u64,
    
    /// Successful probes
    pub probes_successful: u64,
    
    /// Failed probes
    pub probes_failed: u64,
    
    /// Timeouts
    pub timeouts: u64,
    
    /// Connection refused
    pub connection_refused: u64,
    
    /// Host unreachable
    pub host_unreachable: u64,
    
    /// Open ports found
    pub open_ports: u64,
    
    /// Closed ports found
    pub closed_ports: u64,
    
    /// Filtered ports found
    pub filtered_ports: u64,
    
    /// Total probe time
    pub total_time: Duration,
    
    /// Average response time
    pub avg_response_time: Option<Duration>,
    
    /// Min response time
    pub min_response_time: Option<Duration>,
    
    /// Max response time
    pub max_response_time: Option<Duration>,
}

impl ProbeStats {
    /// Create new empty statistics
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Update statistics with a probe result
    pub fn update(&mut self, result: &ProbeResult) {
        self.probes_sent += 1;
        
        if result.is_success() {
            self.probes_successful += 1;
            
            // Update response time statistics
            if let Some(response_time) = result.response_time {
                self.update_response_times(response_time);
            }
            
            // Update port state statistics
            match result.state {
                PortState::Open => self.open_ports += 1,
                PortState::Closed => self.closed_ports += 1,
                PortState::Filtered => self.filtered_ports += 1,
                PortState::Unfiltered => self.open_ports += 1, // Treat as open
                PortState::OpenFiltered => self.filtered_ports += 1, // Treat as filtered
                PortState::ClosedFiltered => self.filtered_ports += 1, // Treat as filtered
            }
        } else {
            self.probes_failed += 1;
            
            // Update error statistics
            if let Some(error) = &result.error {
                match error {
                    ProbeError::Timeout => self.timeouts += 1,
                    ProbeError::ConnectionRefused => self.connection_refused += 1,
                    ProbeError::HostUnreachable | ProbeError::NetworkUnreachable => {
                        self.host_unreachable += 1
                    },
                    _ => {}, // Other errors
                }
            }
        }
    }
    
    /// Update response time statistics
    fn update_response_times(&mut self, response_time: Duration) {
        // Update average
        if let Some(avg) = self.avg_response_time {
            let total_successful = self.probes_successful as f64;
            let new_avg = (avg.as_nanos() as f64 * (total_successful - 1.0) + response_time.as_nanos() as f64) / total_successful;
            self.avg_response_time = Some(Duration::from_nanos(new_avg as u64));
        } else {
            self.avg_response_time = Some(response_time);
        }
        
        // Update min
        if let Some(min) = self.min_response_time {
            if response_time < min {
                self.min_response_time = Some(response_time);
            }
        } else {
            self.min_response_time = Some(response_time);
        }
        
        // Update max
        if let Some(max) = self.max_response_time {
            if response_time > max {
                self.max_response_time = Some(response_time);
            }
        } else {
            self.max_response_time = Some(response_time);
        }
    }
    
    /// Get success rate as percentage
    pub fn success_rate(&self) -> f64 {
        if self.probes_sent == 0 {
            0.0
        } else {
            (self.probes_successful as f64 / self.probes_sent as f64) * 100.0
        }
    }
    
    /// Get timeout rate as percentage
    pub fn timeout_rate(&self) -> f64 {
        if self.probes_sent == 0 {
            0.0
        } else {
            (self.timeouts as f64 / self.probes_sent as f64) * 100.0
        }
    }
    
    /// Increment the number of probes sent
    pub fn increment_probes(&mut self) {
        self.probes_sent += 1;
    }
    
    /// Increment the number of failed probes
    pub fn increment_failed(&mut self) {
        self.probes_failed += 1;
    }
}

/// Probe capability flags
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProbeCapabilities {
    /// Supports TCP probes
    pub tcp: bool,
    
    /// Supports UDP probes
    pub udp: bool,
    
    /// Supports ICMP probes
    pub icmp: bool,
    
    /// Supports SCTP probes
    pub sctp: bool,
    
    /// Supports raw sockets
    pub raw_sockets: bool,
    
    /// Supports IPv6
    pub ipv6: bool,
    
    /// Supports service detection
    pub service_detection: bool,
    
    /// Supports banner grabbing
    pub banner_grabbing: bool,
    
    /// Supports OS fingerprinting
    pub os_fingerprinting: bool,
}

impl Default for ProbeCapabilities {
    fn default() -> Self {
        Self {
            tcp: true,
            udp: false, // Requires raw sockets for proper UDP probing
            icmp: false, // Requires raw sockets
            sctp: false, // Requires raw sockets
            raw_sockets: false, // Platform dependent
            ipv6: true,
            service_detection: true,
            banner_grabbing: true,
            os_fingerprinting: false, // Advanced feature
        }
    }
}

impl ProbeCapabilities {
    /// Check if protocol is supported
    pub fn supports_protocol(&self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::Tcp => self.tcp,
            Protocol::Udp => self.udp,
            Protocol::Icmp => self.icmp,
            Protocol::Sctp => self.sctp,
        }
    }
    
    /// Get supported protocols
    pub fn supported_protocols(&self) -> Vec<Protocol> {
        let mut protocols = Vec::new();
        
        if self.tcp {
            protocols.push(Protocol::Tcp);
        }
        if self.udp {
            protocols.push(Protocol::Udp);
        }
        if self.icmp {
            protocols.push(Protocol::Icmp);
        }
        if self.sctp {
            protocols.push(Protocol::Sctp);
        }
        
        protocols
    }
}

/// Utility functions for probe operations
pub mod utils {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    
    /// Check if an IP address is valid for probing
    pub fn is_valid_probe_target(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => is_valid_ipv4_target(ipv4),
            IpAddr::V6(ipv6) => is_valid_ipv6_target(ipv6),
        }
    }
    
    /// Check if an IPv4 address is valid for probing
    pub fn is_valid_ipv4_target(ip: Ipv4Addr) -> bool {
        // Exclude special-use addresses
        !ip.is_loopback() &&
        !ip.is_broadcast() &&
        !ip.is_multicast() &&
        !ip.is_unspecified() &&
        !is_ipv4_reserved(ip)
    }
    
    /// Check if an IPv6 address is valid for probing
    pub fn is_valid_ipv6_target(ip: Ipv6Addr) -> bool {
        // Exclude special-use addresses
        !ip.is_loopback() &&
        !ip.is_multicast() &&
        !ip.is_unspecified()
    }
    
    /// Check if IPv4 address is in reserved ranges
    fn is_ipv4_reserved(ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        
        // RFC 5735 special-use addresses
        match octets {
            [0, ..] => true,                    // "This" network
            [10, ..] => false,                  // Private (allow)
            [127, ..] => true,                  // Loopback
            [169, 254, ..] => true,             // Link-local
            [172, 16..=31, ..] => false,        // Private (allow)
            [192, 0, 0, ..] => true,            // IETF Protocol Assignments
            [192, 0, 2, ..] => true,            // TEST-NET-1
            [192, 88, 99, ..] => true,          // 6to4 Relay Anycast
            [192, 168, ..] => false,            // Private (allow)
            [198, 18..=19, ..] => true,         // Network Interconnect Device Benchmark Testing
            [198, 51, 100, ..] => true,         // TEST-NET-2
            [203, 0, 113, ..] => true,          // TEST-NET-3
            [224..=255, ..] => true,            // Multicast and reserved
            _ => false,
        }
    }
    
    /// Convert ProbeError to core Error
    pub fn probe_error_to_core_error(error: ProbeError) -> Error {
        match error {
            ProbeError::Timeout => Error::Timeout { timeout_ms: 5000 },
            ProbeError::ConnectionRefused => Error::Network(cynetmapper_core::error::NetworkError::ConnectionFailed { address: "unknown".to_string(), port: 0 }),
            ProbeError::HostUnreachable => Error::Network(cynetmapper_core::error::NetworkError::NetworkUnreachable { network: "host".to_string() }),
            ProbeError::NetworkUnreachable => Error::Network(cynetmapper_core::error::NetworkError::NetworkUnreachable { network: "network".to_string() }),
            ProbeError::PermissionDenied => Error::InsufficientPrivileges { operation: "Raw socket access".to_string() },
            ProbeError::InvalidTarget(msg) => Error::InvalidTarget(msg),
            ProbeError::UnsupportedProtocol(proto) => Error::FeatureNotAvailable { feature: format!("Protocol {:?}", proto) },
            ProbeError::RawSocketError(msg) => Error::Network(cynetmapper_core::error::NetworkError::SocketCreationFailed { reason: msg }),
            ProbeError::ParseError(msg) => Error::Parse(cynetmapper_core::error::ParseError::InvalidJson { reason: msg }),
            ProbeError::IoError(msg) => Error::Io(std::io::Error::new(std::io::ErrorKind::Other, msg)),
            ProbeError::Internal(msg) => Error::Internal { message: msg },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    #[test]
    fn test_probe_options_default() {
        let options = ProbeOptions::default();
        assert_eq!(options.timeout, Duration::from_secs(3));
        assert_eq!(options.retries, 0);
        assert_eq!(options.source_port, 0);
        assert!(options.source_ip.is_none());
        assert!(options.payload.is_none());
    }

    #[test]
    fn test_probe_result_success() {
        let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let result = ProbeResult::success(
            target,
            Protocol::Tcp,
            PortState::Open,
            Duration::from_millis(100),
        );
        
        assert!(result.is_success());
        assert!(result.is_open());
        assert!(!result.is_closed());
        assert!(!result.is_filtered());
        assert!(result.error.is_none());
        assert!(result.response_time.is_some());
    }

    #[test]
    fn test_probe_result_failure() {
        let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let result = ProbeResult::failure(
            target,
            Protocol::Tcp,
            ProbeError::Timeout,
        );
        
        assert!(!result.is_success());
        assert!(!result.is_open());
        assert!(!result.is_closed());
        assert!(result.is_filtered());
        assert!(result.error.is_some());
        assert!(result.response_time.is_none());
    }

    #[test]
    fn test_probe_stats() {
        let mut stats = ProbeStats::new();
        let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        
        // Add successful result
        let success_result = ProbeResult::success(
            target,
            Protocol::Tcp,
            PortState::Open,
            Duration::from_millis(100),
        );
        stats.update(&success_result);
        
        assert_eq!(stats.probes_sent, 1);
        assert_eq!(stats.probes_successful, 1);
        assert_eq!(stats.open_ports, 1);
        assert_eq!(stats.success_rate(), 100.0);
        
        // Add failed result
        let failed_result = ProbeResult::failure(
            target,
            Protocol::Tcp,
            ProbeError::Timeout,
        );
        stats.update(&failed_result);
        
        assert_eq!(stats.probes_sent, 2);
        assert_eq!(stats.probes_failed, 1);
        assert_eq!(stats.timeouts, 1);
        assert_eq!(stats.success_rate(), 50.0);
        assert_eq!(stats.timeout_rate(), 50.0);
    }

    #[test]
    fn test_probe_capabilities() {
        let caps = ProbeCapabilities::default();
        
        assert!(caps.supports_protocol(Protocol::Tcp));
        assert!(!caps.supports_protocol(Protocol::Udp));
        assert!(!caps.supports_protocol(Protocol::Icmp));
        
        let protocols = caps.supported_protocols();
        assert!(protocols.contains(&Protocol::Tcp));
        assert!(!protocols.contains(&Protocol::Udp));
    }

    #[test]
    fn test_valid_probe_targets() {
        use utils::*;
        
        // Valid targets
        assert!(is_valid_ipv4_target(Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_valid_ipv4_target(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(is_valid_ipv6_target(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)));
        
        // Invalid targets
        assert!(!is_valid_ipv4_target(Ipv4Addr::new(127, 0, 0, 1))); // Loopback
        assert!(!is_valid_ipv4_target(Ipv4Addr::new(224, 0, 0, 1))); // Multicast
        assert!(!is_valid_ipv4_target(Ipv4Addr::new(0, 0, 0, 0)));   // Unspecified
        assert!(!is_valid_ipv6_target(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))); // Loopback
    }

    #[test]
    fn test_probe_result_metadata() {
        let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let result = ProbeResult::success(
            target,
            Protocol::Tcp,
            PortState::Open,
            Duration::from_millis(100),
        )
        .with_metadata("service".to_string(), "http".to_string())
        .with_raw_response(b"HTTP/1.1 200 OK".to_vec());
        
        assert_eq!(result.get_metadata("service"), Some(&"http".to_string()));
        assert!(result.raw_response.is_some());
        assert_eq!(result.raw_response.as_ref().unwrap(), b"HTTP/1.1 200 OK");
    }
}
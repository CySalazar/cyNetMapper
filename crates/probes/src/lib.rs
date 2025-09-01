//! Network probes for cyNetMapper
//!
//! This crate provides various network probing capabilities including:
//! - TCP Connect scans
//! - UDP probes
//! - ICMP ping and traceroute
//! - Service detection
//! - Banner grabbing
//! - OS fingerprinting
//! - Comprehensive probe management

pub mod banner_grabbing;
pub mod common;
pub mod icmp;
pub mod manager;
pub mod os_fingerprinting;
pub mod service_detection;
pub mod tcp;
pub mod udp;

// Re-export commonly used types
pub use banner_grabbing::{BannerGrabber, BannerOptions, BannerResult};
pub use common::{ProbeCapabilities, ProbeError, ProbeOptions, ProbeResult, ProbeStats};
pub use icmp::{IcmpProbe, IcmpProbeOptions, IcmpProbeResult};
pub use manager::{ComprehensiveProbeResult, ProbeManager, ProbeManagerConfig};
pub use os_fingerprinting::{OsFingerprint, OsFingerprinter};
pub use service_detection::{ServiceDetector, ServiceInfo};
pub use tcp::{TcpProbe, TcpProbeOptions, TcpProbeResult};
pub use udp::{UdpProbe, UdpProbeOptions, UdpProbeResult};

// Re-export from core
pub use cynetmapper_core::{
    types::{IpAddr, Protocol, PortState},
    error::{Error, Result},
    config::Config,
};



/// Constants for common probe configurations
pub mod constants {
    use std::time::Duration;
    
    /// Default probe timeout
    pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
    
    /// Default connection timeout for TCP probes
    pub const DEFAULT_TCP_TIMEOUT: Duration = Duration::from_secs(5);
    
    /// Default UDP probe timeout
    pub const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(2);
    
    /// Default ICMP probe timeout
    pub const DEFAULT_ICMP_TIMEOUT: Duration = Duration::from_secs(1);
    
    /// Default banner grab timeout
    pub const DEFAULT_BANNER_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// Maximum banner size to grab
    pub const MAX_BANNER_SIZE: usize = 4096;
    
    /// Common TCP ports for service detection
    pub const COMMON_TCP_PORTS: &[u16] = &[
        21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900
    ];
    
    /// Common UDP ports for service detection
    pub const COMMON_UDP_PORTS: &[u16] = &[
        53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500
    ];
    
    /// Top 100 TCP ports (most commonly used)
    pub const TOP_100_TCP_PORTS: &[u16] = &[
        7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
        139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
        554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
        1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
        4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
        6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
        49152, 49153, 49154, 49155, 49156, 49157
    ];
    
    /// Top 100 UDP ports (most commonly used)
    pub const TOP_100_UDP_PORTS: &[u16] = &[
        7, 9, 17, 19, 49, 53, 67, 68, 69, 80, 88, 111, 120, 123, 135, 136, 137, 138, 139,
        158, 161, 162, 177, 427, 443, 497, 500, 514, 515, 518, 520, 593, 623, 626, 631,
        996, 997, 998, 999, 1022, 1023, 1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434,
        1645, 1646, 1701, 1718, 1719, 1720, 1721, 1723, 1812, 1813, 1900, 2000, 2048,
        2049, 2222, 2223, 3283, 3456, 4444, 4500, 5000, 5060, 5353, 5632, 9200, 10000,
        17185, 20031, 30718, 31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774,
        32775, 32776, 32777, 32778, 32779, 32780, 32781, 32782, 32783, 32784, 49152,
        49153, 49154, 49155, 49156, 49157, 49158, 49159, 49160, 49161
    ];
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::sync::Arc;

    #[test]
    fn test_probe_manager_creation() {
        let config = Arc::new(Config::default());
        let _manager = ProbeManager::new(config);
        // Manager creation should succeed
    }

    #[test]
    fn test_constants() {
        assert!(!constants::COMMON_TCP_PORTS.is_empty());
        assert!(!constants::COMMON_UDP_PORTS.is_empty());
        assert!(!constants::TOP_100_TCP_PORTS.is_empty());
        assert!(!constants::TOP_100_UDP_PORTS.is_empty());
        assert_eq!(constants::TOP_100_TCP_PORTS.len(), 100);
        assert_eq!(constants::TOP_100_UDP_PORTS.len(), 100);
    }

    #[test]
    fn test_port_lists_sorted() {
        // Verify that port lists are sorted for efficient searching
        let mut tcp_sorted = constants::TOP_100_TCP_PORTS.to_vec();
        tcp_sorted.sort();
        assert_eq!(constants::TOP_100_TCP_PORTS, &tcp_sorted[..]);
        
        let mut udp_sorted = constants::TOP_100_UDP_PORTS.to_vec();
        udp_sorted.sort();
        assert_eq!(constants::TOP_100_UDP_PORTS, &udp_sorted[..]);
    }
}
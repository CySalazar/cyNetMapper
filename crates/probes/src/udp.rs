//! UDP probing implementation for cyNetMapper

use crate::common::{ProbeError, ProbeOptions, ProbeResult, ProbeStats};
use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::{IpAddr, Protocol, PortState},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// UDP probe configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpProbeOptions {
    /// Base probe options
    pub base: ProbeOptions,
    
    /// Send timeout
    pub send_timeout: Duration,
    
    /// Receive timeout
    pub recv_timeout: Duration,
    
    /// Number of probe attempts
    pub probe_attempts: u32,
    
    /// Delay between attempts
    pub attempt_delay: Duration,
    
    /// Maximum response size to read
    pub max_response_size: usize,
    
    /// Enable service-specific probes
    pub service_probes: bool,
    
    /// Custom UDP payload
    pub custom_payload: Option<Vec<u8>>,
}

impl Default for UdpProbeOptions {
    fn default() -> Self {
        Self {
            base: ProbeOptions::default(),
            send_timeout: Duration::from_secs(2),
            recv_timeout: Duration::from_secs(3),
            probe_attempts: 2,
            attempt_delay: Duration::from_millis(500),
            max_response_size: 1024,
            service_probes: true,
            custom_payload: None,
        }
    }
}

/// UDP probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpProbeResult {
    /// Base probe result
    pub base: ProbeResult,
    
    /// Response data (if received)
    pub response: Option<Vec<u8>>,
    
    /// Response as string (if printable)
    pub response_string: Option<String>,
    
    /// Send time
    pub send_time: Option<Duration>,
    
    /// Receive time
    pub recv_time: Option<Duration>,
    
    /// Number of attempts made
    pub attempts: u32,
    
    /// UDP-specific metadata
    pub udp_metadata: HashMap<String, String>,
}

impl UdpProbeResult {
    /// Create from base probe result
    pub fn from_base(base: ProbeResult) -> Self {
        Self {
            base,
            response: None,
            response_string: None,
            send_time: None,
            recv_time: None,
            attempts: 0,
            udp_metadata: HashMap::new(),
        }
    }
    
    /// Add response data
    pub fn with_response(mut self, response: Vec<u8>, recv_time: Duration) -> Self {
        // Try to convert to string if it's printable
        let response_string = if response.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace()) {
            String::from_utf8(response.clone()).ok()
        } else {
            None
        };
        
        self.response = Some(response);
        self.response_string = response_string;
        self.recv_time = Some(recv_time);
        self
    }
    
    /// Add send time
    pub fn with_send_time(mut self, send_time: Duration) -> Self {
        self.send_time = Some(send_time);
        self
    }
    
    /// Add attempt count
    pub fn with_attempts(mut self, attempts: u32) -> Self {
        self.attempts = attempts;
        self
    }
    
    /// Add UDP metadata
    pub fn with_udp_metadata(mut self, key: String, value: String) -> Self {
        self.udp_metadata.insert(key, value);
        self
    }
}

/// UDP probe implementation
#[derive(Debug, Clone)]
pub struct UdpProbe {
    /// Configuration
    config: Config,
    
    /// Default options
    default_options: UdpProbeOptions,
    
    /// Statistics
    stats: ProbeStats,
}

impl UdpProbe {
    /// Create a new UDP probe
    pub fn new(config: &Config) -> Result<Self> {
        let default_options = UdpProbeOptions {
            send_timeout: config.timing.connect_timeout,
            recv_timeout: config.timing.read_timeout,
            service_probes: config.scan.service_detection,
            ..Default::default()
        };
        
        Ok(Self {
            config: config.clone(),
            default_options,
            stats: ProbeStats::new(),
        })
    }
    
    /// Probe a single UDP port
    pub async fn probe_port(
        &mut self,
        target: SocketAddr,
        options: Option<UdpProbeOptions>,
    ) -> Result<UdpProbeResult> {
        let opts = options.unwrap_or_else(|| self.default_options.clone());
        let start_time = Instant::now();
        
        debug!("UDP probing {}:{}", target.ip(), target.port());
        
        // Create UDP socket
        let socket = self.create_udp_socket(&opts).await?;
        
        // Determine payload to send
        let payload = self.get_probe_payload(target.port(), &opts);
        
        let mut last_error = ProbeError::Timeout;
        let mut attempts = 0;
        
        // Try multiple attempts
        for attempt in 1..=opts.probe_attempts {
            attempts = attempt;
            
            match self.udp_probe_attempt(&socket, target, &payload, &opts).await {
                Ok((response, send_time, recv_time)) => {
                    trace!("UDP probe successful to {} on attempt {}", target, attempt);
                    
                    let result = UdpProbeResult::from_base(
                        ProbeResult::success(
                            target,
                            Protocol::Udp,
                            PortState::Open,
                            recv_time,
                        )
                    )
                    .with_response(response, recv_time)
                    .with_send_time(send_time)
                    .with_attempts(attempts)
                    .with_udp_metadata("payload_size".to_string(), payload.len().to_string());
                    
                    self.stats.update(&result.base);
                    return Ok(result);
                },
                Err(error) => {
                    last_error = error;
                    trace!("UDP probe attempt {} failed to {}: {:?}", attempt, target, last_error);
                    
                    // Wait before next attempt (except for last attempt)
                    if attempt < opts.probe_attempts {
                        tokio::time::sleep(opts.attempt_delay).await;
                    }
                }
            }
        }
        
        // All attempts failed
        let port_state = match &last_error {
            ProbeError::ConnectionRefused => PortState::Closed,
            ProbeError::Timeout => PortState::OpenFiltered, // UDP timeout is ambiguous
            ProbeError::HostUnreachable | ProbeError::NetworkUnreachable => PortState::Filtered,
            _ => PortState::OpenFiltered,
        };
        
        let mut result = UdpProbeResult::from_base(
            ProbeResult::failure(target, Protocol::Udp, last_error)
                .with_metadata("port_state".to_string(), format!("{:?}", port_state))
        ).with_attempts(attempts);
        
        // Add timing metadata
        let total_time = start_time.elapsed();
        result.base = result.base.with_metadata(
            "total_probe_time".to_string(),
            total_time.as_millis().to_string(),
        );
        
        self.stats.update(&result.base);
        Ok(result)
    }
    
    /// Probe multiple UDP ports concurrently
    pub async fn probe_ports(
        &mut self,
        targets: Vec<SocketAddr>,
        options: Option<UdpProbeOptions>,
        max_concurrent: usize,
    ) -> Result<Vec<UdpProbeResult>> {
        let opts = options.unwrap_or_else(|| self.default_options.clone());
        let mut results = Vec::new();
        
        // Process targets in batches to control concurrency
        for batch in targets.chunks(max_concurrent) {
            let mut tasks = Vec::new();
            
            for &target in batch {
                let mut probe_clone = self.clone();
                let opts_clone = opts.clone();
                
                let task = tokio::spawn(async move {
                    probe_clone.probe_port(target, Some(opts_clone)).await
                });
                
                tasks.push(task);
            }
            
            // Collect results from this batch
            for task in tasks {
                match task.await {
                    Ok(Ok(result)) => {
                        results.push(result);
                    },
                    Ok(Err(e)) => {
                        warn!("UDP probe task failed: {}", e);
                    },
                    Err(e) => {
                        warn!("UDP probe task panicked: {}", e);
                    }
                }
            }
        }
        
        Ok(results)
    }
    
    /// Create UDP socket with appropriate options
    async fn create_udp_socket(&self, options: &UdpProbeOptions) -> Result<UdpSocket> {
        let bind_addr = if let Some(source_ip) = options.base.source_ip {
            SocketAddr::new(source_ip.into(), options.base.source_port)
        } else {
            // Bind to any available address and port
            match std::env::consts::OS {
                "windows" => "0.0.0.0:0".parse().unwrap(),
                _ => "0.0.0.0:0".parse().unwrap(),
            }
        };
        
        let socket = UdpSocket::bind(bind_addr).await
            .map_err(|e| Error::Network(cynetmapper_core::error::NetworkError::SocketCreationFailed { reason: e.to_string() }))?;
        
        Ok(socket)
    }
    
    /// Perform a single UDP probe attempt
    async fn udp_probe_attempt(
        &self,
        socket: &UdpSocket,
        target: SocketAddr,
        payload: &[u8],
        options: &UdpProbeOptions,
    ) -> std::result::Result<(Vec<u8>, Duration, Duration), ProbeError> {
        let send_start = Instant::now();
        
        // Send probe
        match timeout(options.send_timeout, socket.send_to(payload, target)).await {
            Ok(Ok(_)) => {
                let send_time = send_start.elapsed();
                trace!("UDP packet sent to {} in {:?}", target, send_time);
                
                // Try to receive response
                let recv_start = Instant::now();
                let mut buffer = vec![0u8; options.max_response_size];
                
                match timeout(options.recv_timeout, socket.recv_from(&mut buffer)).await {
                    Ok(Ok((bytes_received, from_addr))) => {
                        let recv_time = recv_start.elapsed();
                        
                        // Verify response is from target
                        if from_addr.ip() == target.ip() {
                            buffer.truncate(bytes_received);
                            trace!("UDP response received from {} ({} bytes) in {:?}", 
                                   from_addr, bytes_received, recv_time);
                            Ok((buffer, send_time, recv_time))
                        } else {
                            trace!("UDP response from unexpected address: {} (expected {})", 
                                   from_addr, target);
                            Err(ProbeError::IoError("Response from unexpected address".to_string()))
                        }
                    },
                    Ok(Err(e)) => {
                        trace!("UDP receive error from {}: {}", target, e);
                        
                        match e.kind() {
                            std::io::ErrorKind::ConnectionRefused => Err(ProbeError::ConnectionRefused),
                            std::io::ErrorKind::HostUnreachable => Err(ProbeError::HostUnreachable),
                            std::io::ErrorKind::NetworkUnreachable => Err(ProbeError::NetworkUnreachable),
                            _ => Err(ProbeError::IoError(e.to_string())),
                        }
                    },
                    Err(_) => {
                        trace!("UDP receive timeout from {}", target);
                        Err(ProbeError::Timeout)
                    }
                }
            },
            Ok(Err(e)) => {
                trace!("UDP send error to {}: {}", target, e);
                
                match e.kind() {
                    std::io::ErrorKind::PermissionDenied => Err(ProbeError::PermissionDenied),
                    std::io::ErrorKind::HostUnreachable => Err(ProbeError::HostUnreachable),
                    std::io::ErrorKind::NetworkUnreachable => Err(ProbeError::NetworkUnreachable),
                    _ => Err(ProbeError::IoError(e.to_string())),
                }
            },
            Err(_) => {
                trace!("UDP send timeout to {}", target);
                Err(ProbeError::Timeout)
            }
        }
    }
    
    /// Get appropriate probe payload for the target port
    fn get_probe_payload(&self, port: u16, options: &UdpProbeOptions) -> Vec<u8> {
        // Use custom payload if specified
        if let Some(ref custom_payload) = options.custom_payload {
            return custom_payload.clone();
        }
        
        // Use base payload if specified
        if let Some(ref base_payload) = options.base.payload {
            return base_payload.clone();
        }
        
        // Use service-specific payload if enabled
        if options.service_probes {
            if let Some(payload) = payloads::get_service_payload(port) {
                return payload.to_vec();
            }
        }
        
        // Default empty payload
        Vec::new()
    }
    
    /// Get probe statistics
    pub fn get_stats(&self) -> &ProbeStats {
        &self.stats
    }
    
    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = ProbeStats::new();
    }
    
    /// Check if target is valid for UDP probing
    pub fn is_valid_target(&self, target: SocketAddr) -> bool {
        // Check port range
        if target.port() == 0 || target.port() > 65535 {
            return false;
        }
        
        // Check IP address
        crate::common::utils::is_valid_probe_target(target.ip())
    }
    
    /// Get default probe options
    pub fn get_default_options(&self) -> &UdpProbeOptions {
        &self.default_options
    }
    
    /// Set default probe options
    pub fn set_default_options(&mut self, options: UdpProbeOptions) {
        self.default_options = options;
    }
}

/// UDP probe builder for easy configuration
#[derive(Debug, Default)]
pub struct UdpProbeBuilder {
    options: UdpProbeOptions,
}

impl UdpProbeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set send timeout
    pub fn send_timeout(mut self, timeout: Duration) -> Self {
        self.options.send_timeout = timeout;
        self
    }
    
    /// Set receive timeout
    pub fn recv_timeout(mut self, timeout: Duration) -> Self {
        self.options.recv_timeout = timeout;
        self
    }
    
    /// Set number of probe attempts
    pub fn probe_attempts(mut self, attempts: u32) -> Self {
        self.options.probe_attempts = attempts;
        self
    }
    
    /// Set delay between attempts
    pub fn attempt_delay(mut self, delay: Duration) -> Self {
        self.options.attempt_delay = delay;
        self
    }
    
    /// Set maximum response size
    pub fn max_response_size(mut self, size: usize) -> Self {
        self.options.max_response_size = size;
        self
    }
    
    /// Enable/disable service-specific probes
    pub fn service_probes(mut self, enable: bool) -> Self {
        self.options.service_probes = enable;
        self
    }
    
    /// Set custom payload
    pub fn custom_payload(mut self, payload: Vec<u8>) -> Self {
        self.options.custom_payload = Some(payload);
        self
    }
    
    /// Set source port
    pub fn source_port(mut self, port: u16) -> Self {
        self.options.base.source_port = port;
        self
    }
    
    /// Set source IP
    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.options.base.source_ip = Some(ip);
        self
    }
    
    /// Build the options
    pub fn build(self) -> UdpProbeOptions {
        self.options
    }
}

/// Common UDP probe payloads for service detection
pub mod payloads {
    /// DNS query for version.bind
    pub const DNS_VERSION_BIND: &[u8] = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03";
    
    /// DHCP discover
    pub const DHCP_DISCOVER: &[u8] = b"\x01\x01\x06\x00\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    /// SNMP get request
    pub const SNMP_GET: &[u8] = b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x12\x34\x56\x78\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00";
    
    /// NTP request
    pub const NTP_REQUEST: &[u8] = b"\x1b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    /// SIP OPTIONS
    pub const SIP_OPTIONS: &[u8] = b"OPTIONS sip:target SIP/2.0\r\nVia: SIP/2.0/UDP cynetmapper:5060\r\nFrom: <sip:cynetmapper@cynetmapper>\r\nTo: <sip:target>\r\nCall-ID: 12345@cynetmapper\r\nCSeq: 1 OPTIONS\r\nContent-Length: 0\r\n\r\n";
    
    /// TFTP read request
    pub const TFTP_READ: &[u8] = b"\x00\x01test\x00netascii\x00";
    
    /// NetBIOS name query
    pub const NETBIOS_NAME: &[u8] = b"\x12\x34\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x20\x00\x01";
    
    /// RPC portmapper
    pub const RPC_PORTMAP: &[u8] = b"\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xa0\x00\x00\x00\x02\x00\x00\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    /// RADIUS Access-Request
    pub const RADIUS_ACCESS: &[u8] = b"\x01\x00\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    /// L2TP tunnel request
    pub const L2TP_TUNNEL: &[u8] = b"\xc8\x02\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    /// IKE Main Mode
    pub const IKE_MAIN_MODE: &[u8] = b"\x12\x34\x56\x78\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    
    /// MS-SQL ping
    pub const MSSQL_PING: &[u8] = b"\x02";
    
    /// Kerberos AS-REQ
    pub const KERBEROS_AS_REQ: &[u8] = b"\x6a\x81\x9e\x30\x81\x9b\xa1\x03\x02\x01\x05\xa2\x03\x02\x01\x0a";
    
    /// LDAP search request
    pub const LDAP_SEARCH: &[u8] = b"\x30\x0c\x02\x01\x01\x63\x07\x0a\x01\x00\x0a\x01\x00\x01\x01\x00";
    
    /// Memcached stats
    pub const MEMCACHED_STATS: &[u8] = b"stats\r\n";
    
    /// MongoDB isMaster
    pub const MONGODB_ISMASTER: &[u8] = b"\x3f\x00\x00\x00\x12\x34\x56\x78\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00\x74\x65\x73\x74\x2e\x24\x63\x6d\x64\x00\x00\x00\x00\x00\xff\xff\xff\xff\x17\x00\x00\x00\x10\x69\x73\x4d\x61\x73\x74\x65\x72\x00\x01\x00\x00\x00\x00";
    
    /// Get payload for common UDP services
    pub fn get_service_payload(port: u16) -> Option<&'static [u8]> {
        match port {
            53 => Some(DNS_VERSION_BIND),
            67 | 68 => Some(DHCP_DISCOVER),
            69 => Some(TFTP_READ),
            88 => Some(KERBEROS_AS_REQ),
            111 => Some(RPC_PORTMAP),
            123 => Some(NTP_REQUEST),
            137 => Some(NETBIOS_NAME),
            161 => Some(SNMP_GET),
            389 => Some(LDAP_SEARCH),
            500 => Some(IKE_MAIN_MODE),
            1434 => Some(MSSQL_PING),
            1701 => Some(L2TP_TUNNEL),
            1812 | 1813 => Some(RADIUS_ACCESS),
            5060 => Some(SIP_OPTIONS),
            11211 => Some(MEMCACHED_STATS),
            27017 => Some(MONGODB_ISMASTER),
            _ => None,
        }
    }
    
    /// Get service name for common UDP ports
    pub fn get_service_name(port: u16) -> Option<&'static str> {
        match port {
            53 => Some("dns"),
            67 => Some("dhcp-server"),
            68 => Some("dhcp-client"),
            69 => Some("tftp"),
            88 => Some("kerberos"),
            111 => Some("rpcbind"),
            123 => Some("ntp"),
            135 => Some("msrpc"),
            137 => Some("netbios-ns"),
            138 => Some("netbios-dgm"),
            161 => Some("snmp"),
            162 => Some("snmp-trap"),
            389 => Some("ldap"),
            445 => Some("microsoft-ds"),
            500 => Some("isakmp"),
            514 => Some("syslog"),
            520 => Some("rip"),
            631 => Some("ipp"),
            1434 => Some("ms-sql-m"),
            1701 => Some("l2tp"),
            1812 => Some("radius"),
            1813 => Some("radius-acct"),
            1900 => Some("upnp"),
            4500 => Some("ipsec-nat-t"),
            5060 => Some("sip"),
            5353 => Some("mdns"),
            11211 => Some("memcached"),
            27017 => Some("mongodb"),
            _ => None,
        }
    }
    
    /// Get expected response patterns for UDP services
    pub fn get_response_pattern(port: u16) -> Option<&'static [u8]> {
        match port {
            53 => Some(b"\x12\x34"), // DNS response with same ID
            123 => Some(b"\x1c"), // NTP response (server mode)
            161 => Some(b"\x30"), // SNMP response (ASN.1 sequence)
            _ => None,
        }
    }
    
    /// Check if response indicates an open port
    pub fn is_positive_response(port: u16, response: &[u8]) -> bool {
        if response.is_empty() {
            return false;
        }
        
        match port {
            53 => {
                // DNS response should have QR bit set and proper format
                response.len() >= 12 && (response[2] & 0x80) != 0
            },
            123 => {
                // NTP response should be 48 bytes and have proper mode
                response.len() == 48 && (response[0] & 0x07) == 4
            },
            161 => {
                // SNMP response should start with ASN.1 sequence
                response.len() >= 2 && response[0] == 0x30
            },
            69 => {
                // TFTP error response indicates service is running
                response.len() >= 4 && response[0] == 0x00 && response[1] == 0x05
            },
            _ => true, // Any response indicates the port is open
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio_test;

    #[test]
    fn test_udp_probe_creation() {
        let config = Config::default();
        let probe = UdpProbe::new(&config);
        assert!(probe.is_ok());
    }

    #[test]
    fn test_udp_probe_options_default() {
        let options = UdpProbeOptions::default();
        assert_eq!(options.send_timeout, Duration::from_secs(2));
        assert_eq!(options.recv_timeout, Duration::from_secs(3));
        assert_eq!(options.probe_attempts, 2);
        assert_eq!(options.attempt_delay, Duration::from_millis(500));
        assert!(options.service_probes);
        assert_eq!(options.max_response_size, 1024);
    }

    #[test]
    fn test_udp_probe_builder() {
        let options = UdpProbeBuilder::new()
            .send_timeout(Duration::from_secs(1))
            .recv_timeout(Duration::from_secs(2))
            .probe_attempts(3)
            .attempt_delay(Duration::from_millis(1000))
            .max_response_size(2048)
            .service_probes(false)
            .source_port(12345)
            .build();
        
        assert_eq!(options.send_timeout, Duration::from_secs(1));
        assert_eq!(options.recv_timeout, Duration::from_secs(2));
        assert_eq!(options.probe_attempts, 3);
        assert_eq!(options.attempt_delay, Duration::from_millis(1000));
        assert_eq!(options.max_response_size, 2048);
        assert!(!options.service_probes);
        assert_eq!(options.base.source_port, 12345);
    }

    #[test]
    fn test_valid_target() {
        let config = Config::default();
        let probe = UdpProbe::new(&config).unwrap();
        
        // Valid targets
        let valid_target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
        assert!(probe.is_valid_target(valid_target));
        
        // Invalid port
        let invalid_port = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0);
        assert!(!probe.is_valid_target(invalid_port));
        
        // Invalid IP (loopback)
        let invalid_ip = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 53);
        assert!(!probe.is_valid_target(invalid_ip));
    }

    #[tokio::test]
    async fn test_udp_probe_localhost() {
        let config = Config::default();
        let mut probe = UdpProbe::new(&config).unwrap();
        
        // Test against a likely closed port on localhost
        let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
        let options = UdpProbeBuilder::new()
            .send_timeout(Duration::from_millis(100))
            .recv_timeout(Duration::from_millis(200))
            .probe_attempts(1)
            .service_probes(false)
            .build();
        
        let result = probe.probe_port(target, Some(options)).await;
        assert!(result.is_ok());
        
        let udp_result = result.unwrap();
        // UDP timeout is ambiguous - could be open|filtered
        assert!(matches!(udp_result.base.state, PortState::OpenFiltered | PortState::Closed));
    }

    #[test]
    fn test_service_payloads() {
        use payloads::*;
        
        assert!(get_service_payload(53).is_some());
        assert!(get_service_payload(161).is_some());
        assert!(get_service_payload(123).is_some());
        assert!(get_service_payload(9999).is_none());
        
        assert_eq!(get_service_payload(53), Some(DNS_VERSION_BIND));
        assert_eq!(get_service_payload(161), Some(SNMP_GET));
        
        assert_eq!(get_service_name(53), Some("dns"));
        assert_eq!(get_service_name(161), Some("snmp"));
        assert_eq!(get_service_name(9999), None);
    }

    #[test]
    fn test_udp_probe_result() {
        let target = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 53);
        let base_result = ProbeResult::success(
            target,
            Protocol::Udp,
            PortState::Open,
            Duration::from_millis(100),
        );
        
        let response_data = b"DNS response".to_vec();
        let udp_result = UdpProbeResult::from_base(base_result)
            .with_response(response_data.clone(), Duration::from_millis(50))
            .with_send_time(Duration::from_millis(10))
            .with_attempts(2)
            .with_udp_metadata("service".to_string(), "dns".to_string());
        
        assert!(udp_result.response.is_some());
        assert!(udp_result.response_string.is_some());
        assert!(udp_result.send_time.is_some());
        assert!(udp_result.recv_time.is_some());
        assert_eq!(udp_result.attempts, 2);
        assert_eq!(udp_result.response.as_ref().unwrap(), &response_data);
        assert_eq!(udp_result.udp_metadata.get("service"), Some(&"dns".to_string()));
    }

    #[tokio::test]
    async fn test_udp_probe_multiple_ports() {
        let config = Config::default();
        let mut probe = UdpProbe::new(&config).unwrap();
        
        let targets = vec![
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9998),
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999),
        ];
        
        let options = UdpProbeBuilder::new()
            .send_timeout(Duration::from_millis(100))
            .recv_timeout(Duration::from_millis(200))
            .probe_attempts(1)
            .service_probes(false)
            .build();
        
        let results = probe.probe_ports(targets, Some(options), 2).await;
        assert!(results.is_ok());
        
        let udp_results = results.unwrap();
        assert_eq!(udp_results.len(), 2);
    }

    #[test]
    fn test_payload_selection() {
        let config = Config::default();
        let probe = UdpProbe::new(&config).unwrap();
        
        // Test custom payload
        let custom_payload = vec![1, 2, 3, 4];
        let options = UdpProbeOptions {
            custom_payload: Some(custom_payload.clone()),
            ..Default::default()
        };
        assert_eq!(probe.get_probe_payload(53, &options), custom_payload);
        
        // Test base payload
        let base_payload = vec![5, 6, 7, 8];
        let options = UdpProbeOptions {
            base: ProbeOptions {
                payload: Some(base_payload.clone()),
                ..Default::default()
            },
            custom_payload: None,
            ..Default::default()
        };
        assert_eq!(probe.get_probe_payload(53, &options), base_payload);
        
        // Test service-specific payload
        let options = UdpProbeOptions {
            service_probes: true,
            ..Default::default()
        };
        let dns_payload = probe.get_probe_payload(53, &options);
        assert!(!dns_payload.is_empty());
        
        // Test default empty payload
        let options = UdpProbeOptions {
            service_probes: false,
            ..Default::default()
        };
        let empty_payload = probe.get_probe_payload(9999, &options);
        assert!(empty_payload.is_empty());
    }
}
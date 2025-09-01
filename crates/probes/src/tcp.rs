//! TCP probing implementation for cyNetMapper

use crate::common::{ProbeError, ProbeOptions, ProbeResult, ProbeStats};
use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::{IpAddr, Protocol, PortState},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream as AsyncTcpStream;
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// TCP probe configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbeOptions {
    /// Base probe options
    pub base: ProbeOptions,
    
    /// Connection timeout
    pub connect_timeout: Duration,
    
    /// Read timeout for banner grabbing
    pub read_timeout: Duration,
    
    /// Enable banner grabbing
    pub grab_banner: bool,
    
    /// Maximum banner size to read
    pub max_banner_size: usize,
    
    /// Custom TCP flags (for raw socket probes)
    pub tcp_flags: Option<u8>,
    
    /// Window size
    pub window_size: Option<u16>,
    
    /// MSS (Maximum Segment Size)
    pub mss: Option<u16>,
}

impl Default for TcpProbeOptions {
    fn default() -> Self {
        Self {
            base: ProbeOptions::default(),
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(3),
            grab_banner: true,
            max_banner_size: 1024,
            tcp_flags: None,
            window_size: None,
            mss: None,
        }
    }
}

/// TCP probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpProbeResult {
    /// Base probe result
    pub base: ProbeResult,
    
    /// Banner data (if grabbed)
    pub banner: Option<String>,
    
    /// Connection establishment time
    pub connect_time: Option<Duration>,
    
    /// Banner grab time
    pub banner_time: Option<Duration>,
    
    /// TCP-specific metadata
    pub tcp_metadata: HashMap<String, String>,
}

impl TcpProbeResult {
    /// Create from base probe result
    pub fn from_base(base: ProbeResult) -> Self {
        Self {
            base,
            banner: None,
            connect_time: None,
            banner_time: None,
            tcp_metadata: HashMap::new(),
        }
    }
    
    /// Add banner data
    pub fn with_banner(mut self, banner: String, banner_time: Duration) -> Self {
        self.banner = Some(banner);
        self.banner_time = Some(banner_time);
        self
    }
    
    /// Add connection time
    pub fn with_connect_time(mut self, connect_time: Duration) -> Self {
        self.connect_time = Some(connect_time);
        self
    }
    
    /// Add TCP metadata
    pub fn with_tcp_metadata(mut self, key: String, value: String) -> Self {
        self.tcp_metadata.insert(key, value);
        self
    }
}

/// TCP probe implementation
#[derive(Debug, Clone)]
pub struct TcpProbe {
    /// Configuration
    config: Config,
    
    /// Default options
    default_options: TcpProbeOptions,
    
    /// Statistics
    stats: ProbeStats,
}

impl TcpProbe {
    /// Create a new TCP probe
    pub fn new(config: &Config) -> Result<Self> {
        let default_options = TcpProbeOptions {
            connect_timeout: config.timing.connect_timeout,
            read_timeout: config.timing.read_timeout,
            grab_banner: config.scan.service_detection,
            ..Default::default()
        };
        
        Ok(Self {
            config: config.clone(),
            default_options,
            stats: ProbeStats::new(),
        })
    }
    
    /// Probe a single TCP port
    pub async fn probe_port(
        &mut self,
        target: SocketAddr,
        options: Option<TcpProbeOptions>,
    ) -> Result<TcpProbeResult> {
        let opts = options.unwrap_or_else(|| self.default_options.clone());
        let start_time = Instant::now();
        
        debug!("TCP probing {}:{}", target.ip(), target.port());
        
        // Perform TCP connect
        let connect_result = self.tcp_connect(target, &opts).await;
        
        let mut result = match connect_result {
            Ok((stream, connect_time)) => {
                trace!("TCP connect successful to {} in {:?}", target, connect_time);
                
                let mut tcp_result = TcpProbeResult::from_base(
                    ProbeResult::success(
                        target,
                        Protocol::Tcp,
                        PortState::Open,
                        connect_time,
                    )
                ).with_connect_time(connect_time);
                
                // Grab banner if enabled
                if opts.grab_banner {
                    if let Ok((banner, banner_time)) = self.grab_banner(stream, &opts).await {
                        tcp_result = tcp_result.with_banner(banner, banner_time);
                    }
                }
                
                tcp_result
            },
            Err(error) => {
                let port_state = match &error {
                    ProbeError::ConnectionRefused => PortState::Closed,
                    ProbeError::Timeout | ProbeError::HostUnreachable | ProbeError::NetworkUnreachable => PortState::Filtered,
                    _ => PortState::Filtered,
                };
                
                TcpProbeResult::from_base(
                    ProbeResult::failure(target, Protocol::Tcp, error.clone())
                        .with_metadata("port_state".to_string(), format!("{:?}", port_state))
                )
            }
        };
        
        // Add timing metadata
        let total_time = start_time.elapsed();
        result.base = result.base.with_metadata(
            "total_probe_time".to_string(),
            total_time.as_millis().to_string(),
        );
        
        // Update statistics
        self.stats.update(&result.base);
        
        Ok(result)
    }
    
    /// Probe multiple TCP ports concurrently
    pub async fn probe_ports(
        &mut self,
        targets: Vec<SocketAddr>,
        options: Option<TcpProbeOptions>,
        max_concurrent: usize,
    ) -> Result<Vec<TcpProbeResult>> {
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
                        warn!("TCP probe task failed: {}", e);
                    },
                    Err(e) => {
                        warn!("TCP probe task panicked: {}", e);
                    }
                }
            }
        }
        
        Ok(results)
    }
    
    /// Perform TCP connect
    async fn tcp_connect(
        &self,
        target: SocketAddr,
        options: &TcpProbeOptions,
    ) -> std::result::Result<(AsyncTcpStream, Duration), ProbeError> {
        let start_time = Instant::now();
        
        match timeout(options.connect_timeout, AsyncTcpStream::connect(target)).await {
            Ok(Ok(stream)) => {
                let connect_time = start_time.elapsed();
                Ok((stream, connect_time))
            },
            Ok(Err(e)) => {
                trace!("TCP connect failed to {}: {}", target, e);
                
                // Map specific error types
                match e.kind() {
                    std::io::ErrorKind::ConnectionRefused => Err(ProbeError::ConnectionRefused),
                    std::io::ErrorKind::TimedOut => Err(ProbeError::Timeout),
                    std::io::ErrorKind::HostUnreachable => Err(ProbeError::HostUnreachable),
                    std::io::ErrorKind::NetworkUnreachable => Err(ProbeError::NetworkUnreachable),
                    std::io::ErrorKind::PermissionDenied => Err(ProbeError::PermissionDenied),
                    _ => Err(ProbeError::IoError(e.to_string())),
                }
            },
            Err(_) => {
                trace!("TCP connect timeout to {}", target);
                Err(ProbeError::Timeout)
            }
        }
    }
    
    /// Grab banner from TCP connection
    async fn grab_banner(
        &self,
        mut stream: AsyncTcpStream,
        options: &TcpProbeOptions,
    ) -> std::result::Result<(String, Duration), ProbeError> {
        let start_time = Instant::now();
        let mut buffer = vec![0u8; options.max_banner_size];
        
        // Send a probe if payload is specified
        if let Some(payload) = &options.base.payload {
            if let Err(e) = timeout(options.read_timeout, stream.write_all(payload)).await {
                trace!("Failed to send probe payload: {:?}", e);
                return Err(ProbeError::IoError("Failed to send probe".to_string()));
            }
        }
        
        // Try to read banner
        match timeout(options.read_timeout, stream.read(&mut buffer)).await {
            Ok(Ok(bytes_read)) => {
                if bytes_read > 0 {
                    let banner_time = start_time.elapsed();
                    
                    // Convert to string, handling non-UTF8 data gracefully
                    let banner = String::from_utf8_lossy(&buffer[..bytes_read])
                        .trim()
                        .to_string();
                    
                    if !banner.is_empty() {
                        trace!("Grabbed banner: {}", banner);
                        Ok((banner, banner_time))
                    } else {
                        Err(ProbeError::IoError("Empty banner".to_string()))
                    }
                } else {
                    Err(ProbeError::IoError("No data received".to_string()))
                }
            },
            Ok(Err(e)) => {
                trace!("Banner grab IO error: {}", e);
                Err(ProbeError::IoError(e.to_string()))
            },
            Err(_) => {
                trace!("Banner grab timeout");
                Err(ProbeError::Timeout)
            }
        }
    }
    
    /// Get probe statistics
    pub fn get_stats(&self) -> &ProbeStats {
        &self.stats
    }
    
    /// Reset statistics
    pub fn reset_stats(&mut self) {
        self.stats = ProbeStats::new();
    }
    
    /// Check if target is valid for TCP probing
    pub fn is_valid_target(&self, target: SocketAddr) -> bool {
        // Check port range
        if target.port() == 0 || target.port() > 65535 {
            return false;
        }
        
        // Check IP address
        crate::common::utils::is_valid_probe_target(target.ip())
    }
    
    /// Get default probe options
    pub fn get_default_options(&self) -> &TcpProbeOptions {
        &self.default_options
    }
    
    /// Set default probe options
    pub fn set_default_options(&mut self, options: TcpProbeOptions) {
        self.default_options = options;
    }
}

/// TCP probe builder for easy configuration
#[derive(Debug, Default)]
pub struct TcpProbeBuilder {
    options: TcpProbeOptions,
}

impl TcpProbeBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set connection timeout
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.options.connect_timeout = timeout;
        self
    }
    
    /// Set read timeout
    pub fn read_timeout(mut self, timeout: Duration) -> Self {
        self.options.read_timeout = timeout;
        self
    }
    
    /// Enable/disable banner grabbing
    pub fn grab_banner(mut self, enable: bool) -> Self {
        self.options.grab_banner = enable;
        self
    }
    
    /// Set maximum banner size
    pub fn max_banner_size(mut self, size: usize) -> Self {
        self.options.max_banner_size = size;
        self
    }
    
    /// Set probe payload
    pub fn payload(mut self, payload: Vec<u8>) -> Self {
        self.options.base.payload = Some(payload);
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
    pub fn build(self) -> TcpProbeOptions {
        self.options
    }
}

/// Common TCP probe payloads for service detection
pub mod payloads {
    /// HTTP GET request
    pub const HTTP_GET: &[u8] = b"GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: cyNetMapper\r\nConnection: close\r\n\r\n";
    
    /// HTTPS/TLS ClientHello (simplified)
    pub const TLS_CLIENT_HELLO: &[u8] = b"\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03";
    
    /// SSH version exchange
    pub const SSH_VERSION: &[u8] = b"SSH-2.0-cyNetMapper\r\n";
    
    /// FTP greeting
    pub const FTP_HELP: &[u8] = b"HELP\r\n";
    
    /// SMTP EHLO
    pub const SMTP_EHLO: &[u8] = b"EHLO cynetmapper.local\r\n";
    
    /// POP3 capabilities
    pub const POP3_CAPA: &[u8] = b"CAPA\r\n";
    
    /// IMAP capabilities
    pub const IMAP_CAPABILITY: &[u8] = b"a001 CAPABILITY\r\n";
    
    /// DNS query (for TCP DNS)
    pub const DNS_QUERY: &[u8] = b"\x00\x1d\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    
    /// Get payload for common services
    pub fn get_service_payload(port: u16) -> Option<&'static [u8]> {
        match port {
            21 => Some(FTP_HELP),
            22 => Some(SSH_VERSION),
            25 => Some(SMTP_EHLO),
            53 => Some(DNS_QUERY),
            80 => Some(HTTP_GET),
            110 => Some(POP3_CAPA),
            143 => Some(IMAP_CAPABILITY),
            443 => Some(TLS_CLIENT_HELLO),
            _ => None,
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
    fn test_tcp_probe_creation() {
        let config = Config::default();
        let probe = TcpProbe::new(&config);
        assert!(probe.is_ok());
    }

    #[test]
    fn test_tcp_probe_options_default() {
        let options = TcpProbeOptions::default();
        assert_eq!(options.connect_timeout, Duration::from_secs(5));
        assert_eq!(options.read_timeout, Duration::from_secs(3));
        assert!(options.grab_banner);
        assert_eq!(options.max_banner_size, 1024);
    }

    #[test]
    fn test_tcp_probe_builder() {
        let options = TcpProbeBuilder::new()
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(5))
            .grab_banner(false)
            .max_banner_size(2048)
            .source_port(12345)
            .build();
        
        assert_eq!(options.connect_timeout, Duration::from_secs(10));
        assert_eq!(options.read_timeout, Duration::from_secs(5));
        assert!(!options.grab_banner);
        assert_eq!(options.max_banner_size, 2048);
        assert_eq!(options.base.source_port, 12345);
    }

    #[test]
    fn test_valid_target() {
        let config = Config::default();
        let probe = TcpProbe::new(&config).unwrap();
        
        // Valid targets
        let valid_target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        assert!(probe.is_valid_target(valid_target));
        
        // Invalid port
        let invalid_port = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 0);
        assert!(!probe.is_valid_target(invalid_port));
        
        // Invalid IP (loopback)
        let invalid_ip = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80);
        assert!(!probe.is_valid_target(invalid_ip));
    }

    #[tokio::test]
    async fn test_tcp_probe_localhost() {
        let config = Config::default();
        let mut probe = TcpProbe::new(&config).unwrap();
        
        // Test against a likely closed port on localhost
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);
        let options = TcpProbeBuilder::new()
            .connect_timeout(Duration::from_millis(100))
            .grab_banner(false)
            .build();
        
        let result = probe.probe_port(target, Some(options)).await;
        assert!(result.is_ok());
        
        let tcp_result = result.unwrap();
        // Should be either closed or filtered (depending on firewall)
        assert!(matches!(tcp_result.base.state, PortState::Closed | PortState::Filtered));
    }

    #[test]
    fn test_service_payloads() {
        use payloads::*;
        
        assert!(get_service_payload(80).is_some());
        assert!(get_service_payload(443).is_some());
        assert!(get_service_payload(22).is_some());
        assert!(get_service_payload(9999).is_none());
        
        assert_eq!(get_service_payload(80), Some(HTTP_GET));
        assert_eq!(get_service_payload(22), Some(SSH_VERSION));
    }

    #[test]
    fn test_tcp_probe_result() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let base_result = ProbeResult::success(
            target,
            Protocol::Tcp,
            PortState::Open,
            Duration::from_millis(100),
        );
        
        let tcp_result = TcpProbeResult::from_base(base_result)
            .with_connect_time(Duration::from_millis(50))
            .with_banner("HTTP/1.1 200 OK".to_string(), Duration::from_millis(30))
            .with_tcp_metadata("service".to_string(), "http".to_string());
        
        assert!(tcp_result.connect_time.is_some());
        assert!(tcp_result.banner.is_some());
        assert!(tcp_result.banner_time.is_some());
        assert_eq!(tcp_result.banner.as_ref().unwrap(), "HTTP/1.1 200 OK");
        assert_eq!(tcp_result.tcp_metadata.get("service"), Some(&"http".to_string()));
    }

    #[tokio::test]
    async fn test_tcp_probe_multiple_ports() {
        let config = Config::default();
        let mut probe = TcpProbe::new(&config).unwrap();
        
        let targets = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9998),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999),
        ];
        
        let options = TcpProbeBuilder::new()
            .connect_timeout(Duration::from_millis(100))
            .grab_banner(false)
            .build();
        
        let results = probe.probe_ports(targets, Some(options), 2).await;
        assert!(results.is_ok());
        
        let tcp_results = results.unwrap();
        assert_eq!(tcp_results.len(), 2);
    }
}
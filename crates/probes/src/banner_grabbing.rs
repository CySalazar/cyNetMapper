//! Banner grabbing implementation for cyNetMapper

use crate::common::{ProbeError, ProbeOptions, ProbeResult};
use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::Protocol,
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// Banner grabbing result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerResult {
    /// Target address
    pub target: SocketAddr,
    
    /// Protocol used
    pub protocol: Protocol,
    
    /// Captured banner/response
    pub banner: Option<String>,
    
    /// Raw response bytes
    pub raw_data: Option<Vec<u8>>,
    
    /// Response time
    pub response_time: Duration,
    
    /// Success status
    pub success: bool,
    
    /// Error message (if any)
    pub error: Option<String>,
    
    /// Metadata
    pub metadata: HashMap<String, String>,
}

impl BannerResult {
    /// Create a new banner result
    pub fn new(target: SocketAddr, protocol: Protocol) -> Self {
        Self {
            target,
            protocol,
            banner: None,
            raw_data: None,
            response_time: Duration::from_secs(0),
            success: false,
            error: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Set banner text
    pub fn with_banner(mut self, banner: String) -> Self {
        self.banner = Some(banner);
        self.success = true;
        self
    }
    
    /// Set raw data
    pub fn with_raw_data(mut self, data: Vec<u8>) -> Self {
        self.raw_data = Some(data);
        self
    }
    
    /// Set response time
    pub fn with_response_time(mut self, time: Duration) -> Self {
        self.response_time = time;
        self
    }
    
    /// Set error
    pub fn with_error(mut self, error: String) -> Self {
        self.error = Some(error);
        self.success = false;
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Check if banner contains text
    pub fn contains(&self, text: &str) -> bool {
        self.banner.as_ref().map_or(false, |b| b.contains(text))
    }
    
    /// Get banner length
    pub fn banner_length(&self) -> usize {
        self.banner.as_ref().map_or(0, |b| b.len())
    }
    
    /// Check if response is binary
    pub fn is_binary(&self) -> bool {
        if let Some(data) = &self.raw_data {
            // Check for non-printable characters
            data.iter().any(|&b| b < 32 && b != 9 && b != 10 && b != 13)
        } else {
            false
        }
    }
}

/// Banner grabbing options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerOptions {
    /// Connection timeout
    pub connect_timeout: Duration,
    
    /// Read timeout
    pub read_timeout: Duration,
    
    /// Maximum banner size
    pub max_banner_size: usize,
    
    /// Custom probe payload
    pub probe_payload: Option<Vec<u8>>,
    
    /// Wait time before reading
    pub read_delay: Duration,
    
    /// Number of read attempts
    pub read_attempts: u32,
    
    /// Include raw data in result
    pub include_raw_data: bool,
    
    /// Service-specific probes
    pub service_probes: bool,
}

impl Default for BannerOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(3),
            max_banner_size: 4096,
            probe_payload: None,
            read_delay: Duration::from_millis(100),
            read_attempts: 3,
            include_raw_data: false,
            service_probes: true,
        }
    }
}

/// Banner grabber
#[derive(Debug, Clone)]
pub struct BannerGrabber {
    /// Configuration
    config: Config,
    
    /// Service-specific probes
    service_probes: HashMap<u16, Vec<u8>>,
}

impl BannerGrabber {
    /// Create a new banner grabber
    pub fn new(config: &Config) -> Self {
        let mut grabber = Self {
            config: config.clone(),
            service_probes: HashMap::new(),
        };
        
        grabber.load_service_probes();
        grabber
    }
    
    /// Grab banner from TCP service
    pub async fn grab_tcp_banner(
        &self,
        target: SocketAddr,
        options: &BannerOptions,
    ) -> Result<BannerResult> {
        let start_time = Instant::now();
        
        debug!("Grabbing TCP banner from {}", target);
        
        // Connect to target
        let stream = match timeout(
            options.connect_timeout,
            TcpStream::connect(target)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                return Ok(BannerResult::new(target, Protocol::Tcp)
                    .with_error(format!("Connection failed: {}", e))
                    .with_response_time(start_time.elapsed()));
            }
            Err(_) => {
                return Ok(BannerResult::new(target, Protocol::Tcp)
                    .with_error("Connection timeout".to_string())
                    .with_response_time(start_time.elapsed()));
            }
        };
        
        // Perform banner grabbing
        self.grab_tcp_banner_from_stream(target, stream, options, start_time).await
    }
    
    /// Grab banner from established TCP stream
    async fn grab_tcp_banner_from_stream(
        &self,
        target: SocketAddr,
        mut stream: TcpStream,
        options: &BannerOptions,
        start_time: Instant,
    ) -> Result<BannerResult> {
        let mut result = BannerResult::new(target, Protocol::Tcp);
        
        // Send probe payload if specified
        if let Some(payload) = &options.probe_payload {
            if let Err(e) = stream.write_all(payload).await {
                return Ok(result.with_error(format!("Failed to send probe: {}", e))
                    .with_response_time(start_time.elapsed()));
            }
        } else if options.service_probes {
            // Send service-specific probe
            if let Some(probe) = self.service_probes.get(&target.port()) {
                if let Err(e) = stream.write_all(probe).await {
                    trace!("Failed to send service probe to port {}: {}", target.port(), e);
                }
            }
        }
        
        // Wait before reading
        if !options.read_delay.is_zero() {
            tokio::time::sleep(options.read_delay).await;
        }
        
        // Read banner
        let mut buffer = vec![0u8; options.max_banner_size];
        let mut total_read = 0;
        
        for attempt in 1..=options.read_attempts {
            match timeout(
                options.read_timeout,
                stream.read(&mut buffer[total_read..])
            ).await {
                Ok(Ok(0)) => {
                    // Connection closed
                    break;
                }
                Ok(Ok(bytes_read)) => {
                    total_read += bytes_read;
                    trace!("Read {} bytes from {} (attempt {})", bytes_read, target, attempt);
                    
                    // Check if we have enough data
                    if total_read >= 10 || buffer[..total_read].contains(&b'\n') {
                        break;
                    }
                    
                    // Continue reading if buffer not full
                    if total_read >= options.max_banner_size {
                        break;
                    }
                }
                Ok(Err(e)) => {
                    if attempt == options.read_attempts {
                        return Ok(result.with_error(format!("Read failed: {}", e))
                            .with_response_time(start_time.elapsed()));
                    }
                }
                Err(_) => {
                    if attempt == options.read_attempts {
                        return Ok(result.with_error("Read timeout".to_string())
                            .with_response_time(start_time.elapsed()));
                    }
                }
            }
            
            // Small delay between attempts
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        
        // Process the response
        if total_read > 0 {
            buffer.truncate(total_read);
            
            // Store raw data if requested
            if options.include_raw_data {
                result = result.with_raw_data(buffer.clone());
            }
            
            // Convert to string (handle binary data gracefully)
            let banner_text = if buffer.iter().all(|&b| b.is_ascii() && (b >= 32 || b == 9 || b == 10 || b == 13)) {
                String::from_utf8_lossy(&buffer).to_string()
            } else {
                // Binary data - create hex representation
                format!("[Binary data: {} bytes]", buffer.len())
            };
            
            result = result.with_banner(banner_text)
                .with_metadata("bytes_read".to_string(), total_read.to_string());
        } else {
            result = result.with_error("No data received".to_string());
        }
        
        Ok(result.with_response_time(start_time.elapsed()))
    }
    
    /// Grab banner from UDP service
    pub async fn grab_udp_banner(
        &self,
        target: SocketAddr,
        options: &BannerOptions,
    ) -> Result<BannerResult> {
        let start_time = Instant::now();
        
        debug!("Grabbing UDP banner from {}", target);
        
        // Create UDP socket
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(socket) => socket,
            Err(e) => {
                return Ok(BannerResult::new(target, Protocol::Udp)
                    .with_error(format!("Failed to create socket: {}", e))
                    .with_response_time(start_time.elapsed()));
            }
        };
        
        // Connect to target
        if let Err(e) = socket.connect(target).await {
            return Ok(BannerResult::new(target, Protocol::Udp)
                .with_error(format!("Failed to connect: {}", e))
                .with_response_time(start_time.elapsed()));
        }
        
        let mut result = BannerResult::new(target, Protocol::Udp);
        
        // Send probe payload
        let payload = if let Some(payload) = &options.probe_payload {
            payload.clone()
        } else if options.service_probes {
            self.service_probes.get(&target.port()).cloned()
                .unwrap_or_else(|| b"\r\n".to_vec())
        } else {
            b"\r\n".to_vec()
        };
        
        if let Err(e) = socket.send(&payload).await {
            return Ok(result.with_error(format!("Failed to send probe: {}", e))
                .with_response_time(start_time.elapsed()));
        }
        
        // Wait for response
        let mut buffer = vec![0u8; options.max_banner_size];
        
        match timeout(options.read_timeout, socket.recv(&mut buffer)).await {
            Ok(Ok(bytes_read)) => {
                buffer.truncate(bytes_read);
                
                // Store raw data if requested
                if options.include_raw_data {
                    result = result.with_raw_data(buffer.clone());
                }
                
                // Convert to string
                let banner_text = if buffer.iter().all(|&b| b.is_ascii() && (b >= 32 || b == 9 || b == 10 || b == 13)) {
                    String::from_utf8_lossy(&buffer).to_string()
                } else {
                    format!("[Binary data: {} bytes]", buffer.len())
                };
                
                result = result.with_banner(banner_text)
                    .with_metadata("bytes_read".to_string(), bytes_read.to_string());
            }
            Ok(Err(e)) => {
                result = result.with_error(format!("Receive failed: {}", e));
            }
            Err(_) => {
                result = result.with_error("Receive timeout".to_string());
            }
        }
        
        Ok(result.with_response_time(start_time.elapsed()))
    }
    
    /// Grab banner with automatic protocol detection
    pub async fn grab_banner(
        &self,
        target: SocketAddr,
        protocol: Protocol,
        options: &BannerOptions,
    ) -> Result<BannerResult> {
        match protocol {
            Protocol::Tcp => self.grab_tcp_banner(target, options).await,
            Protocol::Udp => self.grab_udp_banner(target, options).await,
            _ => {
                Ok(BannerResult::new(target, protocol)
                    .with_error(format!("Unsupported protocol: {:?}", protocol)))
            }
        }
    }
    
    /// Grab banners from multiple targets
    pub async fn grab_banners(
        &self,
        targets: Vec<(SocketAddr, Protocol)>,
        options: &BannerOptions,
        max_concurrent: usize,
    ) -> Vec<BannerResult> {
        use futures::stream::{self, StreamExt};
        
        stream::iter(targets)
            .map(|(target, protocol)| async move {
                self.grab_banner(target, protocol, options).await
                    .unwrap_or_else(|e| {
                        BannerResult::new(target, protocol)
                            .with_error(format!("Internal error: {}", e))
                    })
            })
            .buffer_unordered(max_concurrent)
            .collect()
            .await
    }
    
    /// Load service-specific probe payloads
    fn load_service_probes(&mut self) {
        // HTTP probe
        self.service_probes.insert(80, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        self.service_probes.insert(8080, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        self.service_probes.insert(443, b"GET / HTTP/1.0\r\n\r\n".to_vec());
        
        // SMTP probe
        self.service_probes.insert(25, b"EHLO cynetmapper\r\n".to_vec());
        self.service_probes.insert(587, b"EHLO cynetmapper\r\n".to_vec());
        
        // POP3 probe
        self.service_probes.insert(110, b"USER test\r\n".to_vec());
        self.service_probes.insert(995, b"USER test\r\n".to_vec());
        
        // IMAP probe
        self.service_probes.insert(143, b"A001 CAPABILITY\r\n".to_vec());
        self.service_probes.insert(993, b"A001 CAPABILITY\r\n".to_vec());
        
        // FTP probe
        self.service_probes.insert(21, b"USER anonymous\r\n".to_vec());
        
        // Telnet probe (just connect, no payload needed)
        // SSH probe (just connect, no payload needed)
        
        // DNS probe (UDP)
        let dns_query = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags (standard query)
            0x00, 0x01, // Questions
            0x00, 0x00, // Answer RRs
            0x00, 0x00, // Authority RRs
            0x00, 0x00, // Additional RRs
            // Query for "version.bind" TXT record
            0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n',
            0x04, b'b', b'i', b'n', b'd',
            0x00, // End of name
            0x00, 0x10, // Type: TXT
            0x00, 0x03, // Class: CHAOS
        ];
        self.service_probes.insert(53, dns_query);
        
        // SNMP probe (UDP)
        let snmp_query = vec![
            0x30, 0x26, // SEQUENCE
            0x02, 0x01, 0x00, // Version (1)
            0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // Community
            0xa0, 0x19, // GetRequest PDU
            0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // Request ID
            0x02, 0x01, 0x00, // Error status
            0x02, 0x01, 0x00, // Error index
            0x30, 0x0b, // Variable bindings
            0x30, 0x09, // Variable binding
            0x06, 0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, // OID (sysDescr)
            0x05, 0x00, // NULL value
        ];
        self.service_probes.insert(161, snmp_query);
        
        // NTP probe (UDP)
        let ntp_query = vec![
            0x1b, // LI=0, VN=3, Mode=3 (client)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        self.service_probes.insert(123, ntp_query);
        
        // SIP probe (UDP)
        let sip_options = b"OPTIONS sip:user@domain SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060\r\nFrom: <sip:test@test.com>\r\nTo: <sip:user@domain>\r\nCall-ID: test@test.com\r\nCSeq: 1 OPTIONS\r\n\r\n";
        self.service_probes.insert(5060, sip_options.to_vec());
    }
    
    /// Get probe payload for a specific port
    pub fn get_probe_payload(&self, port: u16) -> Option<&Vec<u8>> {
        self.service_probes.get(&port)
    }
    
    /// Check if service probe is available for port
    pub fn has_service_probe(&self, port: u16) -> bool {
        self.service_probes.contains_key(&port)
    }
    
    /// Get all supported probe ports
    pub fn get_probe_ports(&self) -> Vec<u16> {
        self.service_probes.keys().copied().collect()
    }
}

/// Banner grabbing utilities
pub mod utils {
    use super::*;
    
    /// Clean banner text (remove control characters)
    pub fn clean_banner(banner: &str) -> String {
        banner.chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .collect::<String>()
            .trim()
            .to_string()
    }
    
    /// Extract first line from banner
    pub fn get_first_line(banner: &str) -> String {
        banner.lines().next().unwrap_or("").trim().to_string()
    }
    
    /// Check if banner looks like HTTP response
    pub fn is_http_banner(banner: &str) -> bool {
        banner.starts_with("HTTP/") || banner.contains("Server:")
    }
    
    /// Check if banner looks like SSH
    pub fn is_ssh_banner(banner: &str) -> bool {
        banner.starts_with("SSH-")
    }
    
    /// Check if banner looks like FTP
    pub fn is_ftp_banner(banner: &str) -> bool {
        banner.starts_with("220 ") && (banner.contains("FTP") || banner.contains("ftp"))
    }
    
    /// Check if banner looks like SMTP
    pub fn is_smtp_banner(banner: &str) -> bool {
        banner.starts_with("220 ") && (banner.contains("SMTP") || banner.contains("mail"))
    }
    
    /// Extract server information from HTTP banner
    pub fn extract_http_server(banner: &str) -> Option<String> {
        for line in banner.lines() {
            if line.to_lowercase().starts_with("server:") {
                return Some(line[7..].trim().to_string());
            }
        }
        None
    }
    
    /// Extract SSH version from banner
    pub fn extract_ssh_version(banner: &str) -> Option<String> {
        if banner.starts_with("SSH-") {
            Some(banner.trim().to_string())
        } else {
            None
        }
    }
    
    /// Calculate banner entropy (for detecting encrypted/compressed data)
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        let len = data.len() as f64;
        let mut entropy = 0.0;
        
        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }
        
        entropy
    }
    
    /// Check if data appears to be encrypted/compressed
    pub fn is_high_entropy(data: &[u8]) -> bool {
        calculate_entropy(data) > 7.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn test_banner_result_creation() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let result = BannerResult::new(target, Protocol::Tcp)
            .with_banner("HTTP/1.1 200 OK".to_string())
            .with_response_time(Duration::from_millis(100))
            .with_metadata("test".to_string(), "value".to_string());
        
        assert_eq!(result.target, target);
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.banner, Some("HTTP/1.1 200 OK".to_string()));
        assert_eq!(result.response_time, Duration::from_millis(100));
        assert!(result.success);
        assert_eq!(result.metadata.get("test"), Some(&"value".to_string()));
    }

    #[test]
    fn test_banner_result_methods() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let result = BannerResult::new(target, Protocol::Tcp)
            .with_banner("HTTP/1.1 200 OK\nServer: Apache".to_string());
        
        assert!(result.contains("HTTP"));
        assert!(result.contains("Apache"));
        assert!(!result.contains("nginx"));
        assert_eq!(result.banner_length(), 26);
        assert!(!result.is_binary());
    }

    #[test]
    fn test_banner_options_default() {
        let options = BannerOptions::default();
        
        assert_eq!(options.connect_timeout, Duration::from_secs(5));
        assert_eq!(options.read_timeout, Duration::from_secs(3));
        assert_eq!(options.max_banner_size, 4096);
        assert_eq!(options.read_attempts, 3);
        assert!(options.service_probes);
    }

    #[test]
    fn test_banner_grabber_creation() {
        let config = Config::default();
        let grabber = BannerGrabber::new(&config);
        
        assert!(grabber.has_service_probe(80)); // HTTP
        assert!(grabber.has_service_probe(25)); // SMTP
        assert!(grabber.has_service_probe(53)); // DNS
        assert!(!grabber.has_service_probe(9999)); // Unknown
    }

    #[test]
    fn test_service_probes() {
        let config = Config::default();
        let grabber = BannerGrabber::new(&config);
        
        let http_probe = grabber.get_probe_payload(80);
        assert!(http_probe.is_some());
        assert!(String::from_utf8_lossy(http_probe.unwrap()).contains("GET /"));
        
        let smtp_probe = grabber.get_probe_payload(25);
        assert!(smtp_probe.is_some());
        assert!(String::from_utf8_lossy(smtp_probe.unwrap()).contains("EHLO"));
        
        let probe_ports = grabber.get_probe_ports();
        assert!(!probe_ports.is_empty());
        assert!(probe_ports.contains(&80));
        assert!(probe_ports.contains(&53));
    }

    #[test]
    fn test_banner_cleaning() {
        use utils::*;
        
        let dirty_banner = "\x00\x01HTTP/1.1 200 OK\r\n\x7f";
        let clean = clean_banner(dirty_banner);
        assert_eq!(clean, "HTTP/1.1 200 OK");
        
        let multiline = "HTTP/1.1 200 OK\nServer: Apache\nContent-Type: text/html";
        let first_line = get_first_line(multiline);
        assert_eq!(first_line, "HTTP/1.1 200 OK");
    }

    #[test]
    fn test_banner_detection() {
        use utils::*;
        
        assert!(is_http_banner("HTTP/1.1 200 OK"));
        assert!(is_http_banner("Server: Apache/2.4.41"));
        assert!(!is_http_banner("SSH-2.0-OpenSSH"));
        
        assert!(is_ssh_banner("SSH-2.0-OpenSSH_8.3"));
        assert!(!is_ssh_banner("HTTP/1.1 200 OK"));
        
        assert!(is_ftp_banner("220 Welcome to FTP server"));
        assert!(!is_ftp_banner("220 SMTP server ready"));
        
        assert!(is_smtp_banner("220 mail.example.com SMTP server"));
        assert!(!is_smtp_banner("220 FTP server ready"));
    }

    #[test]
    fn test_information_extraction() {
        use utils::*;
        
        let http_banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n";
        let server = extract_http_server(http_banner);
        assert_eq!(server, Some("Apache/2.4.41 (Ubuntu)".to_string()));
        
        let ssh_banner = "SSH-2.0-OpenSSH_8.3";
        let version = extract_ssh_version(ssh_banner);
        assert_eq!(version, Some("SSH-2.0-OpenSSH_8.3".to_string()));
    }

    #[test]
    fn test_entropy_calculation() {
        use utils::*;
        
        // Low entropy data (repeated pattern)
        let low_entropy = b"AAAAAAAAAAAAAAAA";
        let entropy = calculate_entropy(low_entropy);
        assert!(entropy < 1.0);
        assert!(!is_high_entropy(low_entropy));
        
        // High entropy data (random-like)
        let high_entropy = b"\x12\x34\x56\x78\x9a\xbc\xde\xf0\x11\x22\x33\x44\x55\x66\x77\x88";
        let entropy = calculate_entropy(high_entropy);
        assert!(entropy > 3.0);
    }

    #[test]
    fn test_binary_detection() {
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        
        // Text data
        let text_result = BannerResult::new(target, Protocol::Tcp)
            .with_raw_data(b"HTTP/1.1 200 OK".to_vec());
        assert!(!text_result.is_binary());
        
        // Binary data
        let binary_result = BannerResult::new(target, Protocol::Tcp)
            .with_raw_data(vec![0x00, 0x01, 0x02, 0x03, 0xff]);
        assert!(binary_result.is_binary());
    }
}
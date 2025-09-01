//! Service detection implementation for cyNetMapper

use crate::common::{ProbeError, ProbeOptions, ProbeResult};
use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::{IpAddr, Protocol, PortState},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, trace, warn};
use regex::Regex;

/// Service detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    /// Service name (e.g., "http", "ssh", "ftp")
    pub name: String,
    
    /// Service version (if detected)
    pub version: Option<String>,
    
    /// Product name (e.g., "Apache", "OpenSSH", "vsftpd")
    pub product: Option<String>,
    
    /// Extra information
    pub extra_info: Option<String>,
    
    /// Operating system hints
    pub os_hint: Option<String>,
    
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    
    /// Detection method used
    pub detection_method: DetectionMethod,
    
    /// Raw banner/response that led to detection
    pub raw_response: Option<String>,
}

impl ServiceInfo {
    /// Create a new service info
    pub fn new(name: String, confidence: f32, method: DetectionMethod) -> Self {
        Self {
            name,
            version: None,
            product: None,
            extra_info: None,
            os_hint: None,
            confidence,
            detection_method: method,
            raw_response: None,
        }
    }
    
    /// Set version
    pub fn with_version(mut self, version: String) -> Self {
        self.version = Some(version);
        self
    }
    
    /// Set product
    pub fn with_product(mut self, product: String) -> Self {
        self.product = Some(product);
        self
    }
    
    /// Set extra info
    pub fn with_extra_info(mut self, info: String) -> Self {
        self.extra_info = Some(info);
        self
    }
    
    /// Set OS hint
    pub fn with_os_hint(mut self, os: String) -> Self {
        self.os_hint = Some(os);
        self
    }
    
    /// Set raw response
    pub fn with_raw_response(mut self, response: String) -> Self {
        self.raw_response = Some(response);
        self
    }
}

/// Detection method used
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DetectionMethod {
    /// Port-based detection (default service for port)
    PortBased,
    /// Banner grabbing
    BannerGrabbing,
    /// Protocol-specific probing
    ProtocolProbing,
    /// Response pattern matching
    PatternMatching,
    /// Behavioral analysis
    BehavioralAnalysis,
}

/// Service signature for pattern matching
#[derive(Debug, Clone)]
struct ServiceSignature {
    /// Service name
    name: String,
    /// Protocol (TCP/UDP)
    protocol: Protocol,
    /// Port number (0 for any port)
    port: u16,
    /// Regex pattern to match
    pattern: Regex,
    /// Product extraction group (optional)
    product_group: Option<usize>,
    /// Version extraction group (optional)
    version_group: Option<usize>,
    /// Confidence level
    confidence: f32,
}

/// Service detector
#[derive(Debug, Clone)]
pub struct ServiceDetector {
    /// Configuration
    config: Config,
    
    /// Service signatures
    signatures: Vec<ServiceSignature>,
    
    /// Port-to-service mappings
    port_services: HashMap<(Protocol, u16), String>,
}

impl ServiceDetector {
    /// Create a new service detector
    pub fn new(config: &Config) -> Result<Self> {
        let mut detector = Self {
            config: config.clone(),
            signatures: Vec::new(),
            port_services: HashMap::new(),
        };
        
        detector.load_signatures();
        detector.load_port_mappings();
        
        Ok(detector)
    }
    
    /// Detect service from probe result
    pub fn detect_service(
        &self,
        target: SocketAddr,
        protocol: Protocol,
        banner: Option<&str>,
        port_state: PortState,
    ) -> Option<ServiceInfo> {
        if port_state != PortState::Open {
            return None;
        }
        
        debug!("Detecting service on {}:{}/{:?}", target.ip(), target.port(), protocol);
        
        // Try banner-based detection first (highest confidence)
        if let Some(banner_text) = banner {
            if let Some(service) = self.detect_from_banner(target.port(), protocol, banner_text) {
                trace!("Service detected from banner: {:?}", service);
                return Some(service);
            }
        }
        
        // Fall back to port-based detection
        if let Some(service) = self.detect_from_port(target.port(), protocol) {
            trace!("Service detected from port: {:?}", service);
            return Some(service);
        }
        
        None
    }
    
    /// Detect service from banner
    fn detect_from_banner(&self, port: u16, protocol: Protocol, banner: &str) -> Option<ServiceInfo> {
        for signature in &self.signatures {
            // Check if signature applies to this protocol and port
            if signature.protocol != protocol {
                continue;
            }
            
            if signature.port != 0 && signature.port != port {
                continue;
            }
            
            // Try to match the pattern
            if let Some(captures) = signature.pattern.captures(banner) {
                let mut service = ServiceInfo::new(
                    signature.name.clone(),
                    signature.confidence,
                    DetectionMethod::BannerGrabbing,
                ).with_raw_response(banner.to_string());
                
                // Extract product if specified
                if let Some(group_idx) = signature.product_group {
                    if let Some(product_match) = captures.get(group_idx) {
                        service = service.with_product(product_match.as_str().to_string());
                    }
                }
                
                // Extract version if specified
                if let Some(group_idx) = signature.version_group {
                    if let Some(version_match) = captures.get(group_idx) {
                        service = service.with_version(version_match.as_str().to_string());
                    }
                }
                
                return Some(service);
            }
        }
        
        None
    }
    
    /// Detect service from port number
    fn detect_from_port(&self, port: u16, protocol: Protocol) -> Option<ServiceInfo> {
        if let Some(service_name) = self.port_services.get(&(protocol, port)) {
            Some(ServiceInfo::new(
                service_name.clone(),
                0.5, // Lower confidence for port-based detection
                DetectionMethod::PortBased,
            ))
        } else {
            None
        }
    }
    
    /// Load service signatures
    fn load_signatures(&mut self) {
        // HTTP signatures
        self.add_signature("http", Protocol::Tcp, 0, 
            r"HTTP/([0-9.]+)\s+(\d+)\s+([^\r\n]+)", 
            None, Some(1), 0.9);
        
        self.add_signature("http", Protocol::Tcp, 0,
            r"Server:\s*([^\r\n/]+)(?:/([^\r\n\s]+))?",
            Some(1), Some(2), 0.8);
        
        // SSH signatures
        self.add_signature("ssh", Protocol::Tcp, 22,
            r"SSH-([0-9.]+)-([^\r\n\s]+)(?:\s+([^\r\n]+))?",
            Some(2), Some(1), 0.9);
        
        // FTP signatures
        self.add_signature("ftp", Protocol::Tcp, 21,
            r"220[^\r\n]*\s+([^\r\n/]+)(?:/([^\r\n\s]+))?",
            Some(1), Some(2), 0.8);
        
        self.add_signature("ftp", Protocol::Tcp, 21,
            r"220[^\r\n]*vsftpd\s+([0-9.]+)",
            None, Some(1), 0.9);
        
        // SMTP signatures
        self.add_signature("smtp", Protocol::Tcp, 25,
            r"220[^\r\n]*\s+([^\r\n/]+)(?:/([^\r\n\s]+))?",
            Some(1), Some(2), 0.7);
        
        self.add_signature("smtp", Protocol::Tcp, 25,
            r"220[^\r\n]*Postfix",
            Some(1), None, 0.8);
        
        // DNS signatures
        self.add_signature("dns", Protocol::Udp, 53,
            r"version\.bind.*?([^\r\n]+)",
            None, Some(1), 0.8);
        
        // SNMP signatures
        self.add_signature("snmp", Protocol::Udp, 161,
            r"\x30[\x80-\xff]",
            None, None, 0.7);
        
        // TLS/SSL signatures
        self.add_signature("ssl", Protocol::Tcp, 443,
            r"\x16\x03[\x00-\x03]",
            None, None, 0.8);
        
        // MySQL signatures
        self.add_signature("mysql", Protocol::Tcp, 3306,
            r"\x00\x00\x00\x0a([0-9.]+[^\x00]*)",
            None, Some(1), 0.9);
        
        // PostgreSQL signatures
        self.add_signature("postgresql", Protocol::Tcp, 5432,
            r"FATAL.*?database.*?does not exist",
            None, None, 0.8);
        
        // Redis signatures
        self.add_signature("redis", Protocol::Tcp, 6379,
            r"-NOAUTH Authentication required",
            None, None, 0.9);
        
        // Telnet signatures
        self.add_signature("telnet", Protocol::Tcp, 23,
            r"\xff[\xfb-\xfe]",
            None, None, 0.7);
        
        // POP3 signatures
        self.add_signature("pop3", Protocol::Tcp, 110,
            r"\+OK.*?([^\r\n/]+)(?:/([^\r\n\s]+))?",
            Some(1), Some(2), 0.8);
        
        // IMAP signatures
        self.add_signature("imap", Protocol::Tcp, 143,
            r"\* OK.*?([^\r\n/]+)(?:/([^\r\n\s]+))?",
            Some(1), Some(2), 0.8);
        
        // LDAP signatures
        self.add_signature("ldap", Protocol::Tcp, 389,
            r"\x30[\x80-\xff].*?\x02\x01",
            None, None, 0.7);
        
        // SIP signatures
        self.add_signature("sip", Protocol::Udp, 5060,
            r"SIP/2\.0\s+(\d+)\s+([^\r\n]+)",
            None, None, 0.8);
        
        // NTP signatures
        self.add_signature("ntp", Protocol::Udp, 123,
            r"\x1c[\x01-\x04]",
            None, None, 0.7);
    }
    
    /// Add a service signature
    fn add_signature(
        &mut self,
        name: &str,
        protocol: Protocol,
        port: u16,
        pattern: &str,
        product_group: Option<usize>,
        version_group: Option<usize>,
        confidence: f32,
    ) {
        if let Ok(regex) = Regex::new(pattern) {
            self.signatures.push(ServiceSignature {
                name: name.to_string(),
                protocol,
                port,
                pattern: regex,
                product_group,
                version_group,
                confidence,
            });
        } else {
            warn!("Invalid regex pattern for service {}: {}", name, pattern);
        }
    }
    
    /// Load port-to-service mappings
    fn load_port_mappings(&mut self) {
        // TCP services
        let tcp_services = [
            (21, "ftp"),
            (22, "ssh"),
            (23, "telnet"),
            (25, "smtp"),
            (53, "dns"),
            (80, "http"),
            (110, "pop3"),
            (143, "imap"),
            (443, "https"),
            (993, "imaps"),
            (995, "pop3s"),
            (1433, "mssql"),
            (3306, "mysql"),
            (3389, "rdp"),
            (5432, "postgresql"),
            (5900, "vnc"),
            (6379, "redis"),
            (8080, "http-proxy"),
            (8443, "https-alt"),
        ];
        
        for (port, service) in tcp_services {
            self.port_services.insert((Protocol::Tcp, port), service.to_string());
        }
        
        // UDP services
        let udp_services = [
            (53, "dns"),
            (67, "dhcp-server"),
            (68, "dhcp-client"),
            (69, "tftp"),
            (111, "rpcbind"),
            (123, "ntp"),
            (137, "netbios-ns"),
            (138, "netbios-dgm"),
            (161, "snmp"),
            (162, "snmp-trap"),
            (514, "syslog"),
            (520, "rip"),
            (1900, "upnp"),
            (5060, "sip"),
        ];
        
        for (port, service) in udp_services {
            self.port_services.insert((Protocol::Udp, port), service.to_string());
        }
    }
    
    /// Get all known services for a protocol
    pub fn get_known_services(&self, protocol: Protocol) -> Vec<(u16, &str)> {
        self.port_services
            .iter()
            .filter(|((proto, _), _)| *proto == protocol)
            .map(|((_, port), service)| (*port, service.as_str()))
            .collect()
    }
    
    /// Check if a port is commonly associated with a service
    pub fn is_common_port(&self, protocol: Protocol, port: u16) -> bool {
        self.port_services.contains_key(&(protocol, port))
    }
    
    /// Get service name for a port (if known)
    pub fn get_service_name(&self, protocol: Protocol, port: u16) -> Option<&str> {
        self.port_services.get(&(protocol, port)).map(|s| s.as_str())
    }
}

/// Service detection utilities
pub mod utils {
    use super::*;
    
    /// Extract HTTP server information from headers
    pub fn parse_http_headers(response: &str) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        
        for line in response.lines() {
            if let Some(colon_pos) = line.find(':') {
                let key = line[..colon_pos].trim().to_lowercase();
                let value = line[colon_pos + 1..].trim().to_string();
                headers.insert(key, value);
            }
        }
        
        headers
    }
    
    /// Check if response looks like HTTP
    pub fn is_http_response(response: &str) -> bool {
        response.starts_with("HTTP/") || response.contains("Content-Type:")
    }
    
    /// Check if response looks like TLS/SSL
    pub fn is_tls_response(response: &[u8]) -> bool {
        response.len() >= 3 && 
        response[0] == 0x16 && 
        response[1] == 0x03 && 
        (response[2] >= 0x00 && response[2] <= 0x04)
    }
    
    /// Extract version from banner
    pub fn extract_version(banner: &str) -> Option<String> {
        // Common version patterns
        let patterns = [
            r"version\s+([0-9]+(?:\.[0-9]+)*)",
            r"v([0-9]+(?:\.[0-9]+)*)",
            r"([0-9]+(?:\.[0-9]+){1,3})",
        ];
        
        for pattern in &patterns {
            if let Ok(regex) = Regex::new(pattern) {
                if let Some(captures) = regex.captures(banner) {
                    if let Some(version_match) = captures.get(1) {
                        return Some(version_match.as_str().to_string());
                    }
                }
            }
        }
        
        None
    }
    
    /// Normalize service name
    pub fn normalize_service_name(name: &str) -> String {
        name.to_lowercase()
            .replace("-", "")
            .replace("_", "")
            .replace(" ", "")
    }
    
    /// Get confidence level based on detection method
    pub fn get_confidence_for_method(method: &DetectionMethod) -> f32 {
        match method {
            DetectionMethod::BannerGrabbing => 0.9,
            DetectionMethod::ProtocolProbing => 0.8,
            DetectionMethod::PatternMatching => 0.7,
            DetectionMethod::BehavioralAnalysis => 0.6,
            DetectionMethod::PortBased => 0.5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::net::{Ipv4Addr, SocketAddr};

    #[test]
    fn test_service_detector_creation() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config);
        assert!(detector.is_ok());
    }

    #[test]
    fn test_http_detection() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        let banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\n";
        
        let service = detector.detect_service(target, Protocol::Tcp, Some(banner), PortState::Open);
        assert!(service.is_some());
        
        let service_info = service.unwrap();
        assert_eq!(service_info.name, "http");
        assert_eq!(service_info.detection_method, DetectionMethod::BannerGrabbing);
        assert!(service_info.confidence > 0.8);
    }

    #[test]
    fn test_ssh_detection() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 22);
        let banner = "SSH-2.0-OpenSSH_8.3";
        
        let service = detector.detect_service(target, Protocol::Tcp, Some(banner), PortState::Open);
        assert!(service.is_some());
        
        let service_info = service.unwrap();
        assert_eq!(service_info.name, "ssh");
        assert_eq!(service_info.detection_method, DetectionMethod::BannerGrabbing);
        assert!(service_info.product.is_some());
        assert!(service_info.version.is_some());
    }

    #[test]
    fn test_port_based_detection() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        
        let service = detector.detect_service(target, Protocol::Tcp, None, PortState::Open);
        assert!(service.is_some());
        
        let service_info = service.unwrap();
        assert_eq!(service_info.name, "http");
        assert_eq!(service_info.detection_method, DetectionMethod::PortBased);
        assert_eq!(service_info.confidence, 0.5);
    }

    #[test]
    fn test_no_detection_for_closed_port() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        let target = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 80);
        
        let service = detector.detect_service(target, Protocol::Tcp, None, PortState::Closed);
        assert!(service.is_none());
    }

    #[test]
    fn test_service_info_builder() {
        let service = ServiceInfo::new("http".to_string(), 0.9, DetectionMethod::BannerGrabbing)
            .with_version("1.1".to_string())
            .with_product("Apache".to_string())
            .with_extra_info("Ubuntu".to_string())
            .with_os_hint("Linux".to_string())
            .with_raw_response("HTTP/1.1 200 OK".to_string());
        
        assert_eq!(service.name, "http");
        assert_eq!(service.version, Some("1.1".to_string()));
        assert_eq!(service.product, Some("Apache".to_string()));
        assert_eq!(service.extra_info, Some("Ubuntu".to_string()));
        assert_eq!(service.os_hint, Some("Linux".to_string()));
        assert_eq!(service.confidence, 0.9);
    }

    #[test]
    fn test_known_services() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        let tcp_services = detector.get_known_services(Protocol::Tcp);
        assert!(!tcp_services.is_empty());
        assert!(tcp_services.iter().any(|(port, service)| *port == 80 && *service == "http"));
        
        let udp_services = detector.get_known_services(Protocol::Udp);
        assert!(!udp_services.is_empty());
        assert!(udp_services.iter().any(|(port, service)| *port == 53 && *service == "dns"));
    }

    #[test]
    fn test_common_port_check() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        assert!(detector.is_common_port(Protocol::Tcp, 80));
        assert!(detector.is_common_port(Protocol::Tcp, 443));
        assert!(detector.is_common_port(Protocol::Udp, 53));
        assert!(!detector.is_common_port(Protocol::Tcp, 9999));
    }

    #[test]
    fn test_service_name_lookup() {
        let config = Config::default();
        let detector = ServiceDetector::new(&config).unwrap();
        
        assert_eq!(detector.get_service_name(Protocol::Tcp, 80), Some("http"));
        assert_eq!(detector.get_service_name(Protocol::Tcp, 443), Some("https"));
        assert_eq!(detector.get_service_name(Protocol::Udp, 53), Some("dns"));
        assert_eq!(detector.get_service_name(Protocol::Tcp, 9999), None);
    }

    #[test]
    fn test_http_header_parsing() {
        use utils::*;
        
        let response = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n";
        let headers = parse_http_headers(response);
        
        assert_eq!(headers.get("server"), Some(&"Apache/2.4.41".to_string()));
        assert_eq!(headers.get("content-type"), Some(&"text/html".to_string()));
    }

    #[test]
    fn test_http_response_detection() {
        use utils::*;
        
        assert!(is_http_response("HTTP/1.1 200 OK"));
        assert!(is_http_response("Content-Type: text/html"));
        assert!(!is_http_response("SSH-2.0-OpenSSH"));
    }

    #[test]
    fn test_tls_response_detection() {
        use utils::*;
        
        let tls_response = [0x16, 0x03, 0x01, 0x00, 0x2f];
        assert!(is_tls_response(&tls_response));
        
        let non_tls_response = [0x48, 0x54, 0x54, 0x50]; // "HTTP"
        assert!(!is_tls_response(&non_tls_response));
    }

    #[test]
    fn test_version_extraction() {
        use utils::*;
        
        assert_eq!(extract_version("Apache/2.4.41"), Some("2.4.41".to_string()));
        assert_eq!(extract_version("version 1.2.3"), Some("1.2.3".to_string()));
        assert_eq!(extract_version("v3.1.4"), Some("3.1.4".to_string()));
        assert_eq!(extract_version("no version here"), None);
    }

    #[test]
    fn test_service_name_normalization() {
        use utils::*;
        
        assert_eq!(normalize_service_name("HTTP-Proxy"), "httpproxy");
        assert_eq!(normalize_service_name("DNS_Server"), "dnsserver");
        assert_eq!(normalize_service_name("Web Server"), "webserver");
    }

    #[test]
    fn test_confidence_levels() {
        use utils::*;
        
        assert_eq!(get_confidence_for_method(&DetectionMethod::BannerGrabbing), 0.9);
        assert_eq!(get_confidence_for_method(&DetectionMethod::ProtocolProbing), 0.8);
        assert_eq!(get_confidence_for_method(&DetectionMethod::PortBased), 0.5);
    }
}
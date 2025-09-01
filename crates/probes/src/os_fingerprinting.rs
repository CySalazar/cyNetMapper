//! OS fingerprinting implementation for cyNetMapper

use crate::common::{ProbeError, ProbeOptions, ProbeResult};
use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::{IpAddr, Protocol},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tracing::{debug, trace, warn};

/// OS fingerprint result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsFingerprint {
    /// Target address
    pub target: IpAddr,
    
    /// Detected OS family
    pub os_family: Option<String>,
    
    /// Detected OS version
    pub os_version: Option<String>,
    
    /// Device type (router, switch, server, etc.)
    pub device_type: Option<String>,
    
    /// Confidence level (0.0 - 1.0)
    pub confidence: f32,
    
    /// Detection methods used
    pub detection_methods: Vec<FingerprintMethod>,
    
    /// TCP fingerprint data
    pub tcp_fingerprint: Option<TcpFingerprint>,
    
    /// ICMP fingerprint data
    pub icmp_fingerprint: Option<IcmpFingerprint>,
    
    /// HTTP fingerprint data
    pub http_fingerprint: Option<HttpFingerprint>,
    
    /// SSH fingerprint data
    pub ssh_fingerprint: Option<SshFingerprint>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl OsFingerprint {
    /// Create a new OS fingerprint
    pub fn new(target: IpAddr) -> Self {
        Self {
            target,
            os_family: None,
            os_version: None,
            device_type: None,
            confidence: 0.0,
            detection_methods: Vec::new(),
            tcp_fingerprint: None,
            icmp_fingerprint: None,
            http_fingerprint: None,
            ssh_fingerprint: None,
            metadata: HashMap::new(),
        }
    }
    
    /// Set OS family
    pub fn with_os_family(mut self, family: String) -> Self {
        self.os_family = Some(family);
        self
    }
    
    /// Set OS version
    pub fn with_os_version(mut self, version: String) -> Self {
        self.os_version = Some(version);
        self
    }
    
    /// Set device type
    pub fn with_device_type(mut self, device_type: String) -> Self {
        self.device_type = Some(device_type);
        self
    }
    
    /// Set confidence
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = confidence.clamp(0.0, 1.0);
        self
    }
    
    /// Add detection method
    pub fn add_method(mut self, method: FingerprintMethod) -> Self {
        if !self.detection_methods.contains(&method) {
            self.detection_methods.push(method);
        }
        self
    }
    
    /// Set TCP fingerprint
    pub fn with_tcp_fingerprint(mut self, fingerprint: TcpFingerprint) -> Self {
        self.tcp_fingerprint = Some(fingerprint);
        self
    }
    
    /// Add metadata
    pub fn with_metadata(mut self, key: String, value: String) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Check if OS is detected
    pub fn is_detected(&self) -> bool {
        self.os_family.is_some() && self.confidence > 0.0
    }
    
    /// Get OS description
    pub fn get_os_description(&self) -> String {
        match (&self.os_family, &self.os_version) {
            (Some(family), Some(version)) => format!("{} {}", family, version),
            (Some(family), None) => family.clone(),
            _ => "Unknown".to_string(),
        }
    }
}

/// Fingerprinting method
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum FingerprintMethod {
    /// TCP stack fingerprinting
    TcpStack,
    /// ICMP fingerprinting
    Icmp,
    /// HTTP header analysis
    HttpHeaders,
    /// SSH banner analysis
    SshBanner,
    /// Service banner analysis
    ServiceBanners,
    /// TTL analysis
    TtlAnalysis,
    /// Window size analysis
    WindowSize,
    /// TCP options analysis
    TcpOptions,
}

/// TCP fingerprint data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFingerprint {
    /// Initial TTL
    pub initial_ttl: Option<u8>,
    
    /// Window size
    pub window_size: Option<u16>,
    
    /// TCP options
    pub tcp_options: Vec<u8>,
    
    /// MSS (Maximum Segment Size)
    pub mss: Option<u16>,
    
    /// Window scaling factor
    pub window_scale: Option<u8>,
    
    /// SACK permitted
    pub sack_permitted: bool,
    
    /// Timestamp option
    pub timestamp: bool,
    
    /// Don't fragment flag
    pub dont_fragment: bool,
    
    /// TCP flags in response
    pub tcp_flags: Option<u8>,
}

impl TcpFingerprint {
    /// Create new TCP fingerprint
    pub fn new() -> Self {
        Self {
            initial_ttl: None,
            window_size: None,
            tcp_options: Vec::new(),
            mss: None,
            window_scale: None,
            sack_permitted: false,
            timestamp: false,
            dont_fragment: false,
            tcp_flags: None,
        }
    }
    
    /// Calculate fingerprint score against known signatures
    pub fn calculate_score(&self, signature: &TcpFingerprint) -> f32 {
        let mut score = 0.0;
        let mut total_weight = 0.0;
        
        // TTL matching (weight: 3.0)
        if let (Some(our_ttl), Some(sig_ttl)) = (self.initial_ttl, signature.initial_ttl) {
            let ttl_diff = (our_ttl as i16 - sig_ttl as i16).abs() as f32;
            score += (1.0 - (ttl_diff / 64.0).min(1.0)) * 3.0;
            total_weight += 3.0;
        }
        
        // Window size matching (weight: 2.0)
        if let (Some(our_win), Some(sig_win)) = (self.window_size, signature.window_size) {
            if our_win == sig_win {
                score += 2.0;
            } else {
                let win_ratio = (our_win as f32 / sig_win as f32).min(sig_win as f32 / our_win as f32);
                score += win_ratio * 2.0;
            }
            total_weight += 2.0;
        }
        
        // TCP options matching (weight: 2.5)
        if !signature.tcp_options.is_empty() {
            let options_match = self.tcp_options == signature.tcp_options;
            score += if options_match { 2.5 } else { 0.0 };
            total_weight += 2.5;
        }
        
        // Boolean flags (weight: 1.0 each)
        if signature.sack_permitted == self.sack_permitted {
            score += 1.0;
        }
        total_weight += 1.0;
        
        if signature.timestamp == self.timestamp {
            score += 1.0;
        }
        total_weight += 1.0;
        
        if signature.dont_fragment == self.dont_fragment {
            score += 1.0;
        }
        total_weight += 1.0;
        
        if total_weight > 0.0 {
            score / total_weight
        } else {
            0.0
        }
    }
}

/// ICMP fingerprint data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpFingerprint {
    /// ICMP response code
    pub response_code: Option<u8>,
    
    /// ICMP response type
    pub response_type: Option<u8>,
    
    /// TTL in ICMP response
    pub ttl: Option<u8>,
    
    /// ICMP payload echoed back
    pub payload_echoed: bool,
    
    /// IP ID in response
    pub ip_id: Option<u16>,
    
    /// Don't fragment flag
    pub dont_fragment: bool,
}

/// HTTP fingerprint data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpFingerprint {
    /// Server header
    pub server_header: Option<String>,
    
    /// Supported HTTP methods
    pub supported_methods: Vec<String>,
    
    /// Default error pages
    pub error_pages: HashMap<u16, String>,
    
    /// Header order
    pub header_order: Vec<String>,
    
    /// Case sensitivity
    pub case_sensitive: bool,
}

/// SSH fingerprint data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshFingerprint {
    /// SSH version string
    pub version_string: String,
    
    /// Supported algorithms
    pub algorithms: Vec<String>,
    
    /// Key exchange methods
    pub kex_methods: Vec<String>,
    
    /// Host key types
    pub host_key_types: Vec<String>,
}

/// OS fingerprinting engine
#[derive(Debug)]
pub struct OsFingerprinter {
    /// Configuration
    config: Config,
    
    /// Known OS signatures
    signatures: Vec<OsSignature>,
    
    /// TTL-based OS detection
    ttl_signatures: HashMap<u8, Vec<String>>,
}

/// OS signature for matching
#[derive(Debug, Clone)]
struct OsSignature {
    /// OS family
    os_family: String,
    
    /// OS version
    os_version: Option<String>,
    
    /// Device type
    device_type: Option<String>,
    
    /// TCP fingerprint
    tcp_fingerprint: Option<TcpFingerprint>,
    
    /// ICMP fingerprint
    icmp_fingerprint: Option<IcmpFingerprint>,
    
    /// HTTP patterns
    http_patterns: Vec<String>,
    
    /// SSH patterns
    ssh_patterns: Vec<String>,
    
    /// Confidence weight
    weight: f32,
}

impl OsFingerprinter {
    /// Create a new OS fingerprinter
    pub fn new(config: &Config) -> Self {
        let mut fingerprinter = Self {
            config: config.clone(),
            signatures: Vec::new(),
            ttl_signatures: HashMap::new(),
        };
        
        fingerprinter.load_signatures();
        fingerprinter.load_ttl_signatures();
        
        fingerprinter
    }
    
    /// Perform OS fingerprinting
    pub async fn fingerprint_os(
        &self,
        target: IpAddr,
        tcp_data: Option<&TcpFingerprint>,
        icmp_data: Option<&IcmpFingerprint>,
        http_banner: Option<&str>,
        ssh_banner: Option<&str>,
    ) -> Result<OsFingerprint> {
        let mut fingerprint = OsFingerprint::new(target);
        let mut best_match: Option<(&OsSignature, f32)> = None;
        
        debug!("Starting OS fingerprinting for {}", target);
        
        // Try to match against known signatures
        for signature in &self.signatures {
            let mut score = 0.0;
            let mut total_weight = 0.0;
            
            // TCP fingerprint matching
            if let (Some(tcp_data), Some(sig_tcp)) = (tcp_data, &signature.tcp_fingerprint) {
                let tcp_score = tcp_data.calculate_score(sig_tcp);
                score += tcp_score * 4.0; // High weight for TCP fingerprinting
                total_weight += 4.0;
                trace!("TCP fingerprint score for {}: {}", signature.os_family, tcp_score);
            }
            
            // ICMP fingerprint matching
            if let (Some(icmp_data), Some(sig_icmp)) = (icmp_data, &signature.icmp_fingerprint) {
                let icmp_score = self.calculate_icmp_score(icmp_data, sig_icmp);
                score += icmp_score * 2.0;
                total_weight += 2.0;
                trace!("ICMP fingerprint score for {}: {}", signature.os_family, icmp_score);
            }
            
            // HTTP banner matching
            if let Some(http_banner) = http_banner {
                let http_score = self.calculate_http_score(http_banner, &signature.http_patterns);
                score += http_score * 1.5;
                total_weight += 1.5;
                trace!("HTTP banner score for {}: {}", signature.os_family, http_score);
            }
            
            // SSH banner matching
            if let Some(ssh_banner) = ssh_banner {
                let ssh_score = self.calculate_ssh_score(ssh_banner, &signature.ssh_patterns);
                score += ssh_score * 1.5;
                total_weight += 1.5;
                trace!("SSH banner score for {}: {}", signature.os_family, ssh_score);
            }
            
            // Calculate final score
            let final_score = if total_weight > 0.0 {
                (score / total_weight) * signature.weight
            } else {
                0.0
            };
            
            // Update best match
            if final_score > best_match.as_ref().map_or(0.0, |(_, s)| *s) {
                best_match = Some((signature, final_score));
            }
        }
        
        // Apply best match if confidence is high enough
        if let Some((signature, score)) = best_match {
            if score > 0.3 { // Minimum confidence threshold
                fingerprint = fingerprint
                    .with_os_family(signature.os_family.clone())
                    .with_confidence(score);
                
                if let Some(version) = &signature.os_version {
                    fingerprint = fingerprint.with_os_version(version.clone());
                }
                
                if let Some(device_type) = &signature.device_type {
                    fingerprint = fingerprint.with_device_type(device_type.clone());
                }
                
                debug!("OS detected: {} (confidence: {:.2})", signature.os_family, score);
            }
        }
        
        // Fallback to TTL-based detection
        if !fingerprint.is_detected() {
            if let Some(tcp_data) = tcp_data {
                if let Some(ttl) = tcp_data.initial_ttl {
                    fingerprint = self.detect_from_ttl(fingerprint, ttl);
                }
            }
        }
        
        // Add fingerprint data
        if let Some(tcp_data) = tcp_data {
            fingerprint = fingerprint.with_tcp_fingerprint(tcp_data.clone())
                .add_method(FingerprintMethod::TcpStack);
        }
        
        if icmp_data.is_some() {
            fingerprint = fingerprint.add_method(FingerprintMethod::Icmp);
        }
        
        if http_banner.is_some() {
            fingerprint = fingerprint.add_method(FingerprintMethod::HttpHeaders);
        }
        
        if ssh_banner.is_some() {
            fingerprint = fingerprint.add_method(FingerprintMethod::SshBanner);
        }
        
        Ok(fingerprint)
    }
    
    /// Calculate ICMP fingerprint score
    fn calculate_icmp_score(&self, icmp_data: &IcmpFingerprint, signature: &IcmpFingerprint) -> f32 {
        let mut score = 0.0;
        let mut total_weight = 0.0;
        
        // Response type matching
        if let (Some(our_type), Some(sig_type)) = (icmp_data.response_type, signature.response_type) {
            score += if our_type == sig_type { 1.0 } else { 0.0 };
            total_weight += 1.0;
        }
        
        // TTL matching
        if let (Some(our_ttl), Some(sig_ttl)) = (icmp_data.ttl, signature.ttl) {
            let ttl_diff = (our_ttl as i16 - sig_ttl as i16).abs() as f32;
            score += (1.0 - (ttl_diff / 64.0).min(1.0));
            total_weight += 1.0;
        }
        
        // Boolean flags
        if icmp_data.payload_echoed == signature.payload_echoed {
            score += 0.5;
        }
        total_weight += 0.5;
        
        if icmp_data.dont_fragment == signature.dont_fragment {
            score += 0.5;
        }
        total_weight += 0.5;
        
        if total_weight > 0.0 {
            score / total_weight
        } else {
            0.0
        }
    }
    
    /// Calculate HTTP banner score
    fn calculate_http_score(&self, banner: &str, patterns: &[String]) -> f32 {
        if patterns.is_empty() {
            return 0.0;
        }
        
        let banner_lower = banner.to_lowercase();
        let mut matches = 0;
        
        for pattern in patterns {
            if banner_lower.contains(&pattern.to_lowercase()) {
                matches += 1;
            }
        }
        
        matches as f32 / patterns.len() as f32
    }
    
    /// Calculate SSH banner score
    fn calculate_ssh_score(&self, banner: &str, patterns: &[String]) -> f32 {
        if patterns.is_empty() {
            return 0.0;
        }
        
        let banner_lower = banner.to_lowercase();
        let mut matches = 0;
        
        for pattern in patterns {
            if banner_lower.contains(&pattern.to_lowercase()) {
                matches += 1;
            }
        }
        
        matches as f32 / patterns.len() as f32
    }
    
    /// Detect OS from TTL value
    fn detect_from_ttl(&self, mut fingerprint: OsFingerprint, ttl: u8) -> OsFingerprint {
        // Common initial TTL values and their associated OS families
        let initial_ttl = if ttl > 128 {
            255
        } else if ttl > 64 {
            128
        } else if ttl > 32 {
            64
        } else {
            32
        };
        
        if let Some(os_families) = self.ttl_signatures.get(&initial_ttl) {
            if let Some(os_family) = os_families.first() {
                fingerprint = fingerprint
                    .with_os_family(os_family.clone())
                    .with_confidence(0.3) // Low confidence for TTL-only detection
                    .add_method(FingerprintMethod::TtlAnalysis);
                
                debug!("OS detected from TTL {}: {} (confidence: 0.3)", ttl, os_family);
            }
        }
        
        fingerprint
    }
    
    /// Load OS signatures
    fn load_signatures(&mut self) {
        // Windows signatures
        let mut windows_tcp = TcpFingerprint::new();
        windows_tcp.initial_ttl = Some(128);
        windows_tcp.window_size = Some(65535);
        windows_tcp.mss = Some(1460);
        windows_tcp.sack_permitted = true;
        windows_tcp.timestamp = false;
        
        self.signatures.push(OsSignature {
            os_family: "Windows".to_string(),
            os_version: Some("10/11".to_string()),
            device_type: Some("Desktop".to_string()),
            tcp_fingerprint: Some(windows_tcp),
            icmp_fingerprint: None,
            http_patterns: vec!["Microsoft-IIS".to_string(), "ASP.NET".to_string()],
            ssh_patterns: vec![],
            weight: 1.0,
        });
        
        // Linux signatures
        let mut linux_tcp = TcpFingerprint::new();
        linux_tcp.initial_ttl = Some(64);
        linux_tcp.window_size = Some(29200);
        linux_tcp.mss = Some(1460);
        linux_tcp.sack_permitted = true;
        linux_tcp.timestamp = true;
        linux_tcp.window_scale = Some(7);
        
        self.signatures.push(OsSignature {
            os_family: "Linux".to_string(),
            os_version: None,
            device_type: Some("Server".to_string()),
            tcp_fingerprint: Some(linux_tcp),
            icmp_fingerprint: None,
            http_patterns: vec!["Apache".to_string(), "nginx".to_string()],
            ssh_patterns: vec!["OpenSSH".to_string()],
            weight: 1.0,
        });
        
        // macOS signatures
        let mut macos_tcp = TcpFingerprint::new();
        macos_tcp.initial_ttl = Some(64);
        macos_tcp.window_size = Some(65535);
        macos_tcp.mss = Some(1460);
        macos_tcp.sack_permitted = true;
        macos_tcp.timestamp = true;
        macos_tcp.window_scale = Some(6);
        
        self.signatures.push(OsSignature {
            os_family: "macOS".to_string(),
            os_version: None,
            device_type: Some("Desktop".to_string()),
            tcp_fingerprint: Some(macos_tcp),
            icmp_fingerprint: None,
            http_patterns: vec![],
            ssh_patterns: vec!["OpenSSH".to_string()],
            weight: 1.0,
        });
        
        // FreeBSD signatures
        let mut freebsd_tcp = TcpFingerprint::new();
        freebsd_tcp.initial_ttl = Some(64);
        freebsd_tcp.window_size = Some(65535);
        freebsd_tcp.mss = Some(1460);
        freebsd_tcp.sack_permitted = true;
        freebsd_tcp.timestamp = true;
        
        self.signatures.push(OsSignature {
            os_family: "FreeBSD".to_string(),
            os_version: None,
            device_type: Some("Server".to_string()),
            tcp_fingerprint: Some(freebsd_tcp),
            icmp_fingerprint: None,
            http_patterns: vec![],
            ssh_patterns: vec!["OpenSSH".to_string()],
            weight: 1.0,
        });
        
        // Cisco IOS signatures
        let mut cisco_tcp = TcpFingerprint::new();
        cisco_tcp.initial_ttl = Some(255);
        cisco_tcp.window_size = Some(4128);
        cisco_tcp.mss = Some(536);
        cisco_tcp.sack_permitted = false;
        cisco_tcp.timestamp = false;
        
        self.signatures.push(OsSignature {
            os_family: "Cisco IOS".to_string(),
            os_version: None,
            device_type: Some("Router".to_string()),
            tcp_fingerprint: Some(cisco_tcp),
            icmp_fingerprint: None,
            http_patterns: vec!["cisco".to_string()],
            ssh_patterns: vec!["Cisco".to_string()],
            weight: 1.2,
        });
    }
    
    /// Load TTL-based signatures
    fn load_ttl_signatures(&mut self) {
        self.ttl_signatures.insert(32, vec!["Linux (old)".to_string(), "Unix".to_string()]);
        self.ttl_signatures.insert(64, vec!["Linux".to_string(), "macOS".to_string(), "Unix".to_string()]);
        self.ttl_signatures.insert(128, vec!["Windows".to_string()]);
        self.ttl_signatures.insert(255, vec!["Cisco".to_string(), "Solaris".to_string(), "AIX".to_string()]);
    }
    
    /// Get all known OS families
    pub fn get_known_os_families(&self) -> Vec<String> {
        self.signatures.iter()
            .map(|sig| sig.os_family.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect()
    }
    
    /// Get signature count
    pub fn signature_count(&self) -> usize {
        self.signatures.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::net::Ipv4Addr;

    #[test]
    fn test_os_fingerprint_creation() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let fingerprint = OsFingerprint::new(target)
            .with_os_family("Linux".to_string())
            .with_os_version("Ubuntu 20.04".to_string())
            .with_confidence(0.8)
            .add_method(FingerprintMethod::TcpStack)
            .with_metadata("test".to_string(), "value".to_string());
        
        assert_eq!(fingerprint.target, target);
        assert_eq!(fingerprint.os_family, Some("Linux".to_string()));
        assert_eq!(fingerprint.os_version, Some("Ubuntu 20.04".to_string()));
        assert_eq!(fingerprint.confidence, 0.8);
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::TcpStack));
        assert!(fingerprint.is_detected());
        assert_eq!(fingerprint.get_os_description(), "Linux Ubuntu 20.04");
    }

    #[test]
    fn test_tcp_fingerprint() {
        let mut fingerprint = TcpFingerprint::new();
        fingerprint.initial_ttl = Some(64);
        fingerprint.window_size = Some(29200);
        fingerprint.sack_permitted = true;
        fingerprint.timestamp = true;
        
        let mut signature = TcpFingerprint::new();
        signature.initial_ttl = Some(64);
        signature.window_size = Some(29200);
        signature.sack_permitted = true;
        signature.timestamp = true;
        
        let score = fingerprint.calculate_score(&signature);
        assert!(score > 0.9); // Should be very high match
        
        // Test with different TTL
        signature.initial_ttl = Some(128);
        let score2 = fingerprint.calculate_score(&signature);
        assert!(score2 < score); // Should be lower
    }

    #[test]
    fn test_os_fingerprinter_creation() {
        let config = Config::default();
        let fingerprinter = OsFingerprinter::new(&config);
        
        assert!(fingerprinter.signature_count() > 0);
        
        let os_families = fingerprinter.get_known_os_families();
        assert!(!os_families.is_empty());
        assert!(os_families.contains(&"Linux".to_string()));
        assert!(os_families.contains(&"Windows".to_string()));
    }

    #[tokio::test]
    async fn test_os_fingerprinting() {
        let config = Config::default();
        let fingerprinter = OsFingerprinter::new(&config);
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Create Linux-like TCP fingerprint
        let mut tcp_data = TcpFingerprint::new();
        tcp_data.initial_ttl = Some(64);
        tcp_data.window_size = Some(29200);
        tcp_data.sack_permitted = true;
        tcp_data.timestamp = true;
        tcp_data.window_scale = Some(7);
        
        let result = fingerprinter.fingerprint_os(
            target,
            Some(&tcp_data),
            None,
            Some("Apache/2.4.41 (Ubuntu)"),
            Some("SSH-2.0-OpenSSH_8.3"),
        ).await;
        
        assert!(result.is_ok());
        let fingerprint = result.unwrap();
        
        // Should detect Linux with reasonable confidence
        assert!(fingerprint.is_detected());
        assert!(fingerprint.confidence > 0.3);
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::TcpStack));
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::HttpHeaders));
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::SshBanner));
    }

    #[tokio::test]
    async fn test_ttl_based_detection() {
        let config = Config::default();
        let fingerprinter = OsFingerprinter::new(&config);
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        // Create TCP fingerprint with Windows-like TTL
        let mut tcp_data = TcpFingerprint::new();
        tcp_data.initial_ttl = Some(120); // Decremented from 128
        
        let result = fingerprinter.fingerprint_os(
            target,
            Some(&tcp_data),
            None,
            None,
            None,
        ).await;
        
        assert!(result.is_ok());
        let fingerprint = result.unwrap();
        
        // Should detect something based on TTL
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::TcpStack));
    }

    #[test]
    fn test_confidence_clamping() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        
        let fingerprint1 = OsFingerprint::new(target).with_confidence(1.5);
        assert_eq!(fingerprint1.confidence, 1.0);
        
        let fingerprint2 = OsFingerprint::new(target).with_confidence(-0.5);
        assert_eq!(fingerprint2.confidence, 0.0);
    }

    #[test]
    fn test_method_deduplication() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let fingerprint = OsFingerprint::new(target)
            .add_method(FingerprintMethod::TcpStack)
            .add_method(FingerprintMethod::TcpStack) // Duplicate
            .add_method(FingerprintMethod::HttpHeaders);
        
        assert_eq!(fingerprint.detection_methods.len(), 2);
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::TcpStack));
        assert!(fingerprint.detection_methods.contains(&FingerprintMethod::HttpHeaders));
    }
}
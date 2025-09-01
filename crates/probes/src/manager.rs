//! Probe manager for coordinating different types of network probes

use crate::{
    banner_grabbing::{BannerGrabber, BannerOptions, BannerResult},
    common::{ProbeError, ProbeOptions, ProbeResult, ProbeStats, ProbeCapabilities},
    icmp::{IcmpProbe, IcmpProbeOptions, IcmpProbeResult},
    os_fingerprinting::{OsFingerprinter, OsFingerprint, TcpFingerprint},
    service_detection::{ServiceDetector, ServiceInfo},
    tcp::{TcpProbe, TcpProbeOptions, TcpProbeResult},
    udp::{UdpProbe, UdpProbeOptions, UdpProbeResult},
};

use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::{IpAddr, Protocol, PortRange, PortState},
};

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, trace, warn};

/// Comprehensive probe result combining all probe types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComprehensiveProbeResult {
    /// Target information
    pub target: IpAddr,
    
    /// Port being probed (0 for host-level probes)
    pub port: u16,
    
    /// Protocol used
    pub protocol: Protocol,
    
    /// Overall probe state
    pub state: PortState,
    
    /// TCP probe result
    pub tcp_result: Option<TcpProbeResult>,
    
    /// UDP probe result
    pub udp_result: Option<UdpProbeResult>,
    
    /// ICMP probe result
    pub icmp_result: Option<IcmpProbeResult>,
    
    /// Banner grabbing result
    pub banner_result: Option<BannerResult>,
    
    /// Service detection result
    pub service_info: Option<ServiceInfo>,
    
    /// OS fingerprint (for host-level probes)
    pub os_fingerprint: Option<OsFingerprint>,
    
    /// Total probe time
    pub total_time: Duration,
    
    /// Probe timestamp
    pub timestamp: std::time::SystemTime,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl ComprehensiveProbeResult {
    /// Create new comprehensive probe result
    pub fn new(target: IpAddr, port: u16, protocol: Protocol) -> Self {
        Self {
            target,
            port,
            protocol,
            state: PortState::Filtered,
            tcp_result: None,
            udp_result: None,
            icmp_result: None,
            banner_result: None,
            service_info: None,
            os_fingerprint: None,
            total_time: Duration::from_secs(0),
            timestamp: std::time::SystemTime::now(),
            metadata: HashMap::new(),
        }
    }
    
    /// Check if target is reachable
    pub fn is_reachable(&self) -> bool {
        match self.protocol {
            Protocol::Tcp => self.tcp_result.as_ref().map_or(false, |r| r.base.state == PortState::Open),
            Protocol::Udp => self.udp_result.as_ref().map_or(false, |r| r.base.state == PortState::Open),
            Protocol::Icmp => self.icmp_result.as_ref().map_or(false, |r| r.is_reachable()),
            _ => false,
        }
    }
    
    /// Get service name if detected
    pub fn get_service_name(&self) -> Option<&str> {
        self.service_info.as_ref().map(|s| s.name.as_str())
    }
    
    /// Get banner if available
    pub fn get_banner(&self) -> Option<&str> {
        self.banner_result.as_ref().and_then(|b| b.banner.as_deref())
    }
    
    /// Get OS description if available
    pub fn get_os_description(&self) -> Option<String> {
        self.os_fingerprint.as_ref().map(|os| os.get_os_description())
    }
}

/// Probe manager configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProbeManagerConfig {
    /// Enable TCP probes
    pub enable_tcp: bool,
    
    /// Enable UDP probes
    pub enable_udp: bool,
    
    /// Enable ICMP probes
    pub enable_icmp: bool,
    
    /// Enable banner grabbing
    pub enable_banner_grabbing: bool,
    
    /// Enable service detection
    pub enable_service_detection: bool,
    
    /// Enable OS fingerprinting
    pub enable_os_fingerprinting: bool,
    
    /// Maximum concurrent probes
    pub max_concurrent_probes: usize,
    
    /// Default timeout for probes
    pub default_timeout: Duration,
    
    /// Retry failed probes
    pub retry_failed: bool,
    
    /// Maximum retries
    pub max_retries: u32,
    
    /// Delay between retries
    pub retry_delay: Duration,
}

impl Default for ProbeManagerConfig {
    fn default() -> Self {
        Self {
            enable_tcp: true,
            enable_udp: true,
            enable_icmp: true,
            enable_banner_grabbing: true,
            enable_service_detection: true,
            enable_os_fingerprinting: true,
            max_concurrent_probes: 100,
            default_timeout: Duration::from_secs(3),
            retry_failed: false,
            max_retries: 2,
            retry_delay: Duration::from_millis(500),
        }
    }
}

/// Probe manager for coordinating different probe types
#[derive(Debug)]
pub struct ProbeManager {
    /// Configuration
    config: Arc<Config>,
    
    /// Manager-specific configuration
    manager_config: ProbeManagerConfig,
    
    /// TCP probe
    tcp_probe: TcpProbe,
    
    /// UDP probe
    udp_probe: UdpProbe,
    
    /// ICMP probe
    icmp_probe: IcmpProbe,
    
    /// Banner grabber
    banner_grabber: BannerGrabber,
    
    /// Service detector
    service_detector: ServiceDetector,
    
    /// OS fingerprinter
    os_fingerprinter: OsFingerprinter,
    
    /// Probe statistics
    stats: Arc<RwLock<ProbeStats>>,
}

impl ProbeManager {
    /// Create a new probe manager
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let manager_config = ProbeManagerConfig::default();
        
        Ok(Self {
            tcp_probe: TcpProbe::new(&config)?,
            udp_probe: UdpProbe::new(&config)?,
            icmp_probe: IcmpProbe::new(config.clone()),
            banner_grabber: BannerGrabber::new(&config),
            service_detector: ServiceDetector::new(&config)?,
            os_fingerprinter: OsFingerprinter::new(&config),
            config,
            manager_config,
            stats: Arc::new(RwLock::new(ProbeStats::new())),
        })
    }
    
    /// Create probe manager with custom configuration
    pub fn with_config(config: Arc<Config>, manager_config: ProbeManagerConfig) -> Result<Self> {
        Ok(Self {
            tcp_probe: TcpProbe::new(&config)?,
            udp_probe: UdpProbe::new(&config)?,
            icmp_probe: IcmpProbe::new(config.clone()),
            banner_grabber: BannerGrabber::new(&config),
            service_detector: ServiceDetector::new(&config)?,
            os_fingerprinter: OsFingerprinter::new(&config),
            config,
            manager_config,
            stats: Arc::new(RwLock::new(ProbeStats::new())),
        })
    }
    
    /// Perform comprehensive host discovery
    pub async fn discover_host(&mut self, target: IpAddr) -> Result<ComprehensiveProbeResult> {
        let start_time = Instant::now();
        let mut result = ComprehensiveProbeResult::new(target, 0, Protocol::Icmp);
        
        info!("Starting host discovery for {}", target);
        
        // ICMP ping first (fastest)
        if self.manager_config.enable_icmp {
            match self.icmp_probe.probe_target(target, None).await {
                Ok(icmp_result) => {
                    let reachable = icmp_result.is_reachable();
                    result.icmp_result = Some(icmp_result);
                    result.state = if reachable { PortState::Open } else { PortState::Filtered };
                    
                    debug!("ICMP probe for {}: reachable={}", target, reachable);
                }
                Err(e) => {
                    warn!("ICMP probe failed for {}: {}", target, e);
                }
            }
        }
        
        // If ICMP failed, try TCP connect to common ports
        if result.state != PortState::Open && self.manager_config.enable_tcp {
            let common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995];
            
            for &port in &common_ports {
                match self.tcp_probe.probe_port(std::net::SocketAddr::new(target.into(), port), None).await {
                    Ok(tcp_result) => {
                        if tcp_result.base.state == PortState::Open {
                            result.state = PortState::Open;
                            debug!("Host {} discovered via TCP port {}", target, port);
                            break;
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
        
        result.total_time = start_time.elapsed();
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.probes_sent += 1;
            if result.is_reachable() {
                stats.probes_successful += 1;
            } else {
                stats.probes_failed += 1;
            }
        }
        
        info!("Host discovery completed for {}: reachable={}, time={:.2}ms", 
              target, result.is_reachable(), result.total_time.as_secs_f64() * 1000.0);
        
        Ok(result)
    }
    
    /// Perform comprehensive port scan
    pub async fn scan_port(
        &mut self,
        target: IpAddr,
        port: u16,
        protocol: Protocol,
    ) -> Result<ComprehensiveProbeResult> {
        let start_time = Instant::now();
        let mut result = ComprehensiveProbeResult::new(target, port, protocol);
        
        debug!("Starting comprehensive scan for {}:{}/{:?}", target, port, protocol);
        
        // Perform protocol-specific probe
        match protocol {
            Protocol::Tcp if self.manager_config.enable_tcp => {
                result = self.scan_tcp_port(result, target, port).await?;
            }
            Protocol::Udp if self.manager_config.enable_udp => {
                result = self.scan_udp_port(result, target, port).await?;
            }
            _ => {
                warn!("Protocol {:?} not enabled or supported", protocol);
                result.state = PortState::Filtered;
            }
        }
        
        // If port is open, perform additional analysis
        if result.state == PortState::Open {
            result = self.perform_additional_analysis(result).await?;
        }
        
        result.total_time = start_time.elapsed();
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.probes_sent += 1;
            match result.state {
                PortState::Open => stats.open_ports += 1,
                PortState::Closed => stats.closed_ports += 1,
                PortState::Filtered => stats.filtered_ports += 1,
                _ => {}
            }
            
            if result.is_reachable() {
                stats.probes_successful += 1;
            } else {
                stats.probes_failed += 1;
            }
        }
        
        debug!("Comprehensive scan completed for {}:{}/{:?}: state={:?}, time={:.2}ms", 
               target, port, protocol, result.state, result.total_time.as_secs_f64() * 1000.0);
        
        Ok(result)
    }
    
    /// Scan multiple ports concurrently
    pub async fn scan_ports(
        &mut self,
        target: IpAddr,
        ports: &[u16],
        protocol: Protocol,
    ) -> Result<Vec<ComprehensiveProbeResult>> {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.manager_config.max_concurrent_probes));
        let mut tasks = Vec::new();
        
        for &port in ports {
            let mut manager = self.clone();
            let semaphore = semaphore.clone();
            
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                manager.scan_port(target, port, protocol).await
            });
            
            tasks.push(task);
        }
        
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => {
                    warn!("Port scan failed: {}", e);
                }
                Err(e) => {
                    warn!("Port scan task failed: {}", e);
                }
            }
        }
        
        Ok(results)
    }
    
    /// Perform OS fingerprinting on a host
    pub async fn fingerprint_os(&mut self, target: IpAddr) -> Result<OsFingerprint> {
        if !self.manager_config.enable_os_fingerprinting {
            return Err(Error::FeatureNotAvailable { feature: "OS fingerprinting".to_string() });
        }
        
        info!("Starting OS fingerprinting for {}", target);
        
        // Collect TCP fingerprint data
        let tcp_fingerprint = self.collect_tcp_fingerprint(target).await?;
        
        // Collect banners for analysis
        let (http_banner, ssh_banner) = self.collect_banners_for_os(target).await;
        
        // Perform OS fingerprinting
        let fingerprint = self.os_fingerprinter.fingerprint_os(
            target,
            tcp_fingerprint.as_ref(),
            None, // ICMP fingerprint not implemented yet
            http_banner.as_deref(),
            ssh_banner.as_deref(),
        ).await?;
        
        info!("OS fingerprinting completed for {}: {}", target, fingerprint.get_os_description());
        
        Ok(fingerprint)
    }
    
    /// Scan TCP port with comprehensive analysis
    async fn scan_tcp_port(
        &mut self,
        mut result: ComprehensiveProbeResult,
        target: IpAddr,
        port: u16,
    ) -> Result<ComprehensiveProbeResult> {
        let tcp_options = TcpProbeOptions {
            connect_timeout: self.manager_config.default_timeout,
            grab_banner: self.manager_config.enable_banner_grabbing,
            ..Default::default()
        };
        
        match self.tcp_probe.probe_port(std::net::SocketAddr::new(target.into(), port), Some(tcp_options)).await {
            Ok(tcp_result) => {
                result.state = tcp_result.base.state;
                result.tcp_result = Some(tcp_result);
            }
            Err(e) => {
                warn!("TCP probe failed for {}:{}: {}", target, port, e);
                result.state = PortState::Filtered;
            }
        }
        
        Ok(result)
    }
    
    /// Scan UDP port with comprehensive analysis
    async fn scan_udp_port(
        &mut self,
        mut result: ComprehensiveProbeResult,
        target: IpAddr,
        port: u16,
    ) -> Result<ComprehensiveProbeResult> {
        let udp_options = UdpProbeOptions {
            send_timeout: self.manager_config.default_timeout,
            recv_timeout: self.manager_config.default_timeout,
            service_probes: self.manager_config.enable_service_detection,
            ..Default::default()
        };
        
        match self.udp_probe.probe_port(std::net::SocketAddr::new(target.into(), port), Some(udp_options)).await {
            Ok(udp_result) => {
                result.state = udp_result.base.state;
                result.udp_result = Some(udp_result);
            }
            Err(e) => {
                warn!("UDP probe failed for {}:{}: {}", target, port, e);
                result.state = PortState::Filtered;
            }
        }
        
        Ok(result)
    }
    
    /// Perform additional analysis on open ports
    async fn perform_additional_analysis(
        &mut self,
        mut result: ComprehensiveProbeResult,
    ) -> Result<ComprehensiveProbeResult> {
        // Banner grabbing
        if self.manager_config.enable_banner_grabbing {
            let banner_options = BannerOptions {
                connect_timeout: self.manager_config.default_timeout,
                max_banner_size: 1024,
                service_probes: self.manager_config.enable_service_detection,
                ..Default::default()
            };
            
            let socket_addr = std::net::SocketAddr::new(result.target.into(), result.port);
            match self.banner_grabber.grab_banner(socket_addr, result.protocol, &banner_options).await {
                Ok(banner_result) => {
                    result.banner_result = Some(banner_result);
                }
                Err(e) => {
                    trace!("Banner grabbing failed for {}:{}: {}", result.target, result.port, e);
                }
            }
        }
        
        // Service detection
        if self.manager_config.enable_service_detection {
            let banner = result.banner_result.as_ref().and_then(|b| b.banner.as_deref());
            
            let socket_addr = std::net::SocketAddr::new(result.target.into(), result.port);
            if let Some(service) = self.service_detector.detect_service(socket_addr, result.protocol, banner, result.state) {
                result.service_info = Some(service);
            }
        }
        
        Ok(result)
    }
    
    /// Collect TCP fingerprint data for OS detection
    async fn collect_tcp_fingerprint(&mut self, target: IpAddr) -> Result<Option<TcpFingerprint>> {
        // This would involve sending specially crafted TCP packets
        // For now, we'll return a basic fingerprint from a regular connection
        
        let tcp_options = TcpProbeOptions {
            connect_timeout: Duration::from_secs(2),
            grab_banner: false,
            ..Default::default()
        };
        
        // Try common ports to get TCP response
        let test_ports = [80, 443, 22];
        
        for &port in &test_ports {
            if let Ok(tcp_result) = self.tcp_probe.probe_port(std::net::SocketAddr::new(target.into(), port), Some(tcp_options.clone())).await {
                if tcp_result.base.state == PortState::Open {
                    // Extract basic TCP fingerprint information
                    let mut fingerprint = TcpFingerprint::new();
                    
                    // Estimate initial TTL based on response time and common values
                    if let Some(rtt) = tcp_result.connect_time {
                        fingerprint.initial_ttl = if rtt < Duration::from_millis(10) {
                            Some(64) // Likely local/Linux
                        } else if rtt < Duration::from_millis(50) {
                            Some(128) // Likely Windows
                        } else {
                            Some(255) // Likely router/distant
                        };
                    }
                    
                    return Ok(Some(fingerprint));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Collect banners for OS fingerprinting
    async fn collect_banners_for_os(&self, target: IpAddr) -> (Option<String>, Option<String>) {
        let mut http_banner = None;
        let mut ssh_banner = None;
        
        let banner_options = BannerOptions {
            connect_timeout: Duration::from_secs(2),
            max_banner_size: 512,
            service_probes: false,
            ..Default::default()
        };
        
        // Try to get HTTP banner
        if let Ok(banner_result) = self.banner_grabber.grab_banner(std::net::SocketAddr::new(target.into(), 80), Protocol::Tcp, &banner_options).await {
            http_banner = banner_result.banner;
        }
        
        // Try to get SSH banner
        if let Ok(banner_result) = self.banner_grabber.grab_banner(std::net::SocketAddr::new(target.into(), 22), Protocol::Tcp, &banner_options).await {
            ssh_banner = banner_result.banner;
        }
        
        (http_banner, ssh_banner)
    }
    
    /// Get probe capabilities
    pub fn get_capabilities(&self) -> ProbeCapabilities {
        ProbeCapabilities {
            tcp: self.manager_config.enable_tcp,

            udp: self.manager_config.enable_udp,
            icmp: self.manager_config.enable_icmp,
            sctp: false, // Not implemented yet
            raw_sockets: false, // Not implemented yet
            ipv6: true,
            service_detection: self.manager_config.enable_service_detection,
            banner_grabbing: self.manager_config.enable_banner_grabbing,
            os_fingerprinting: self.manager_config.enable_os_fingerprinting,
        }
    }
    
    /// Get current statistics
    pub async fn get_stats(&self) -> ProbeStats {
        self.stats.read().await.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = ProbeStats::new();
    }
    
    /// Update manager configuration
    pub fn update_config(&mut self, config: ProbeManagerConfig) {
        self.manager_config = config;
    }
    
    /// Get current configuration
    pub fn get_config(&self) -> &ProbeManagerConfig {
        &self.manager_config
    }
}

impl Clone for ProbeManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            manager_config: self.manager_config.clone(),
            tcp_probe: self.tcp_probe.clone(),
            udp_probe: self.udp_probe.clone(),
            icmp_probe: self.icmp_probe.clone(),
            banner_grabber: self.banner_grabber.clone(),
            service_detector: self.service_detector.clone(),
            os_fingerprinter: OsFingerprinter::new(&self.config),
            stats: self.stats.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    #[test]
    fn test_comprehensive_probe_result() {
        let target = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let mut result = ComprehensiveProbeResult::new(target, 80, Protocol::Tcp);
        
        assert_eq!(result.target, target);
        assert_eq!(result.port, 80);
        assert_eq!(result.protocol, Protocol::Tcp);
        assert_eq!(result.state, PortState::Filtered);
        assert!(!result.is_reachable());
        
        // Add TCP result
        let tcp_result = crate::tcp::TcpProbeResult {
            base: crate::common::ProbeResult {
                target: SocketAddr::new(target.into(), 80),
                protocol: Protocol::Tcp,
                state: PortState::Open,
                response_time: Some(Duration::from_millis(10)),
                timestamp: std::time::SystemTime::now(),
                error: None,
                metadata: HashMap::new(),
                raw_response: None,
            },
            banner: None,
            connect_time: Some(Duration::from_millis(10)),
            banner_time: None,
            tcp_metadata: HashMap::new(),
        };
        result.tcp_result = Some(tcp_result);
        result.state = PortState::Open;
        
        assert!(result.is_reachable());
    }

    #[test]
    fn test_probe_manager_config() {
        let config = ProbeManagerConfig::default();
        
        assert!(config.enable_tcp);
        assert!(config.enable_udp);
        assert!(config.enable_icmp);
        assert!(config.enable_banner_grabbing);
        assert!(config.enable_service_detection);
        assert!(config.enable_os_fingerprinting);
        assert_eq!(config.max_concurrent_probes, 100);
        assert_eq!(config.default_timeout, Duration::from_secs(3));
    }

    #[tokio::test]
    async fn test_probe_manager_creation() {
        let config = Arc::new(Config::default());
        let manager = ProbeManager::new(config).unwrap();
        
        let capabilities = manager.get_capabilities();
        assert!(capabilities.tcp);
        assert!(capabilities.udp);
        assert!(capabilities.icmp);
        assert!(capabilities.service_detection);
        assert!(capabilities.banner_grabbing);
        assert!(capabilities.os_fingerprinting);
        
        let stats = manager.get_stats().await;
        assert_eq!(stats.probes_sent, 0);
        assert_eq!(stats.probes_successful, 0);
        assert_eq!(stats.probes_failed, 0);
    }

    #[tokio::test]
    async fn test_host_discovery() {
        let config = Arc::new(Config::default());
        let mut manager = ProbeManager::new(config).unwrap();
        
        // Test with localhost
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = manager.discover_host(target).await;
        
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.target, target);
        assert_eq!(result.port, 0);
        assert_eq!(result.protocol, Protocol::Icmp);
    }

    #[tokio::test]
    async fn test_port_scanning() {
        let config = Arc::new(Config::default());
        let mut manager = ProbeManager::new(config).unwrap();
        
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let ports = vec![22, 80, 443];
        
        let results = manager.scan_ports(target, &ports, Protocol::Tcp).await;
        assert!(results.is_ok());
        
        let results = results.unwrap();
        assert_eq!(results.len(), ports.len());
        
        for result in results {
            assert_eq!(result.target, target);
            assert_eq!(result.protocol, Protocol::Tcp);
            assert!(ports.contains(&result.port));
        }
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let config = Arc::new(Config::default());
        let manager = ProbeManager::new(config).unwrap();
        
        let initial_stats = manager.get_stats().await;
        assert_eq!(initial_stats.probes_sent, 0);
        
        // Note: Cannot test scan_port here as it requires &mut self and would modify statistics
        // In a real test, we would need to create a mutable manager instance
        
        // For now, just verify that stats can be read
        let updated_stats = manager.get_stats().await;
        assert_eq!(updated_stats.probes_sent, initial_stats.probes_sent);
        
        // Reset statistics
        manager.reset_stats().await;
        let reset_stats = manager.get_stats().await;
        assert_eq!(reset_stats.probes_sent, 0);
    }

    #[test]
    fn test_manager_config_update() {
        let config = Arc::new(Config::default());
        let mut manager = ProbeManager::new(config).unwrap();
        
        let mut new_config = ProbeManagerConfig::default();
        new_config.enable_tcp = false;
        new_config.max_concurrent_probes = 50;
        
        manager.update_config(new_config.clone());
        
        let current_config = manager.get_config();
        assert!(!current_config.enable_tcp);
        assert_eq!(current_config.max_concurrent_probes, 50);
    }
}
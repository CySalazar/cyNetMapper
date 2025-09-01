//! Core scanning engine for cyNetMapper

use crate::config::{Config, ScanProfile, TimingTemplate};
use crate::error::{Error, Result};
use crate::network::NetworkScanner;
use crate::results::*;
use crate::security::SecurityContext;
use crate::timing::TimingController;
use crate::types::{HostState, IpAddr, PortRange, PortState, Protocol, Target};

use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Main scanning engine
#[derive(Debug)]
pub struct Scanner {
    /// Scanner configuration
    config: Arc<Config>,
    /// Network scanner instance
    network_scanner: NetworkScanner,
    /// Security context
    security_context: SecurityContext,
    /// Timing engine
    timing_engine: TimingController,
    /// Current scan results
    results: Arc<RwLock<ScanResults>>,
    /// Scan state
    state: Arc<RwLock<ScanState>>,
}

/// Scan state tracking
#[derive(Debug, Clone)]
pub struct ScanState {
    /// Scan ID
    pub scan_id: Uuid,
    /// Current phase
    pub phase: ScanPhase,
    /// Start time
    pub start_time: Instant,
    /// Targets to scan
    pub targets: Vec<Target>,
    /// Ports to scan
    pub ports: PortRange,
    /// Protocols to use
    pub protocols: Vec<Protocol>,
    /// Progress tracking
    pub progress: ScanProgress,
    /// Whether scan is cancelled
    pub cancelled: bool,
    /// Whether scan is paused
    pub paused: bool,
}

/// Scan phases
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanPhase {
    /// Initializing scan
    Initializing,
    /// Resolving targets
    TargetResolution,
    /// Host discovery
    HostDiscovery,
    /// Port scanning
    PortScanning,
    /// Service detection
    ServiceDetection,
    /// OS fingerprinting
    OsFingerprinting,
    /// Finalizing results
    Finalizing,
    /// Scan completed
    Completed,
    /// Scan failed
    Failed,
    /// Scan cancelled
    Cancelled,
}

/// Progress tracking
#[derive(Debug, Clone)]
pub struct ScanProgress {
    /// Total targets
    pub total_targets: usize,
    /// Completed targets
    pub completed_targets: usize,
    /// Total ports
    pub total_ports: usize,
    /// Completed ports
    pub completed_ports: usize,
    /// Current target
    pub current_target: Option<String>,
    /// Estimated time remaining
    pub eta: Option<Duration>,
    /// Scan rate (targets/ports per second)
    pub rate: f64,
}

/// Scan options for individual operations
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Maximum concurrent operations
    pub max_concurrency: usize,
    /// Connection timeout
    pub timeout: Duration,
    /// Number of retries
    pub retries: u32,
    /// Delay between operations
    pub delay: Duration,
    /// Whether to perform host discovery
    pub host_discovery: bool,
    /// Whether to perform service detection
    pub service_detection: bool,
    /// Whether to perform OS fingerprinting
    pub os_fingerprinting: bool,
    /// Whether to skip ping
    pub skip_ping: bool,
    /// Protocols to scan
    pub protocols: Vec<Protocol>,
}

/// Progress callback type
pub type ProgressCallback = Box<dyn Fn(&ScanProgress) + Send + Sync>;

/// Event callback type
pub type EventCallback = Box<dyn Fn(&ScanEvent) + Send + Sync>;

/// Scan events
#[derive(Debug, Clone)]
pub enum ScanEvent {
    /// Scan started
    ScanStarted { scan_id: Uuid },
    /// Phase changed
    PhaseChanged { phase: ScanPhase },
    /// Host discovered
    HostDiscovered { host: HostResult },
    /// Port found
    PortFound { port: PortResult },
    /// Service detected
    ServiceDetected { service: ServiceResult },
    /// Error occurred
    ErrorOccurred { error: ScanError },
    /// Progress updated
    ProgressUpdated { progress: ScanProgress },
    /// Scan completed
    ScanCompleted { results: ScanResults },
    /// Scan cancelled
    ScanCancelled { scan_id: Uuid },
}

impl Scanner {
    /// Create a new scanner with configuration
    pub fn new(config: Config) -> Result<Self> {
        let config = Arc::new(config);
        let network_scanner = NetworkScanner::new(Duration::from_secs(5));
        let security_context = SecurityContext::new(&config)?;
        let timing_engine = TimingController::new(&config)?;
        
        let metadata = ScanMetadata {
            start_time: SystemTime::now(),
            scanner_version: env!("CARGO_PKG_VERSION").to_string(),
            scan_profile: format!("{:?}", config.scan.profile),
            targets: Vec::new(),
            ports: "default".to_string(),
            protocols: config.scan.protocols.clone(),
            options: HashMap::new(),
            ..Default::default()
        };
        
        let results = Arc::new(RwLock::new(ScanResults::new(metadata)));
        let state = Arc::new(RwLock::new(ScanState::new()));
        
        Ok(Self {
            config,
            network_scanner,
            security_context,
            timing_engine,
            results,
            state,
        })
    }

    /// Start a scan with the given targets and options
    pub async fn scan(
        &mut self,
        targets: Vec<Target>,
        ports: PortRange,
        options: ScanOptions,
    ) -> Result<ScanResults> {
        let scan_id = {
            let state = self.state.read().await;
            state.scan_id
        };

        // Initialize scan state
        {
            let mut state = self.state.write().await;
            state.targets = targets.clone();
            state.ports = ports.clone();
            state.protocols = self.config.scan.protocols.clone();
            state.phase = ScanPhase::Initializing;
            state.progress.total_targets = targets.len();
        }

        // Security checks
        self.security_context.validate_targets(&targets)?;
        self.security_context.check_permissions(&options)?;

        // Update metadata
        {
            let mut results = self.results.write().await;
            results.metadata.targets = targets.iter().map(|t| t.to_string()).collect();
            results.metadata.ports = ports.to_string();
        }

        info!(
            scan_id = %scan_id,
            target_count = targets.len(),
            port_range = %ports,
            protocols = ?options.protocols,
            max_concurrency = options.max_concurrency,
            timeout_ms = options.timeout.as_millis(),
            "Starting network scan"
        );

        // Execute scan phases
        self.execute_scan_phases(targets, ports, options).await?;

        // Return final results
        let results = self.results.read().await.clone();
        info!(
            scan_id = %scan_id,
            hosts_discovered = results.hosts.len(),
            ports_found = results.ports.len(),
            services_detected = results.services.len(),
            "Scan completed successfully"
        );
        
        Ok(results)
    }

    /// Execute all scan phases
    async fn execute_scan_phases(
        &mut self,
        targets: Vec<Target>,
        ports: PortRange,
        options: ScanOptions,
    ) -> Result<()> {
        // Phase 1: Target Resolution
        self.set_phase(ScanPhase::TargetResolution).await;
        let resolved_targets = self.resolve_targets(targets).await?;

        // Phase 2: Host Discovery (if enabled)
        let live_hosts = if options.host_discovery {
            self.set_phase(ScanPhase::HostDiscovery).await;
            self.discover_hosts(resolved_targets, &options).await?
        } else {
            // Assume all targets are live
            resolved_targets.into_iter().map(|ip| {
                HostResult::new(ip, HostState::Up, DiscoveryMethod::TcpConnect)
            }).collect()
        };

        // Phase 3: Port Scanning
        self.set_phase(ScanPhase::PortScanning).await;
        self.scan_ports(&live_hosts, &ports, &options).await?;

        // Phase 4: Service Detection (if enabled)
        if options.service_detection {
            self.set_phase(ScanPhase::ServiceDetection).await;
            self.detect_services(&options).await?;
        }

        // Phase 5: OS Fingerprinting (if enabled)
        if options.os_fingerprinting {
            self.set_phase(ScanPhase::OsFingerprinting).await;
            self.fingerprint_os(&live_hosts, &options).await?;
        }

        // Phase 6: Finalize
        self.set_phase(ScanPhase::Finalizing).await;
        self.finalize_scan().await?;

        self.set_phase(ScanPhase::Completed).await;
        Ok(())
    }

    /// Resolve targets to IP addresses
    async fn resolve_targets(&self, targets: Vec<Target>) -> Result<Vec<IpAddr>> {
        let mut resolved = Vec::new();
        
        for target in targets {
            match target {
                Target::Ip(ip) => resolved.push(ip),
                Target::Cidr { network, prefix } => {
                    // Expand CIDR to individual IPs
                    let cidr_str = format!("{}/{}", network, prefix);
                    let ips = self.expand_cidr(&cidr_str)?;
                    resolved.extend(ips);
                },
                Target::Hostname(hostname) => {
                    // Resolve hostname to IP
                    let mut scanner_clone = self.network_scanner.clone();
                    match scanner_clone.resolve_hostname(&hostname).await {
                        Ok(dns_result) => {
                            for address in &dns_result.addresses {
                                resolved.push(*address);
                            }
                        },
                        Err(e) => {
                            warn!(
                                hostname = %hostname,
                                error = %e,
                                "Failed to resolve hostname"
                            );
                            self.add_error(ScanError::new(
                                ErrorSeverity::Warning,
                                format!("Failed to resolve hostname: {}", e)
                            ).with_target(hostname)).await;
                        }
                    }
                },
                Target::Range { start, end } => {
                    // Expand IP range
                    let ips = self.expand_ip_range(start, end)?;
                    resolved.extend(ips);
                },
            }
        }
        
        info!(
            resolved_count = resolved.len(),
            "Target resolution completed"
        );
        Ok(resolved)
    }

    /// Discover live hosts
    async fn discover_hosts(
        &self,
        targets: Vec<IpAddr>,
        options: &ScanOptions,
    ) -> Result<Vec<HostResult>> {
        let target_count = targets.len();
        let mut live_hosts = Vec::new();
        let (tx, mut rx) = mpsc::channel(1000);
        
        // Spawn discovery tasks
        let semaphore = Arc::new(tokio::sync::Semaphore::new(options.max_concurrency));
        let mut tasks = Vec::new();
        
        for target in targets {
            let tx = tx.clone();
            let semaphore = semaphore.clone();
            let scanner = self.network_scanner.clone();
            let timeout_duration = options.timeout;
            
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                
                let start_time = Instant::now();
                let result = timeout(timeout_duration, scanner.is_host_reachable(target)).await;
                let response_time = start_time.elapsed();
                
                let host_result = match result {
                    Ok(Ok(true)) => HostResult::new(
                        target,
                        HostState::Up,
                        DiscoveryMethod::TcpConnect
                    ).with_response_time(response_time),
                    Ok(Ok(false)) => HostResult::new(
                        target,
                        HostState::Down,
                        DiscoveryMethod::TcpConnect
                    ),
                    Ok(Err(_)) | Err(_) => HostResult::new(
                        target,
                        HostState::Unknown,
                        DiscoveryMethod::TcpConnect
                    ),
                };
                
                let _ = tx.send(host_result).await;
            });
            
            tasks.push(task);
        }
        
        drop(tx); // Close the sender
        
        // Collect results
        while let Some(host_result) = rx.recv().await {
            if host_result.state == HostState::Up {
                live_hosts.push(host_result.clone());
            }
            
            // Add to results
            {
                let mut results = self.results.write().await;
                results.add_host(host_result);
            }
            
            // Update progress
            self.update_progress().await;
        }
        
        // Wait for all tasks to complete
        for task in tasks {
            let _ = task.await;
        }
        
        info!(
            live_hosts = live_hosts.len(),
            total_targets = target_count,
            discovery_rate = format!("{:.1}%", (live_hosts.len() as f64 / target_count as f64) * 100.0),
            "Host discovery completed"
        );
        Ok(live_hosts)
    }

    /// Scan ports on live hosts
    async fn scan_ports(
        &self,
        hosts: &[HostResult],
        ports: &PortRange,
        options: &ScanOptions,
    ) -> Result<()> {
        let port_list = ports.expand();
        let total_scans = hosts.len() * port_list.len() * options.protocols.len();
        
        info!(
            port_count = port_list.len(),
            host_count = hosts.len(),
            total_scans = total_scans,
            protocols = ?options.protocols,
            max_concurrency = options.max_concurrency,
            "Starting port scanning phase"
        );
        
        let (tx, mut rx) = mpsc::channel(1000);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(options.max_concurrency));
        let mut tasks = Vec::new();
        
        for host in hosts {
            for &port in &port_list {
                for &protocol in &options.protocols {
                    let tx = tx.clone();
                    let semaphore = semaphore.clone();
                    let scanner_clone = self.network_scanner.clone();
                    let target_addr = match host.address {
                        IpAddr::V4(ip) => SocketAddr::V4(std::net::SocketAddrV4::new(ip, port)),
                        IpAddr::V6(ip) => SocketAddr::V6(std::net::SocketAddrV6::new(ip, port, 0, 0)),
                    };
                    let timeout_duration = options.timeout;
                    
                    let task = tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        
                        let start_time = Instant::now();
                        let result = match protocol {
                            Protocol::Tcp => {
                                timeout(timeout_duration, scanner_clone.test_tcp_connection(target_addr)).await
                            },
                            Protocol::Udp => {
                                timeout(timeout_duration, scanner_clone.test_udp_connection(target_addr)).await
                            },
                            _ => {
                                // Other protocols not implemented yet
                                return;
                            }
                        };
                        let response_time = start_time.elapsed();
                        
                        let port_state = match result {
                            Ok(Ok(conn_result)) => {
                                if conn_result.success {
                                    PortState::Open
                                } else {
                                    PortState::Closed
                                }
                            },
                            Ok(Err(_)) | Err(_) => PortState::Filtered,
                        };
                        
                        let port_result = PortResult::new(target_addr, protocol, port_state)
                            .with_response_time(response_time);
                        
                        let _ = tx.send(port_result).await;
                    });
                    
                    tasks.push(task);
                }
            }
        }
        
        drop(tx); // Close the sender
        
        // Collect results
        while let Some(port_result) = rx.recv().await {
            // Add to results
            {
                let mut results = self.results.write().await;
                results.add_port(port_result);
            }
            
            // Update progress
            self.update_progress().await;
        }
        
        // Wait for all tasks to complete
        for task in tasks {
            let _ = task.await;
        }
        
        Ok(())
    }

    /// Detect services on open ports
    async fn detect_services(&self, _options: &ScanOptions) -> Result<()> {
        // Get open ports from results
        let open_ports = {
            let results = self.results.read().await;
            results.ports_by_state(PortState::Open).into_iter().cloned().collect::<Vec<_>>()
        };
        
        info!(
            open_ports = open_ports.len(),
            "Starting service detection phase"
        );
        
        for port in open_ports {
            // Basic service detection based on port number
            let service_name = self.guess_service_by_port(port.address.port());
            
            if let Some(service) = service_name {
                let service_result = ServiceResult {
                    address: port.address,
                    protocol: port.protocol,
                    service: service.to_string(),
                    version: None,
                    product: None,
                    extra_info: None,
                    fingerprint: None,
                    confidence: 50, // Low confidence for port-based detection
                    method: DetectionMethod::BannerGrab,
                    timestamp: SystemTime::now(),
                };
                
                let mut results = self.results.write().await;
                results.add_service(service_result);
            }
        }
        
        Ok(())
    }

    /// Perform OS fingerprinting
    async fn fingerprint_os(&self, _hosts: &[HostResult], _options: &ScanOptions) -> Result<()> {
        // OS fingerprinting not implemented in MVP
        info!(
            host_count = _hosts.len(),
            "OS fingerprinting phase skipped (not implemented in MVP)"
        );
        Ok(())
    }

    /// Finalize scan results
    async fn finalize_scan(&self) -> Result<()> {
        let mut results = self.results.write().await;
        results.complete();
        
        info!(
            hosts_scanned = results.hosts.len(),
            ports_scanned = results.ports.len(),
            services_detected = results.services.len(),
            errors = results.errors.len(),
            "Scan finalization completed"
        );
        Ok(())
    }

    /// Set current scan phase
    async fn set_phase(&self, phase: ScanPhase) {
        let scan_id = {
            let state = self.state.read().await;
            state.scan_id
        };
        
        let mut state = self.state.write().await;
        state.phase = phase;
        
        info!(
            scan_id = %scan_id,
            phase = ?phase,
            elapsed_ms = state.start_time.elapsed().as_millis(),
            "Scan phase changed"
        );
    }

    /// Update scan progress
    async fn update_progress(&self) {
        // Implementation would update progress counters
        // This is a simplified version
    }

    /// Add an error to the results
    async fn add_error(&self, error: ScanError) {
        let mut results = self.results.write().await;
        results.add_error(error);
    }

    /// Expand CIDR notation to IP addresses
    fn expand_cidr(&self, cidr: &str) -> Result<Vec<IpAddr>> {
        // Simplified CIDR expansion - in real implementation would handle large ranges carefully
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(Error::Parse(crate::error::ParseError::InvalidCidr { cidr: cidr.to_string() }));
        }
        
        let base_ip: IpAddr = parts[0].parse()
            .map_err(|_| Error::Parse(crate::error::ParseError::InvalidIpAddress { address: parts[0].to_string() }))?;
        let prefix: u8 = parts[1].parse()
            .map_err(|_| Error::Parse(crate::error::ParseError::InvalidCidr { cidr: cidr.to_string() }))?;
        
        // For MVP, limit to small subnets to avoid memory issues
        if prefix < 24 {
            return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                range: "CIDR prefix too large for MVP (minimum /24)".to_string()
            }));
        }
        
        // Simple expansion for /24 networks
        match base_ip {
            IpAddr::V4(ipv4) => {
                let mut ips = Vec::new();
                let octets = ipv4.octets();
                for i in 1..255 {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], i)));
                }
                Ok(ips)
            },
            IpAddr::V6(_) => {
                // IPv6 CIDR expansion not implemented in MVP
                Err(Error::FeatureNotAvailable { feature: "IPv6 CIDR expansion".to_string() })
            }
        }
    }

    /// Expand IP range to individual addresses
    fn expand_ip_range(&self, start: IpAddr, end: IpAddr) -> Result<Vec<IpAddr>> {
        // Simplified IP range expansion
        match (start, end) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let start_num = u32::from(start_v4);
                let end_num = u32::from(end_v4);
                
                if end_num < start_num {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "End IP must be greater than start IP".to_string()
                    }));
                }
                
                // Limit range size for MVP
                if end_num - start_num > 1000 {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "IP range too large for MVP (maximum 1000 addresses)".to_string()
                    }));
                }
                
                let mut ips = Vec::new();
                for i in start_num..=end_num {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::from(i)));
                }
                Ok(ips)
            },
            _ => Err(Error::FeatureNotAvailable { feature: "IPv6 ranges or mixed ranges".to_string() })
        }
    }

    /// Guess service name by port number
    fn guess_service_by_port(&self, port: u16) -> Option<&'static str> {
        match port {
            21 => Some("ftp"),
            22 => Some("ssh"),
            23 => Some("telnet"),
            25 => Some("smtp"),
            53 => Some("dns"),
            80 => Some("http"),
            110 => Some("pop3"),
            143 => Some("imap"),
            443 => Some("https"),
            993 => Some("imaps"),
            995 => Some("pop3s"),
            3389 => Some("rdp"),
            5432 => Some("postgresql"),
            3306 => Some("mysql"),
            1433 => Some("mssql"),
            _ => None,
        }
    }

    /// Get current scan results
    pub async fn get_results(&self) -> ScanResults {
        self.results.read().await.clone()
    }

    /// Get current scan state
    pub async fn get_state(&self) -> ScanState {
        self.state.read().await.clone()
    }

    /// Cancel the current scan
    pub async fn cancel(&self) {
        let mut state = self.state.write().await;
        state.cancelled = true;
        state.phase = ScanPhase::Cancelled;
        let scan_id = {
            let state = self.state.read().await;
            state.scan_id
        };
        
        info!(
            scan_id = %scan_id,
            "Scan cancelled by user request"
        );
    }

    /// Pause the current scan
    pub async fn pause(&self) {
        let mut state = self.state.write().await;
        state.paused = true;
        let scan_id = {
            let state = self.state.read().await;
            state.scan_id
        };
        
        info!(
            scan_id = %scan_id,
            "Scan paused by user request"
        );
    }

    /// Resume the current scan
    pub async fn resume(&self) {
        let mut state = self.state.write().await;
        state.paused = false;
        let scan_id = {
            let state = self.state.read().await;
            state.scan_id
        };
        
        info!(
            scan_id = %scan_id,
            "Scan resumed by user request"
        );
    }
}

impl ScanState {
    /// Create a new scan state
    pub fn new() -> Self {
        Self {
            scan_id: Uuid::new_v4(),
            phase: ScanPhase::Initializing,
            start_time: Instant::now(),
            targets: Vec::new(),
            ports: PortRange::Single(80),
            protocols: vec![Protocol::Tcp],
            progress: ScanProgress::default(),
            cancelled: false,
            paused: false,
        }
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Check if scan is active
    pub fn is_active(&self) -> bool {
        matches!(self.phase, 
            ScanPhase::Initializing |
            ScanPhase::TargetResolution |
            ScanPhase::HostDiscovery |
            ScanPhase::PortScanning |
            ScanPhase::ServiceDetection |
            ScanPhase::OsFingerprinting |
            ScanPhase::Finalizing
        ) && !self.cancelled
    }
}

impl Default for ScanProgress {
    fn default() -> Self {
        Self {
            total_targets: 0,
            completed_targets: 0,
            total_ports: 0,
            completed_ports: 0,
            current_target: None,
            eta: None,
            rate: 0.0,
        }
    }
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            max_concurrency: 100,
            timeout: Duration::from_secs(5),
            retries: 1,
            delay: Duration::from_millis(0),
            host_discovery: true,
            service_detection: true,
            os_fingerprinting: false,
            skip_ping: false,
            protocols: vec![Protocol::Tcp],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_scanner_creation() {
        let config = Config::default();
        let scanner = Scanner::new(config);
        assert!(scanner.is_ok());
    }

    #[tokio::test]
    async fn test_scan_state() {
        let state = ScanState::new();
        assert_eq!(state.phase, ScanPhase::Initializing);
        assert!(state.is_active());
        assert!(!state.cancelled);
        assert!(!state.paused);
    }

    #[test]
    fn test_cidr_expansion() {
        let config = Config::default();
        let scanner = Scanner::new(config).unwrap();
        
        let ips = scanner.expand_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ips.len(), 254); // 1-254
        
        // Test invalid CIDR
        assert!(scanner.expand_cidr("192.168.1.0/16").is_err()); // Too large
        assert!(scanner.expand_cidr("invalid").is_err());
    }

    #[test]
    fn test_ip_range_expansion() {
        let config = Config::default();
        let scanner = Scanner::new(config).unwrap();
        
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        
        let ips = scanner.expand_ip_range(start, end).unwrap();
        assert_eq!(ips.len(), 10);
        
        // Test invalid range
        let large_end = IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1));
        assert!(scanner.expand_ip_range(start, large_end).is_err()); // Too large
    }

    #[test]
    fn test_service_guessing() {
        let config = Config::default();
        let scanner = Scanner::new(config).unwrap();
        
        assert_eq!(scanner.guess_service_by_port(80), Some("http"));
        assert_eq!(scanner.guess_service_by_port(443), Some("https"));
        assert_eq!(scanner.guess_service_by_port(22), Some("ssh"));
        assert_eq!(scanner.guess_service_by_port(12345), None);
    }

    #[test]
    fn test_scan_options_default() {
        let options = ScanOptions::default();
        assert_eq!(options.max_concurrency, 100);
        assert_eq!(options.timeout, Duration::from_secs(5));
        assert!(options.host_discovery);
        assert!(options.service_detection);
        assert!(!options.os_fingerprinting);
    }
}
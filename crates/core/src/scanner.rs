//! Core scanning engine for cyNetMapper

use crate::config::{Config, ScanProfile, TimingTemplate};
use crate::error::{Error, Result};
use crate::evasion::{EvasionConfig, EvasionManager};
use crate::network::NetworkScanner;
use crate::rate_limiter::{AdaptiveRateLimiter, CongestionDetector, TokenBucketLimiter};
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
    /// Adaptive rate limiter
    rate_limiter: Arc<RwLock<AdaptiveRateLimiter>>,
    /// Token bucket for burst control
    token_bucket: Arc<RwLock<TokenBucketLimiter>>,
    /// Congestion detector
    congestion_detector: Arc<RwLock<CongestionDetector>>,
    /// Evasion manager
    evasion_manager: Arc<RwLock<EvasionManager>>,
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
        
        // Initialize rate limiting components based on timing configuration
        let timing_config = &config.timing;
        let initial_pps = timing_config.rate_limit.unwrap_or(1000.0);
        let max_pps = timing_config.advanced.max_parallelism as f64;
        let min_pps = timing_config.advanced.min_parallelism as f64;
        
        let rate_limiter = Arc::new(RwLock::new(
            AdaptiveRateLimiter::new(initial_pps, min_pps, max_pps)
        ));
        
        let token_bucket = Arc::new(RwLock::new(
            TokenBucketLimiter::new(
                timing_config.advanced.max_parallelism.min(1000),
                initial_pps
            )
        ));
        
        let congestion_detector = Arc::new(RwLock::new(
            CongestionDetector::new()
        ));
        
        // Initialize evasion manager based on scan profile
        let evasion_config = match config.scan.profile {
            ScanProfile::Stealth => EvasionConfig::stealth_profile(),
            ScanProfile::Thorough => EvasionConfig::paranoid_profile(),
            ScanProfile::Aggressive => EvasionConfig::firewall_evasion_profile(),
            _ => EvasionConfig::default(),
        };
        
        let evasion_manager = Arc::new(RwLock::new(
            EvasionManager::new(evasion_config)
        ));
        
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
            rate_limiter,
            token_bucket,
            congestion_detector,
            evasion_manager,
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
        
        for mut port in open_ports {
            // Basic service detection based on port number
            let service_name = self.guess_service_by_port(port.address.port());
            
            if let Some(service) = service_name {
                // Update the port result with service information
                port.service = Some(service.to_string());
                
                // Create service result for detailed tracking
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
                
                // Update the port in the results
                if let Some(existing_port) = results.ports.iter_mut().find(|p| p.address == port.address && p.protocol == port.protocol) {
                    existing_port.service = port.service.clone();
                }
                
                // Add service result for detailed tracking
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
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(Error::Parse(crate::error::ParseError::InvalidCidr { cidr: cidr.to_string() }));
        }
        
        let base_ip: IpAddr = parts[0].parse()
            .map_err(|_| Error::Parse(crate::error::ParseError::InvalidIpAddress { address: parts[0].to_string() }))?;
        let prefix: u8 = parts[1].parse()
            .map_err(|_| Error::Parse(crate::error::ParseError::InvalidCidr { cidr: cidr.to_string() }))?;
        
        match base_ip {
            IpAddr::V4(ipv4) => {
                // For IPv4, limit to /24 or smaller to avoid memory issues
                if prefix < 24 {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "IPv4 CIDR prefix too large (minimum /24)".to_string()
                    }));
                }
                
                let mut ips = Vec::new();
                let octets = ipv4.octets();
                for i in 1..255 {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::new(octets[0], octets[1], octets[2], i)));
                }
                Ok(ips)
            },
            IpAddr::V6(ipv6) => {
                // For IPv6, limit to /112 or smaller to avoid memory issues
                if prefix < 112 {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "IPv6 CIDR prefix too large (minimum /112)".to_string()
                    }));
                }
                
                let host_bits = 128 - prefix;
                let num_addresses = 1u128 << host_bits;
                
                // Limit to 65536 addresses to prevent memory issues
                if num_addresses > 65536 {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "IPv6 CIDR range too large (maximum 65536 addresses)".to_string()
                    }));
                }
                
                let mut ips = Vec::new();
                let base_int = u128::from(ipv6);
                let network_mask = !((1u128 << host_bits) - 1);
                let network_base = base_int & network_mask;
                
                for i in 0..num_addresses {
                    let addr_int = network_base | i;
                    let addr = std::net::Ipv6Addr::from(addr_int);
                    ips.push(IpAddr::V6(addr));
                }
                
                Ok(ips)
            }
        }
    }

    /// Expand IP range to individual addresses
    fn expand_ip_range(&self, start: IpAddr, end: IpAddr) -> Result<Vec<IpAddr>> {
        match (start, end) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let start_num = u32::from(start_v4);
                let end_num = u32::from(end_v4);
                
                if end_num < start_num {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "End IP must be greater than start IP".to_string()
                    }));
                }
                
                // Limit range size to prevent memory issues
                if end_num - start_num > 65536 {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "IPv4 range too large (maximum 65536 addresses)".to_string()
                    }));
                }
                
                let mut ips = Vec::new();
                for i in start_num..=end_num {
                    ips.push(IpAddr::V4(std::net::Ipv4Addr::from(i)));
                }
                Ok(ips)
            },
            (IpAddr::V6(start_v6), IpAddr::V6(end_v6)) => {
                let start_num = u128::from(start_v6);
                let end_num = u128::from(end_v6);
                
                if end_num < start_num {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "End IPv6 must be greater than start IPv6".to_string()
                    }));
                }
                
                let range_size = end_num.saturating_sub(start_num).saturating_add(1);
                
                // Limit range size to prevent memory issues
                if range_size > 65536 {
                    return Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                        range: "IPv6 range too large (maximum 65536 addresses)".to_string()
                    }));
                }
                
                let mut ips = Vec::new();
                let mut current = start_num;
                
                while current <= end_num && ips.len() < 65536 {
                    ips.push(IpAddr::V6(std::net::Ipv6Addr::from(current)));
                    if current == u128::MAX {
                        break; // Prevent overflow
                    }
                    current += 1;
                }
                Ok(ips)
            },
            _ => Err(Error::Config(crate::error::ConfigError::InvalidPortRange {
                range: "IP range must use the same IP version (IPv4 or IPv6)".to_string()
            }))
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
            1433 => Some("mssql"),
            3000 => Some("node"),
            3001 => Some("node"),
            3306 => Some("mysql"),
            3389 => Some("rdp"),
            4157 => Some("unknown"),
            5000 => Some("flask"),
            5432 => Some("postgresql"),
            6379 => Some("redis"),
            7000 => Some("cassandra"),
            8000 => Some("http-alt"),
            8021 => Some("unknown"),
            8080 => Some("http-proxy"),
            8828 => Some("unknown"),
            9000 => Some("http-alt"),
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
    
    /// Wait for rate limiting before sending next probe
    async fn wait_for_rate_limit(&self) {
        // Use token bucket for burst control
        self.token_bucket.write().await.consume().await;
        
        // Use adaptive rate limiter for congestion control
        self.rate_limiter.write().await.wait_for_next().await;
    }
    
    /// Record probe response for rate limiting adjustment
    async fn record_probe_response(&self, response_time: Duration, success: bool) {
        if success {
            self.rate_limiter.write().await.record_response(response_time);
            self.congestion_detector.write().await.record_rtt(response_time);
        } else {
            self.rate_limiter.write().await.record_timeout();
        }
    }
    
    /// Get optimal parallelism level based on current conditions
    async fn get_optimal_parallelism(&self) -> usize {
        let timing_config = &self.config.timing;
        let is_congested = self.congestion_detector.read().await.is_congested();
        
        if is_congested {
            // Reduce parallelism during congestion
            timing_config.advanced.min_parallelism as usize
        } else {
            // Use effective parallelism from timing config
            timing_config.effective_parallelism() as usize
        }
    }
    
    /// Perform parallel port scan with rate limiting
    async fn parallel_port_scan(
        &self,
        host: &HostResult,
        ports: &[u16],
        protocol: Protocol,
        options: &ScanOptions,
    ) -> Result<Vec<PortResult>> {
        let parallelism = self.get_optimal_parallelism().await.min(options.max_concurrency);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(parallelism));
        let mut tasks = Vec::new();
        
        for &port in ports {
            let permit = semaphore.clone().acquire_owned().await.unwrap();
            let host_addr = host.address;
            let scanner = self.clone_for_task();
            let opts = options.clone();
            
            let task = tokio::spawn(async move {
                let _permit = permit; // Hold permit until task completes
                
                // Wait for rate limiting
                scanner.wait_for_rate_limit().await;
                
                let start_time = Instant::now();
                let result = scanner.scan_single_port(host_addr, port, protocol, &opts).await;
                let response_time = start_time.elapsed();
                
                // Record response for rate limiting
                scanner.record_probe_response(response_time, result.is_ok()).await;
                
                result
            });
            
            tasks.push(task);
        }
        
        // Collect results
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(port_result)) => results.push(port_result),
                Ok(Err(e)) => {
                    warn!("Port scan error: {}", e);
                }
                Err(e) => {
                    warn!("Task join error: {}", e);
                }
            }
        }
        
        Ok(results)
    }
    
    /// Clone scanner for use in async tasks (lightweight clone)
    fn clone_for_task(&self) -> ScannerTask {
        ScannerTask {
            config: self.config.clone(),
            network_scanner: self.network_scanner.clone(),
            rate_limiter: self.rate_limiter.clone(),
            token_bucket: self.token_bucket.clone(),
            congestion_detector: self.congestion_detector.clone(),
        }
    }
    
    /// Scan a single port with timeout and retries
    async fn scan_single_port(
        &self,
        host: IpAddr,
        port: u16,
        protocol: Protocol,
        options: &ScanOptions,
    ) -> Result<PortResult> {
        let mut last_error = None;
        
        for attempt in 0..=options.retries {
            if attempt > 0 {
                tokio::time::sleep(options.delay).await;
            }
            
            match timeout(options.timeout, self.probe_port(host, port, protocol)).await {
                Ok(Ok(state)) => {
                    return Ok(PortResult {
                          address: SocketAddr::new(host.into(), port),
                          protocol,
                          state,
                          service: None,
                          version: None,
                          banner: None,
                          response_time: Some(options.timeout),
                          extra_info: HashMap::new(),
                          timestamp: SystemTime::now(),
                      });
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_) => {
                     last_error = Some(Error::timeout(options.timeout.as_millis() as u64));
                 }
            }
        }
        
        Err(last_error.unwrap_or_else(|| Error::timeout(options.timeout.as_millis() as u64)))
    }
    
    /// Probe a single port with evasion techniques
     async fn probe_port(&self, host: IpAddr, port: u16, protocol: Protocol) -> Result<PortState> {
         let mut evasion_manager = self.evasion_manager.write().await;
         
         match protocol {
             Protocol::Tcp => {
                 // Apply TCP evasion techniques
                 let target_addr = SocketAddr::new(host.into(), port);
                 
                 // Use custom source port if configured
                  let bind_addr = if let Some(source_ip) = evasion_manager.get_spoofed_source() {
                      SocketAddr::new(source_ip.into(), 0)
                  } else {
                      SocketAddr::new("0.0.0.0".parse().unwrap(), 0)
                  };
                 
                 // Apply timing randomization
                 let delay = evasion_manager.get_random_delay();
                 if delay > Duration::from_micros(0) {
                     tokio::time::sleep(delay).await;
                 }
                 
                 match tokio::net::TcpStream::connect(target_addr).await {
                     Ok(_) => Ok(PortState::Open),
                     Err(_) => Ok(PortState::Closed),
                 }
             }
             Protocol::Udp => {
                 // UDP scanning with evasion techniques
                 use tokio::net::UdpSocket;
                 
                 let bind_addr = if let Some(source_ip) = evasion_manager.get_spoofed_source() {
                      format!("{}:0", source_ip)
                  } else {
                      "0.0.0.0:0".to_string()
                  };
                 
                 let socket = UdpSocket::bind(&bind_addr).await
                       .map_err(|e| Error::Network(crate::error::NetworkError::SocketCreationFailed { reason: e.to_string() }))?;
                   
                 let target_addr = SocketAddr::new(host.into(), port);
                 
                 // Use custom payload if available
                 let payload = evasion_manager.generate_random_payload();
                 
                 // Apply timing randomization
                 let delay = evasion_manager.get_random_delay();
                 if delay > Duration::from_micros(0) {
                     tokio::time::sleep(delay).await;
                 }
                 
                 socket.send_to(&payload, target_addr).await
                     .map_err(|e| Error::Network(crate::error::NetworkError::PacketSendFailed { reason: e.to_string() }))?;
                 
                 // Wait for response with timeout
                 let mut buf = [0u8; 1024];
                 let timeout_duration = Duration::from_millis(5000);
                 
                 match tokio::time::timeout(timeout_duration, socket.recv_from(&mut buf)).await {
                     Ok(Ok(_)) => Ok(PortState::Open),
                     Ok(Err(_)) => Ok(PortState::Filtered),
                     Err(_) => Ok(PortState::OpenFiltered),
                 }
             }
             Protocol::Icmp => {
                 // ICMP scanning placeholder
                 Ok(PortState::OpenFiltered)
             }
             Protocol::Sctp => {
                 // SCTP scanning placeholder
                 Ok(PortState::OpenFiltered)
             }
         }
     }
}

/// Lightweight scanner for async tasks
#[derive(Clone)]
struct ScannerTask {
    config: Arc<Config>,
    network_scanner: NetworkScanner,
    rate_limiter: Arc<RwLock<AdaptiveRateLimiter>>,
    token_bucket: Arc<RwLock<TokenBucketLimiter>>,
    congestion_detector: Arc<RwLock<CongestionDetector>>,
}

impl ScannerTask {
    async fn wait_for_rate_limit(&self) {
        self.token_bucket.write().await.consume().await;
        self.rate_limiter.write().await.wait_for_next().await;
    }
    
    async fn record_probe_response(&self, response_time: Duration, success: bool) {
        if success {
            self.rate_limiter.write().await.record_response(response_time);
            self.congestion_detector.write().await.record_rtt(response_time);
        } else {
            self.rate_limiter.write().await.record_timeout();
        }
    }
    
    async fn scan_single_port(
        &self,
        host: IpAddr,
        port: u16,
        protocol: Protocol,
        options: &ScanOptions,
    ) -> Result<PortResult> {
        let mut last_error = None;
        
        for attempt in 0..=options.retries {
            if attempt > 0 {
                tokio::time::sleep(options.delay).await;
            }
            
            match timeout(options.timeout, self.probe_port(host, port, protocol)).await {
                Ok(Ok(state)) => {
                    return Ok(PortResult {
                          address: SocketAddr::new(host.into(), port),
                          protocol,
                          state,
                          service: None,
                          version: None,
                          banner: None,
                          response_time: Some(options.timeout),
                          extra_info: HashMap::new(),
                          timestamp: SystemTime::now(),
                      });
                }
                Ok(Err(e)) => {
                    last_error = Some(e);
                }
                Err(_) => {
                     last_error = Some(Error::timeout(options.timeout.as_millis() as u64));
                 }
            }
        }
        
        Err(last_error.unwrap_or_else(|| Error::timeout(options.timeout.as_millis() as u64)))
    }
    
    async fn probe_port(&self, host: IpAddr, port: u16, protocol: Protocol) -> Result<PortState> {
         match protocol {
             Protocol::Tcp => {
                  match tokio::net::TcpStream::connect(SocketAddr::new(host.into(), port)).await {
                      Ok(_) => Ok(PortState::Open),
                      Err(_) => Ok(PortState::Closed),
                  }
              }
             Protocol::Udp => {
                 // UDP scanning with basic socket approach
                 use tokio::net::UdpSocket;
                 
                 let socket = UdpSocket::bind("0.0.0.0:0").await
                       .map_err(|e| Error::Network(crate::error::NetworkError::SocketCreationFailed { reason: e.to_string() }))?;
                   
                   let target_addr = SocketAddr::new(host.into(), port);
                   
                   // Send basic UDP probe
                   let payload = b"\x00\x00\x00\x00";
                   socket.send_to(payload, target_addr).await
                       .map_err(|e| Error::Network(crate::error::NetworkError::PacketSendFailed { reason: e.to_string() }))?;
                 
                 // Wait for response with timeout
                 let mut buf = [0u8; 1024];
                 let timeout_duration = Duration::from_millis(5000);
                 
                 match tokio::time::timeout(timeout_duration, socket.recv_from(&mut buf)).await {
                     Ok(Ok(_)) => Ok(PortState::Open),
                     Ok(Err(_)) => Ok(PortState::Filtered),
                     Err(_) => Ok(PortState::OpenFiltered),
                 }
             }
             Protocol::Icmp => {
                 Ok(PortState::OpenFiltered)
             }
             Protocol::Sctp => {
                 Ok(PortState::OpenFiltered)
             }
         }
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
            host_discovery: false,  // Disabled by default to allow scanning hosts without common ports open
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
        assert!(!options.host_discovery);
        assert!(options.service_detection);
        assert!(!options.os_fingerprinting);
    }
}
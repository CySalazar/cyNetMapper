//! Host discovery engine for cyNetMapper

use crate::config::Config;
use crate::error::{Error, ParseError, Result};
use crate::network::{NetworkScanner, ConnectionResult};
use crate::results::{HostResult, DiscoveryMethod, ScanMetadata};
use crate::timing::{TimingController, ScanPhase};
use crate::types::{IpAddr, Target, HostState};

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, trace, warn};

/// Host discovery engine
#[derive(Debug)]
pub struct DiscoveryEngine {
    /// Configuration
    config: Arc<Config>,
    /// Network scanner
    network_scanner: NetworkScanner,
    /// Timing controller
    timing_controller: TimingController,
    /// Discovery methods to use
    methods: Vec<DiscoveryMethod>,
}

/// Discovery probe configuration
#[derive(Debug, Clone)]
pub struct DiscoveryProbe {
    /// Probe method
    pub method: DiscoveryMethod,
    /// Target ports for TCP/UDP probes
    pub ports: Vec<u16>,
    /// Timeout for this probe
    pub timeout: Duration,
    /// Number of retries
    pub retries: u32,
}

/// Discovery result for a single host
#[derive(Debug, Clone)]
pub struct HostDiscoveryResult {
    /// Target IP address
    pub ip: IpAddr,
    /// Host state
    pub state: HostState,
    /// Discovery methods that succeeded
    pub successful_methods: Vec<DiscoveryMethod>,
    /// Response times for each method
    pub response_times: HashMap<DiscoveryMethod, Duration>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
    /// Discovery timestamp
    pub timestamp: Instant,
}

/// Discovery statistics
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    /// Total hosts tested
    pub hosts_tested: u64,
    /// Hosts found up
    pub hosts_up: u64,
    /// Hosts found down
    pub hosts_down: u64,
    /// Hosts with unknown state
    pub hosts_unknown: u64,
    /// Total probes sent
    pub probes_sent: u64,
    /// Total responses received
    pub responses_received: u64,
    /// Discovery duration
    pub duration: Duration,
    /// Methods used
    pub methods_used: Vec<DiscoveryMethod>,
}

impl DiscoveryEngine {
    /// Create a new discovery engine
    pub fn new(config: &Config) -> Result<Self> {
        let network_scanner = NetworkScanner::new(Duration::from_secs(5));
        let timing_controller = TimingController::new(config)?;
        
        // Determine discovery methods based on configuration
        let methods = Self::get_discovery_methods(config);
        
        Ok(Self {
            config: Arc::new(config.clone()),
            network_scanner,
            timing_controller,
            methods,
        })
    }
    
    /// Discover hosts from a list of targets
    pub async fn discover_hosts(&self, targets: &[Target]) -> Result<Vec<HostDiscoveryResult>> {
        info!("Starting host discovery for {} targets", targets.len());
        let start_time = Instant::now();
        
        // Expand targets to individual IP addresses
        let ips = self.expand_targets(targets).await?;
        info!("Expanded to {} IP addresses", ips.len());
        
        // Perform discovery
        let mut results = Vec::new();
        let mut stats = DiscoveryStats::default();
        
        // Process IPs in batches to control concurrency
        let batch_size = self.config.scan.max_concurrency as usize;
        
        for batch in ips.chunks(batch_size) {
            let batch_results = self.discover_batch(batch).await?;
            
            for result in batch_results {
                stats.hosts_tested += 1;
                match result.state {
                    HostState::Up => stats.hosts_up += 1,
                    HostState::Down => stats.hosts_down += 1,
                    HostState::Unknown => stats.hosts_unknown += 1,
                }
                results.push(result);
            }
        }
        
        stats.duration = start_time.elapsed();
        stats.methods_used = self.methods.clone();
        
        info!(
            "Host discovery completed: {}/{} hosts up in {:?}",
            stats.hosts_up, stats.hosts_tested, stats.duration
        );
        
        Ok(results)
    }
    
    /// Discover a single host
    pub async fn discover_host(&self, ip: IpAddr) -> Result<HostDiscoveryResult> {
        debug!("Discovering host: {}", ip);
        let start_time = Instant::now();
        
        let mut successful_methods = Vec::new();
        let mut response_times = HashMap::new();
        let mut metadata = HashMap::new();
        
        // Try each discovery method
        for method in &self.methods {
            let probe_start = Instant::now();
            
            match self.probe_host(ip, *method).await {
                Ok(true) => {
                    let response_time = probe_start.elapsed();
                    successful_methods.push(*method);
                    response_times.insert(*method, response_time);
                    trace!("Host {} responded to {:?} in {:?}", ip, method, response_time);
                },
                Ok(false) => {
                    trace!("Host {} did not respond to {:?}", ip, method);
                },
                Err(e) => {
                    warn!("Error probing host {} with {:?}: {}", ip, method, e);
                }
            }
            
            // Rate limiting
            self.timing_controller.wait_for_rate_limit().await?;
        }
        
        // Determine host state
        let state = if successful_methods.is_empty() {
            HostState::Down
        } else {
            HostState::Up
        };
        
        // Add metadata
        metadata.insert("discovery_duration".to_string(), start_time.elapsed().as_millis().to_string());
        metadata.insert("methods_tried".to_string(), self.methods.len().to_string());
        metadata.insert("methods_successful".to_string(), successful_methods.len().to_string());
        
        Ok(HostDiscoveryResult {
            ip,
            state,
            successful_methods,
            response_times,
            metadata,
            timestamp: start_time,
        })
    }
    
    /// Discover a batch of hosts concurrently
    async fn discover_batch(&self, ips: &[IpAddr]) -> Result<Vec<HostDiscoveryResult>> {
        let mut tasks = Vec::new();
        
        for &ip in ips {
            let engine = self.clone_for_task();
            let task = tokio::spawn(async move {
                engine.discover_host(ip).await
            });
            tasks.push(task);
        }
        
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => warn!("Discovery task failed: {}", e),
                Err(e) => warn!("Discovery task panicked: {}", e),
            }
        }
        
        Ok(results)
    }
    
    /// Probe a host with a specific method
    async fn probe_host(&self, ip: IpAddr, method: DiscoveryMethod) -> Result<bool> {
        let timing = self.timing_controller.get_scan_timing(ScanPhase::HostDiscovery);
        
        match method {
            DiscoveryMethod::TcpConnect => self.tcp_connect_probe(ip, timing.initial_timeout).await,
            DiscoveryMethod::TcpSyn => {
                // TCP SYN probe not implemented in MVP (requires raw sockets)
                warn!("TCP SYN probe not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::IcmpEcho => {
                // ICMP Echo probe not implemented in MVP (requires raw sockets)
                warn!("ICMP Echo probe not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::IcmpTimestamp => {
                // ICMP Timestamp probe not implemented in MVP
                warn!("ICMP Timestamp probe not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::IcmpAddressMask => {
                // ICMP Address Mask probe not implemented in MVP
                warn!("ICMP Address Mask probe not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::TcpAck => {
                // TCP ACK probe not implemented in MVP
                warn!("TCP ACK probe not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::UdpProbe => {
                // UDP probe not implemented in MVP
                warn!("UDP probe not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::Arp => {
                // ARP ping not implemented in MVP
                warn!("ARP ping not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::DnsResolution => {
                // DNS resolution not implemented in MVP
                warn!("DNS resolution not implemented in MVP");
                Ok(false)
            },
            DiscoveryMethod::DnsLookup => self.dns_lookup_probe(ip).await,
        }
    }
    
    /// TCP Connect probe (most reliable for MVP)
    async fn tcp_connect_probe(&self, ip: IpAddr, timeout_duration: Duration) -> Result<bool> {
        // Try common ports that are likely to be open
        let common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995];
        
        for &port in &common_ports {
            let addr = SocketAddr::new(ip.into(), port);
            
            match timeout(timeout_duration, TcpStream::connect(addr)).await {
                Ok(Ok(_stream)) => {
                    trace!("TCP connect successful to {}:{}", ip, port);
                    return Ok(true);
                },
                Ok(Err(_)) => {
                    // Connection refused or other error, try next port
                    continue;
                },
                Err(_) => {
                    // Timeout, try next port
                    continue;
                }
            }
        }
        
        Ok(false)
    }
    
    /// DNS lookup probe
    async fn dns_lookup_probe(&self, ip: IpAddr) -> Result<bool> {
        // Perform reverse DNS lookup to check if host responds to DNS queries
        match self.network_scanner.reverse_dns_lookup(ip).await {
            Ok(hostname) => {
                trace!("Reverse DNS lookup successful for {}: {}", ip, hostname);
                Ok(true)
            },
            Err(e) => {
                trace!("Reverse DNS lookup failed for {}: {}", ip, e);
                Ok(false)
            }
        }
    }
    
    /// Expand targets to individual IP addresses
    async fn expand_targets(&self, targets: &[Target]) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();
        
        for target in targets {
            match target {
                Target::Ip(ip) => {
                    ips.push(*ip);
                },
                Target::Cidr { network, prefix } => {
                    let cidr_str = format!("{}/{}", network, prefix);
                    let expanded = self.expand_cidr(&cidr_str)?;
                    ips.extend(expanded);
                },
                Target::Hostname(hostname) => {
                    // Hostname resolution not implemented in MVP
                    warn!("Hostname resolution not implemented in MVP: {}", hostname);
                },
                Target::Range { start, end } => {
                    let expanded = self.expand_ip_range(*start, *end)?;
                    ips.extend(expanded);
                },
            }
        }
        
        // Remove duplicates
        ips.sort();
        ips.dedup();
        
        Ok(ips)
    }
    
    /// Expand CIDR notation to individual IPs
    fn expand_cidr(&self, cidr: &str) -> Result<Vec<IpAddr>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(Error::Parse(ParseError::InvalidCidr { cidr: cidr.to_string() }));
        }
        
        let base_ip: IpAddr = parts[0].parse()
            .map_err(|e: std::net::AddrParseError| Error::Parse(ParseError::InvalidIpAddress { address: e.to_string() }))?;
        let prefix: u8 = parts[1].parse()
            .map_err(|e: std::num::ParseIntError| Error::Parse(ParseError::InvalidCidr { cidr: e.to_string() }))?;
        
        match base_ip {
            IpAddr::V4(ipv4) => self.expand_ipv4_cidr(ipv4, prefix),
            IpAddr::V6(_ipv6) => {
                // IPv6 CIDR expansion is complex and can generate huge ranges
                // For MVP, limit to small prefixes or return error
                if prefix < 120 {
                    return Err(Error::Parse(ParseError::InvalidCidr { 
                        cidr: format!("IPv6 CIDR prefix too large for expansion: /{}", prefix) 
                    }));
                }
                // TODO: Implement IPv6 CIDR expansion for small ranges
                warn!("IPv6 CIDR expansion not fully implemented in MVP");
                Ok(vec![base_ip])
            }
        }
    }
    
    /// Expand IPv4 CIDR to individual IPs
    fn expand_ipv4_cidr(&self, base_ip: Ipv4Addr, prefix: u8) -> Result<Vec<IpAddr>> {
        if prefix > 32 {
            return Err(Error::Parse(ParseError::InvalidCidr { cidr: "IPv4 prefix cannot be greater than 32".to_string() }));
        }
        
        // Prevent expansion of very large networks
        if prefix < 16 {
            return Err(Error::Parse(ParseError::InvalidCidr { cidr: "IPv4 CIDR prefix too large for expansion (minimum /16)".to_string() }));
        }
        
        let host_bits = 32 - prefix;
        let num_hosts = 1u32 << host_bits;
        
        // Additional safety check
        if num_hosts > 65536 {
            return Err(Error::Parse(ParseError::InvalidCidr { cidr: "CIDR range too large for expansion".to_string() }));
        }
        
        let base_num = u32::from(base_ip);
        let network_mask = !((1u32 << host_bits) - 1);
        let network_addr = base_num & network_mask;
        
        let mut ips = Vec::new();
        for i in 1..(num_hosts - 1) { // Skip network and broadcast addresses
            let ip_num = network_addr + i;
            let ip = Ipv4Addr::from(ip_num);
            ips.push(IpAddr::V4(ip));
        }
        
        Ok(ips)
    }
    
    /// Expand IP range to individual IPs
    fn expand_ip_range(&self, start: IpAddr, end: IpAddr) -> Result<Vec<IpAddr>> {
        match (start, end) {
            (IpAddr::V4(start_v4), IpAddr::V4(end_v4)) => {
                let start_num = u32::from(start_v4);
                let end_num = u32::from(end_v4);
                
                if end_num < start_num {
                    return Err(Error::Parse(ParseError::InvalidIpAddress { address: "End IP must be >= start IP".to_string() }));
                }
                
                let range_size = end_num - start_num + 1;
                if range_size > 65536 {
                    return Err(Error::Parse(ParseError::InvalidIpAddress { address: "IP range too large for expansion".to_string() }));
                }
                
                let mut ips = Vec::new();
                for ip_num in start_num..=end_num {
                    let ip = Ipv4Addr::from(ip_num);
                    ips.push(IpAddr::V4(ip));
                }
                
                Ok(ips)
            },
            (IpAddr::V6(_), IpAddr::V6(_)) => {
                // IPv6 range expansion is complex
                warn!("IPv6 range expansion not implemented in MVP");
                Ok(vec![start, end])
            },
            _ => Err(Error::Parse(ParseError::InvalidIpAddress { address: "IP range must use same IP version".to_string() })),
        }
    }
    
    /// Resolve hostname to IP addresses
    async fn resolve_hostname(&self, hostname: &str) -> Result<Vec<IpAddr>> {
        // Hostname resolution not implemented in MVP
        warn!("Hostname resolution not implemented in MVP: {}", hostname);
        Ok(vec![])
    }
    
    /// Get discovery methods based on configuration
    fn get_discovery_methods(config: &Config) -> Vec<DiscoveryMethod> {
        let mut methods = Vec::new();
        
        // Always include TCP Connect for MVP (most reliable)
        methods.push(DiscoveryMethod::TcpConnect);
        
        // Add DNS lookup if enabled
        if config.scan.host_discovery {
            methods.push(DiscoveryMethod::DnsLookup);
        }
        
        // TODO: Add other methods when implemented
        // if config.scan.enable_icmp {
        //     methods.push(DiscoveryMethod::IcmpEcho);
        // }
        
        methods
    }
    
    /// Clone engine for concurrent tasks
    fn clone_for_task(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            network_scanner: self.network_scanner.clone(),
            timing_controller: self.timing_controller.clone(),
            methods: self.methods.clone(),
        }
    }
}

impl Clone for DiscoveryEngine {
    fn clone(&self) -> Self {
        Self {
            config: Arc::clone(&self.config),
            network_scanner: self.network_scanner.clone(),
            timing_controller: self.timing_controller.clone(),
            methods: self.methods.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[tokio::test]
    async fn test_discovery_engine_creation() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_expand_ipv4_cidr() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config).unwrap();
        
        // Test /24 network
        let base_ip = Ipv4Addr::new(192, 168, 1, 0);
        let ips = engine.expand_ipv4_cidr(base_ip, 24).unwrap();
        assert_eq!(ips.len(), 254); // Excluding network and broadcast
        
        // Test /30 network (small)
        let ips = engine.expand_ipv4_cidr(base_ip, 30).unwrap();
        assert_eq!(ips.len(), 2); // Only 2 host addresses
        
        // Test invalid prefix
        let result = engine.expand_ipv4_cidr(base_ip, 8);
        assert!(result.is_err()); // Too large
        
        let result = engine.expand_ipv4_cidr(base_ip, 33);
        assert!(result.is_err()); // Invalid prefix
    }

    #[test]
    fn test_expand_ip_range() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config).unwrap();
        
        let start = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let end = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10));
        
        let ips = engine.expand_ip_range(start, end).unwrap();
        assert_eq!(ips.len(), 10);
        
        // Test invalid range
        let result = engine.expand_ip_range(end, start);
        assert!(result.is_err());
        
        // Test mixed IP versions
        let ipv6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let result = engine.expand_ip_range(start, ipv6);
        assert!(result.is_err());
    }

    #[test]
    fn test_expand_cidr() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config).unwrap();
        
        // Valid CIDR
        let ips = engine.expand_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ips.len(), 254);
        
        // Invalid CIDR format
        let result = engine.expand_cidr("192.168.1.0");
        assert!(result.is_err());
        
        let result = engine.expand_cidr("invalid/24");
        assert!(result.is_err());
        
        // Too large CIDR
        let result = engine.expand_cidr("10.0.0.0/8");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_expand_targets() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config).unwrap();
        
        let targets = vec![
            Target::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
            Target::Cidr { network: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), prefix: 30 },
        ];
        
        let ips = engine.expand_targets(&targets).await.unwrap();
        assert!(ips.len() >= 3); // At least the single IP + 2 from CIDR
        
        // Check for duplicates (should be removed)
        let mut sorted_ips = ips.clone();
        sorted_ips.sort();
        sorted_ips.dedup();
        assert_eq!(ips.len(), sorted_ips.len());
    }

    #[tokio::test]
    async fn test_tcp_connect_probe() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config).unwrap();
        
        // Test localhost (should work if any services are running)
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = engine.tcp_connect_probe(localhost, Duration::from_secs(1)).await;
        // Result depends on what's running on localhost, so we just check it doesn't panic
        assert!(result.is_ok());
        
        // Test unreachable IP (should fail)
        let unreachable = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)); // RFC 5737 test address
        let result = engine.tcp_connect_probe(unreachable, Duration::from_millis(100)).await;
        assert!(result.is_ok()); // Should return Ok(false)
        if let Ok(success) = result {
            assert!(!success); // Should not succeed
        }
    }

    #[test]
    fn test_discovery_methods() {
        let config = Config::default();
        let methods = DiscoveryEngine::get_discovery_methods(&config);
        
        // Should always include TCP Connect
        assert!(methods.contains(&DiscoveryMethod::TcpConnect));
        
        // Should include DNS lookup if host discovery is enabled
        if config.scan.host_discovery {
            assert!(methods.contains(&DiscoveryMethod::DnsLookup));
        }
    }

    #[tokio::test]
    async fn test_host_discovery_result() {
        let config = Config::default();
        let engine = DiscoveryEngine::new(&config).unwrap();
        
        let ip = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let result = engine.discover_host(ip).await;
        
        assert!(result.is_ok());
        let discovery_result = result.unwrap();
        assert_eq!(discovery_result.ip, ip);
        assert!(matches!(discovery_result.state, HostState::Up | HostState::Down));
        assert!(!discovery_result.metadata.is_empty());
    }
}
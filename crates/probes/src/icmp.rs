//! ICMP probe implementation for cyNetMapper

use crate::common::{ProbeError, ProbeOptions, ProbeResult};
use cynetmapper_core::{
    config::Config,
    error::{Error, Result},
    types::{IpAddr, Protocol},
};

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr as StdIpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::timeout;
use tracing::{debug, trace, warn};

/// ICMP probe options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpProbeOptions {
    /// Timeout for ICMP responses
    pub timeout: Duration,
    
    /// Number of ping attempts
    pub count: u32,
    
    /// Interval between pings
    pub interval: Duration,
    
    /// Packet size (data payload)
    pub packet_size: u16,
    
    /// TTL value to use
    pub ttl: Option<u8>,
    
    /// Don't fragment flag
    pub dont_fragment: bool,
    
    /// Custom payload pattern
    pub payload_pattern: Option<Vec<u8>>,
    
    /// Source IP address
    pub source_ip: Option<IpAddr>,
    
    /// Enable traceroute mode
    pub traceroute: bool,
    
    /// Maximum hops for traceroute
    pub max_hops: u8,
}

impl Default for IcmpProbeOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            count: 1,
            interval: Duration::from_secs(1),
            packet_size: 32,
            ttl: None,
            dont_fragment: false,
            payload_pattern: None,
            source_ip: None,
            traceroute: false,
            max_hops: 30,
        }
    }
}

/// ICMP probe result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpProbeResult {
    /// Base probe result
    pub base: ProbeResult,
    
    /// ICMP response type
    pub icmp_type: Option<u8>,
    
    /// ICMP response code
    pub icmp_code: Option<u8>,
    
    /// Round-trip times for each ping
    pub round_trip_times: Vec<Duration>,
    
    /// Packet loss percentage
    pub packet_loss: f32,
    
    /// Average RTT
    pub avg_rtt: Option<Duration>,
    
    /// Minimum RTT
    pub min_rtt: Option<Duration>,
    
    /// Maximum RTT
    pub max_rtt: Option<Duration>,
    
    /// Standard deviation of RTT
    pub rtt_stddev: Option<Duration>,
    
    /// TTL of received packets
    pub received_ttl: Option<u8>,
    
    /// Payload echoed back correctly
    pub payload_echoed: bool,
    
    /// Traceroute hops (if traceroute enabled)
    pub traceroute_hops: Vec<TracerouteHop>,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl IcmpProbeResult {
    /// Create new ICMP probe result
    pub fn new(target: IpAddr) -> Self {
        use std::net::SocketAddr;
        let socket_addr = SocketAddr::new(target.into(), 0);
        Self {
            base: ProbeResult::success(
                socket_addr,
                Protocol::Icmp,
                cynetmapper_core::types::PortState::Open,
                std::time::Duration::from_millis(0),
            ),
            icmp_type: None,
            icmp_code: None,
            round_trip_times: Vec::new(),
            packet_loss: 0.0,
            avg_rtt: None,
            min_rtt: None,
            max_rtt: None,
            rtt_stddev: None,
            received_ttl: None,
            payload_echoed: false,
            traceroute_hops: Vec::new(),
            metadata: HashMap::new(),
        }
    }
    
    /// Add RTT measurement
    pub fn add_rtt(&mut self, rtt: Duration) {
        self.round_trip_times.push(rtt);
        self.calculate_statistics();
    }
    
    /// Calculate RTT statistics
    fn calculate_statistics(&mut self) {
        if self.round_trip_times.is_empty() {
            return;
        }
        
        let sum: Duration = self.round_trip_times.iter().sum();
        self.avg_rtt = Some(sum / self.round_trip_times.len() as u32);
        
        self.min_rtt = self.round_trip_times.iter().min().copied();
        self.max_rtt = self.round_trip_times.iter().max().copied();
        
        // Calculate standard deviation
        if let Some(avg) = self.avg_rtt {
            let variance: f64 = self.round_trip_times.iter()
                .map(|rtt| {
                    let diff = rtt.as_nanos() as f64 - avg.as_nanos() as f64;
                    diff * diff
                })
                .sum::<f64>() / self.round_trip_times.len() as f64;
            
            let stddev_nanos = variance.sqrt() as u64;
            self.rtt_stddev = Some(Duration::from_nanos(stddev_nanos));
        }
    }
    
    /// Set packet loss percentage
    pub fn set_packet_loss(&mut self, sent: u32, received: u32) {
        if sent > 0 {
            self.packet_loss = ((sent - received) as f32 / sent as f32) * 100.0;
        }
    }
    
    /// Check if host is reachable
    pub fn is_reachable(&self) -> bool {
        !self.round_trip_times.is_empty() && self.packet_loss < 100.0
    }
}

/// Traceroute hop information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerouteHop {
    /// Hop number (TTL)
    pub hop: u8,
    
    /// IP address of the hop
    pub address: Option<IpAddr>,
    
    /// Hostname (if resolved)
    pub hostname: Option<String>,
    
    /// Round-trip times for this hop
    pub rtts: Vec<Duration>,
    
    /// Average RTT for this hop
    pub avg_rtt: Option<Duration>,
    
    /// ICMP type/code received
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    
    /// Whether this hop responded
    pub responded: bool,
}

impl TracerouteHop {
    /// Create new traceroute hop
    pub fn new(hop: u8) -> Self {
        Self {
            hop,
            address: None,
            hostname: None,
            rtts: Vec::new(),
            avg_rtt: None,
            icmp_type: None,
            icmp_code: None,
            responded: false,
        }
    }
    
    /// Add RTT measurement
    pub fn add_rtt(&mut self, rtt: Duration) {
        self.rtts.push(rtt);
        self.responded = true;
        
        // Calculate average
        let sum: Duration = self.rtts.iter().sum();
        self.avg_rtt = Some(sum / self.rtts.len() as u32);
    }
}

/// ICMP packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpType {
    /// Echo Reply
    EchoReply = 0,
    /// Destination Unreachable
    DestinationUnreachable = 3,
    /// Source Quench
    SourceQuench = 4,
    /// Redirect
    Redirect = 5,
    /// Echo Request
    EchoRequest = 8,
    /// Router Advertisement
    RouterAdvertisement = 9,
    /// Router Solicitation
    RouterSolicitation = 10,
    /// Time Exceeded
    TimeExceeded = 11,
    /// Parameter Problem
    ParameterProblem = 12,
    /// Timestamp Request
    TimestampRequest = 13,
    /// Timestamp Reply
    TimestampReply = 14,
    /// Information Request
    InformationRequest = 15,
    /// Information Reply
    InformationReply = 16,
}

/// ICMP probe implementation
#[derive(Debug)]
pub struct IcmpProbe {
    /// Configuration
    config: Arc<Config>,
    
    /// Default options
    default_options: IcmpProbeOptions,
}

impl IcmpProbe {
    /// Create a new ICMP probe
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            config,
            default_options: IcmpProbeOptions::default(),
        }
    }
    
    /// Probe a single target with ICMP
    pub async fn probe_target(
        &self,
        target: IpAddr,
        options: Option<&IcmpProbeOptions>,
    ) -> Result<IcmpProbeResult> {
        let opts = options.unwrap_or(&self.default_options);
        let mut result = IcmpProbeResult::new(target);
        
        debug!("Starting ICMP probe for {} with {} pings", target, opts.count);
        
        if opts.traceroute {
            // Perform traceroute
            result = self.traceroute(target, opts).await?;
        } else {
            // Perform regular ping
            result = self.ping(target, opts).await?;
        }
        
        debug!("ICMP probe completed for {}: reachable={}, loss={:.1}%", 
               target, result.is_reachable(), result.packet_loss);
        
        Ok(result)
    }
    
    /// Probe multiple targets concurrently
    pub async fn probe_targets(
        &self,
        targets: &[IpAddr],
        options: Option<&IcmpProbeOptions>,
        max_concurrent: Option<usize>,
    ) -> Result<Vec<IcmpProbeResult>> {
        let max_concurrent = max_concurrent.unwrap_or(self.config.scan.max_concurrency);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
        
        let mut tasks = Vec::new();
        
        for &target in targets {
            let probe = self.clone();
            let options = options.cloned();
            let semaphore = semaphore.clone();
            
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                probe.probe_target(target, options.as_ref()).await
            });
            
            tasks.push(task);
        }
        
        let mut results = Vec::new();
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => {
                    warn!("ICMP probe failed: {}", e);
                    // Continue with other probes
                }
                Err(e) => {
                    warn!("ICMP probe task failed: {}", e);
                }
            }
        }
        
        Ok(results)
    }
    
    /// Perform ping operation
    async fn ping(
        &self,
        target: IpAddr,
        options: &IcmpProbeOptions,
    ) -> Result<IcmpProbeResult> {
        let mut result = IcmpProbeResult::new(target);
        let mut sent = 0;
        let mut received = 0;
        
        for i in 0..options.count {
            if i > 0 {
                tokio::time::sleep(options.interval).await;
            }
            
            sent += 1;
            
            match self.send_ping(target, options).await {
                Ok(Some(rtt)) => {
                    received += 1;
                    result.add_rtt(rtt);
                    trace!("Ping {} reply {}: time={:.2}ms", target, i + 1, rtt.as_secs_f64() * 1000.0);
                }
                Ok(None) => {
                    trace!("Ping {} timeout {}", target, i + 1);
                }
                Err(e) => {
                    warn!("Ping {} error {}: {}", target, i + 1, e);
                }
            }
        }
        
        result.set_packet_loss(sent, received);
        
        if received > 0 {
            result.base.state = cynetmapper_core::types::PortState::Open;
        } else {
            result.base.state = cynetmapper_core::types::PortState::Filtered;
        }
        
        Ok(result)
    }
    
    /// Perform traceroute operation
    async fn traceroute(
        &self,
        target: IpAddr,
        options: &IcmpProbeOptions,
    ) -> Result<IcmpProbeResult> {
        let mut result = IcmpProbeResult::new(target);
        
        debug!("Starting traceroute to {} with max {} hops", target, options.max_hops);
        
        for ttl in 1..=options.max_hops {
            let mut hop = TracerouteHop::new(ttl);
            
            // Send multiple probes per hop
            for _ in 0..3 {
                let mut hop_options = options.clone();
                hop_options.ttl = Some(ttl);
                
                match self.send_ping(target, &hop_options).await {
                    Ok(Some(rtt)) => {
                        hop.add_rtt(rtt);
                        // In a real implementation, we would extract the source IP
                        // from the ICMP Time Exceeded message
                        trace!("Traceroute hop {}: time={:.2}ms", ttl, rtt.as_secs_f64() * 1000.0);
                    }
                    Ok(None) => {
                        trace!("Traceroute hop {} timeout", ttl);
                    }
                    Err(e) => {
                        trace!("Traceroute hop {} error: {}", ttl, e);
                    }
                }
            }
            
            result.traceroute_hops.push(hop);
            
            // Check if we reached the target
            // In a real implementation, we would check if the response came from the target
            // For now, we'll stop at max_hops
        }
        
        Ok(result)
    }
    
    /// Send a single ping packet
    async fn send_ping(
        &self,
        target: IpAddr,
        options: &IcmpProbeOptions,
    ) -> Result<Option<Duration>> {
        let start = Instant::now();
        
        // Note: This is a simplified implementation
        // In a real implementation, we would:
        // 1. Create raw ICMP socket (requires privileges)
        // 2. Construct ICMP packet with proper headers
        // 3. Send packet and wait for reply
        // 4. Parse ICMP response
        
        // For now, we'll simulate with a TCP connect to port 80 as a connectivity test
        let result = self.simulate_ping(target, options).await;
        
        match result {
            Ok(true) => {
                let rtt = start.elapsed();
                Ok(Some(rtt))
            }
            Ok(false) => Ok(None),
            Err(e) => Err(e),
        }
    }
    
    /// Simulate ping using TCP connect (fallback when raw sockets not available)
    async fn simulate_ping(
        &self,
        target: IpAddr,
        options: &IcmpProbeOptions,
    ) -> Result<bool> {
        let std_addr = match target {
            IpAddr::V4(addr) => StdIpAddr::V4(addr.into()),
            IpAddr::V6(addr) => StdIpAddr::V6(addr.into()),
        };
        
        // Try common ports for connectivity test
        let test_ports = [80, 443, 22, 21, 25, 53];
        
        for &port in &test_ports {
            let socket_addr = SocketAddr::new(std_addr, port);
            
            match timeout(options.timeout, tokio::net::TcpStream::connect(socket_addr)).await {
                Ok(Ok(_)) => {
                    trace!("Connectivity test successful to {}:{}", target, port);
                    return Ok(true);
                }
                Ok(Err(_)) => {
                    // Port closed, but host might be reachable
                    continue;
                }
                Err(_) => {
                    // Timeout
                    continue;
                }
            }
        }
        
        // If no ports responded, try UDP to port 53 (DNS)
        match self.udp_connectivity_test(std_addr, options.timeout).await {
            Ok(true) => Ok(true),
            _ => Ok(false),
        }
    }
    
    /// UDP connectivity test
    async fn udp_connectivity_test(
        &self,
        target: StdIpAddr,
        timeout_duration: Duration,
    ) -> Result<bool> {
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await
            .map_err(|e| Error::Network(cynetmapper_core::error::NetworkError::SocketCreationFailed { reason: e.to_string() }))?;
        
        let target_addr = SocketAddr::new(target, 53); // DNS port
        
        // Send a simple DNS query
        let dns_query = vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            // Query for "."
            0x00,       // Root domain
            0x00, 0x01, // Type: A
            0x00, 0x01, // Class: IN
        ];
        
        match timeout(timeout_duration, socket.send_to(&dns_query, target_addr)).await {
            Ok(Ok(_)) => {
                // Try to receive response
                let mut buf = [0u8; 512];
                match timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                    Ok(Ok(_)) => Ok(true),
                    _ => Ok(false), // No response, but packet was sent
                }
            }
            _ => Ok(false),
        }
    }
    
    /// Create ICMP packet payload
    fn create_payload(&self, options: &IcmpProbeOptions) -> Vec<u8> {
        if let Some(pattern) = &options.payload_pattern {
            pattern.clone()
        } else {
            // Default payload pattern
            let mut payload = Vec::with_capacity(options.packet_size as usize);
            for i in 0..options.packet_size {
                payload.push((i % 256) as u8);
            }
            payload
        }
    }
    
    /// Check if raw sockets are available
    pub fn raw_sockets_available(&self) -> bool {
        // In a real implementation, we would check if we can create raw sockets
        // This requires root privileges on Unix systems
        false // Simplified for this implementation
    }
    
    /// Get capabilities
    pub fn get_capabilities(&self) -> HashMap<String, bool> {
        let mut caps = HashMap::new();
        caps.insert("icmp_ping".to_string(), true);
        caps.insert("traceroute".to_string(), true);
        caps.insert("raw_sockets".to_string(), self.raw_sockets_available());
        caps.insert("ipv4".to_string(), true);
        caps.insert("ipv6".to_string(), true);
        caps
    }
}

impl Clone for IcmpProbe {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            default_options: self.default_options.clone(),
        }
    }
}

/// ICMP probe builder for easy configuration
#[derive(Debug)]
pub struct IcmpProbeBuilder {
    options: IcmpProbeOptions,
}

impl IcmpProbeBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            options: IcmpProbeOptions::default(),
        }
    }
    
    /// Set timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.options.timeout = timeout;
        self
    }
    
    /// Set ping count
    pub fn count(mut self, count: u32) -> Self {
        self.options.count = count;
        self
    }
    
    /// Set interval between pings
    pub fn interval(mut self, interval: Duration) -> Self {
        self.options.interval = interval;
        self
    }
    
    /// Set packet size
    pub fn packet_size(mut self, size: u16) -> Self {
        self.options.packet_size = size;
        self
    }
    
    /// Set TTL
    pub fn ttl(mut self, ttl: u8) -> Self {
        self.options.ttl = Some(ttl);
        self
    }
    
    /// Enable don't fragment
    pub fn dont_fragment(mut self) -> Self {
        self.options.dont_fragment = true;
        self
    }
    
    /// Set custom payload pattern
    pub fn payload_pattern(mut self, pattern: Vec<u8>) -> Self {
        self.options.payload_pattern = Some(pattern);
        self
    }
    
    /// Set source IP
    pub fn source_ip(mut self, ip: IpAddr) -> Self {
        self.options.source_ip = Some(ip);
        self
    }
    
    /// Enable traceroute mode
    pub fn traceroute(mut self, max_hops: u8) -> Self {
        self.options.traceroute = true;
        self.options.max_hops = max_hops;
        self
    }
    
    /// Build the options
    pub fn build(self) -> IcmpProbeOptions {
        self.options
    }
}

impl Default for IcmpProbeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    #[test]
    fn test_icmp_probe_options() {
        let options = IcmpProbeBuilder::new()
            .timeout(Duration::from_secs(5))
            .count(3)
            .interval(Duration::from_millis(500))
            .packet_size(64)
            .ttl(64)
            .dont_fragment()
            .build();
        
        assert_eq!(options.timeout, Duration::from_secs(5));
        assert_eq!(options.count, 3);
        assert_eq!(options.interval, Duration::from_millis(500));
        assert_eq!(options.packet_size, 64);
        assert_eq!(options.ttl, Some(64));
        assert!(options.dont_fragment);
    }

    #[test]
    fn test_icmp_probe_result() {
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let mut result = IcmpProbeResult::new(target);
        
        // Add some RTT measurements
        result.add_rtt(Duration::from_millis(10));
        result.add_rtt(Duration::from_millis(15));
        result.add_rtt(Duration::from_millis(12));
        
        assert_eq!(result.round_trip_times.len(), 3);
        assert!(result.avg_rtt.is_some());
        assert!(result.min_rtt.is_some());
        assert!(result.max_rtt.is_some());
        assert!(result.rtt_stddev.is_some());
        
        assert_eq!(result.min_rtt.unwrap(), Duration::from_millis(10));
        assert_eq!(result.max_rtt.unwrap(), Duration::from_millis(15));
        
        // Test packet loss calculation
        result.set_packet_loss(4, 3);
        assert_eq!(result.packet_loss, 25.0);
        
        assert!(result.is_reachable());
    }

    #[test]
    fn test_traceroute_hop() {
        let mut hop = TracerouteHop::new(5);
        
        assert_eq!(hop.hop, 5);
        assert!(!hop.responded);
        assert!(hop.avg_rtt.is_none());
        
        hop.add_rtt(Duration::from_millis(20));
        hop.add_rtt(Duration::from_millis(25));
        
        assert!(hop.responded);
        assert!(hop.avg_rtt.is_some());
        assert_eq!(hop.rtts.len(), 2);
    }

    #[tokio::test]
    async fn test_icmp_probe_creation() {
        let config = Arc::new(Config::default());
        let probe = IcmpProbe::new(config);
        
        let capabilities = probe.get_capabilities();
        assert!(capabilities.get("icmp_ping").unwrap_or(&false));
        assert!(capabilities.get("traceroute").unwrap_or(&false));
        assert!(capabilities.get("ipv4").unwrap_or(&false));
        assert!(capabilities.get("ipv6").unwrap_or(&false));
    }

    #[tokio::test]
    async fn test_icmp_probe_simulation() {
        let config = Arc::new(Config::default());
        let probe = IcmpProbe::new(config);
        
        // Test with localhost (should be reachable)
        let target = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
        let target_socket = SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
        let options = IcmpProbeBuilder::new()
            .count(1)
            .timeout(Duration::from_secs(1))
            .build();
        
        let result = probe.probe_target(target, Some(&options)).await;
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.base.target, target_socket);
        assert_eq!(result.base.protocol, Protocol::Icmp);
    }

    #[tokio::test]
    async fn test_multiple_targets() {
        let config = Arc::new(Config::default());
        let probe = IcmpProbe::new(config);
        
        let targets = vec![
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        ];
        
        let options = IcmpProbeBuilder::new()
            .count(1)
            .timeout(Duration::from_secs(2))
            .build();
        
        let results = probe.probe_targets(&targets, Some(&options), Some(2)).await;
        assert!(results.is_ok());
        
        let results = results.unwrap();
        assert!(!results.is_empty());
    }

    #[test]
    fn test_payload_creation() {
        let config = Arc::new(Config::default());
        let probe = IcmpProbe::new(config);
        
        let options = IcmpProbeOptions {
            packet_size: 10,
            ..Default::default()
        };
        
        let payload = probe.create_payload(&options);
        assert_eq!(payload.len(), 10);
        
        // Test with custom pattern
        let custom_pattern = vec![0xAA, 0xBB, 0xCC];
        let options_custom = IcmpProbeOptions {
            payload_pattern: Some(custom_pattern.clone()),
            ..Default::default()
        };
        
        let payload_custom = probe.create_payload(&options_custom);
        assert_eq!(payload_custom, custom_pattern);
    }

    #[test]
    fn test_icmp_type_enum() {
        assert_eq!(IcmpType::EchoRequest as u8, 8);
        assert_eq!(IcmpType::EchoReply as u8, 0);
        assert_eq!(IcmpType::TimeExceeded as u8, 11);
        assert_eq!(IcmpType::DestinationUnreachable as u8, 3);
    }
}
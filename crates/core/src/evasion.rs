//! Network evasion techniques module
//!
//! This module implements various techniques to evade firewalls and IDS systems,
//! including packet fragmentation, decoy scanning, and source spoofing.

use crate::config::Config;
use crate::error::{Error, Result};
use crate::types::{IpAddr, Protocol};

use rand::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Evasion technique configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvasionConfig {
    /// Enable packet fragmentation
    pub fragment_packets: bool,
    
    /// Fragment size for packet fragmentation
    pub fragment_size: Option<u16>,
    
    /// Enable decoy scanning
    pub use_decoys: bool,
    
    /// List of decoy IP addresses
    pub decoy_addresses: Vec<IpAddr>,
    
    /// Number of random decoys to generate
    pub random_decoys: u8,
    
    /// Enable source IP spoofing
    pub spoof_source: bool,
    
    /// Source IP to spoof (if None, random IP will be used)
    pub spoofed_source: Option<IpAddr>,
    
    /// Enable timing randomization
    pub randomize_timing: bool,
    
    /// Minimum delay between packets (microseconds)
    pub min_packet_delay: u64,
    
    /// Maximum delay between packets (microseconds)
    pub max_packet_delay: u64,
    
    /// Enable source port randomization
    pub randomize_source_port: bool,
    
    /// Range of source ports to use
    pub source_port_range: Option<(u16, u16)>,
    
    /// Enable data payload randomization
    pub randomize_payload: bool,
    
    /// Maximum payload size for randomization
    pub max_payload_size: usize,
    
    /// Enable TCP sequence number randomization
    pub randomize_tcp_seq: bool,
    
    /// Enable IP ID randomization
    pub randomize_ip_id: bool,
    
    /// TTL value to use (if None, system default)
    pub custom_ttl: Option<u8>,
    
    /// Enable bad checksum technique
    pub bad_checksum: bool,
}

impl Default for EvasionConfig {
    fn default() -> Self {
        Self {
            fragment_packets: false,
            fragment_size: Some(8),
            use_decoys: false,
            decoy_addresses: Vec::new(),
            random_decoys: 0,
            spoof_source: false,
            spoofed_source: None,
            randomize_timing: false,
            min_packet_delay: 0,
            max_packet_delay: 1000,
            randomize_source_port: false,
            source_port_range: None,
            randomize_payload: false,
            max_payload_size: 64,
            randomize_tcp_seq: false,
            randomize_ip_id: false,
            custom_ttl: None,
            bad_checksum: false,
        }
    }
}

/// Evasion technique types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EvasionTechnique {
    /// Packet fragmentation
    Fragmentation,
    /// Decoy scanning
    DecoyScanning,
    /// Source IP spoofing
    SourceSpoofing,
    /// Timing randomization
    TimingRandomization,
    /// Source port randomization
    SourcePortRandomization,
    /// Payload randomization
    PayloadRandomization,
    /// TCP sequence randomization
    TcpSequenceRandomization,
    /// IP ID randomization
    IpIdRandomization,
    /// Custom TTL
    CustomTtl,
    /// Bad checksum
    BadChecksum,
}

/// Evasion manager for coordinating evasion techniques
#[derive(Debug)]
pub struct EvasionManager {
    config: EvasionConfig,
    active_techniques: Vec<EvasionTechnique>,
    decoy_pool: Vec<IpAddr>,
}

impl EvasionManager {
    /// Create a new evasion manager
    pub fn new(config: EvasionConfig) -> Self {
        let mut manager = Self {
            config: config.clone(),
            active_techniques: Vec::new(),
            decoy_pool: Vec::new(),
        };
        
        manager.initialize_techniques();
        manager.generate_decoy_pool();
        
        manager
    }
    
    /// Initialize active evasion techniques based on configuration
    fn initialize_techniques(&mut self) {
        self.active_techniques.clear();
        
        if self.config.fragment_packets {
            self.active_techniques.push(EvasionTechnique::Fragmentation);
        }
        
        if self.config.use_decoys {
            self.active_techniques.push(EvasionTechnique::DecoyScanning);
        }
        
        if self.config.spoof_source {
            self.active_techniques.push(EvasionTechnique::SourceSpoofing);
        }
        
        if self.config.randomize_timing {
            self.active_techniques.push(EvasionTechnique::TimingRandomization);
        }
        
        if self.config.randomize_source_port {
            self.active_techniques.push(EvasionTechnique::SourcePortRandomization);
        }
        
        if self.config.randomize_payload {
            self.active_techniques.push(EvasionTechnique::PayloadRandomization);
        }
        
        if self.config.randomize_tcp_seq {
            self.active_techniques.push(EvasionTechnique::TcpSequenceRandomization);
        }
        
        if self.config.randomize_ip_id {
            self.active_techniques.push(EvasionTechnique::IpIdRandomization);
        }
        
        if self.config.custom_ttl.is_some() {
            self.active_techniques.push(EvasionTechnique::CustomTtl);
        }
        
        if self.config.bad_checksum {
            self.active_techniques.push(EvasionTechnique::BadChecksum);
        }
        
        info!(
            "Initialized {} evasion techniques: {:?}",
            self.active_techniques.len(),
            self.active_techniques
        );
    }
    
    /// Generate decoy IP pool
    fn generate_decoy_pool(&mut self) {
        self.decoy_pool = self.config.decoy_addresses.clone();
        
        // Generate random decoys if requested
        for _ in 0..self.config.random_decoys {
            let random_ip = self.generate_random_ip();
            self.decoy_pool.push(random_ip);
        }
        
        if !self.decoy_pool.is_empty() {
            info!("Generated decoy pool with {} addresses", self.decoy_pool.len());
        }
    }
    
    /// Generate a random IP address
    fn generate_random_ip(&mut self) -> IpAddr {
        let mut rng = rand::thread_rng();
        // Generate random IPv4 address (avoiding reserved ranges)
        loop {
            let a = rng.gen_range(1..=223);
            let b = rng.gen_range(0..=255);
            let c = rng.gen_range(0..=255);
            let d = rng.gen_range(1..=254);
            
            // Avoid reserved ranges
            if a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168) {
                continue;
            }
            
            return IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d));
        }
    }
    
    /// Get random timing delay
    pub fn get_random_delay(&mut self) -> Duration {
        if !self.config.randomize_timing {
            return Duration::from_micros(0);
        }
        
        let mut rng = rand::thread_rng();
        let delay_micros = rng.gen_range(
            self.config.min_packet_delay..=self.config.max_packet_delay
        );
        
        Duration::from_micros(delay_micros)
    }
    
    /// Get random source port
    pub fn get_random_source_port(&mut self) -> Option<u16> {
        if !self.config.randomize_source_port {
            return None;
        }
        
        let mut rng = rand::thread_rng();
        match self.config.source_port_range {
            Some((min, max)) => Some(rng.gen_range(min..=max)),
            None => Some(rng.gen_range(32768..=65535)), // Ephemeral port range
        }
    }
    
    /// Get spoofed source IP
    pub fn get_spoofed_source(&mut self) -> Option<IpAddr> {
        if !self.config.spoof_source {
            return None;
        }
        
        match &self.config.spoofed_source {
            Some(ip) => Some(*ip),
            None => Some(self.generate_random_ip()),
        }
    }
    
    /// Get decoy addresses for scanning
    pub fn get_decoy_addresses(&mut self, target: IpAddr, real_source: IpAddr) -> Vec<IpAddr> {
        if !self.config.use_decoys || self.decoy_pool.is_empty() {
            return vec![real_source];
        }
        
        let mut rng = rand::thread_rng();
        let mut addresses = self.decoy_pool.clone();
        
        // Insert real source at random position
        let insert_pos = rng.gen_range(0..=addresses.len());
        addresses.insert(insert_pos, real_source);
        
        // Shuffle the addresses
        use rand::seq::SliceRandom;
        addresses.shuffle(&mut rng);
        
        debug!(
            "Generated decoy sequence for target {}: {} addresses",
            target,
            addresses.len()
        );
        
        addresses
    }
    
    /// Generate random payload
    pub fn generate_random_payload(&mut self) -> Vec<u8> {
        if !self.config.randomize_payload {
            return Vec::new();
        }
        
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(0..=self.config.max_payload_size);
        (0..size).map(|_| rng.gen()).collect()
    }
    
    /// Get random TCP sequence number
    pub fn get_random_tcp_sequence(&mut self) -> Option<u32> {
        if !self.config.randomize_tcp_seq {
            return None;
        }
        
        let mut rng = rand::thread_rng();
        Some(rng.gen())
    }
    
    /// Get random IP ID
    pub fn get_random_ip_id(&mut self) -> Option<u16> {
        if !self.config.randomize_ip_id {
            return None;
        }
        
        let mut rng = rand::thread_rng();
        Some(rng.gen())
    }
    
    /// Get custom TTL value
    pub fn get_custom_ttl(&self) -> Option<u8> {
        self.config.custom_ttl
    }
    
    /// Check if bad checksum should be used
    pub fn use_bad_checksum(&self) -> bool {
        self.config.bad_checksum
    }
    
    /// Get fragment size
    pub fn get_fragment_size(&self) -> Option<u16> {
        if self.config.fragment_packets {
            self.config.fragment_size
        } else {
            None
        }
    }
    
    /// Check if technique is active
    pub fn is_technique_active(&self, technique: EvasionTechnique) -> bool {
        self.active_techniques.contains(&technique)
    }
    
    /// Get active techniques
    pub fn get_active_techniques(&self) -> &[EvasionTechnique] {
        &self.active_techniques
    }
    
    /// Update configuration
    pub fn update_config(&mut self, config: EvasionConfig) {
        self.config = config;
        self.initialize_techniques();
        self.generate_decoy_pool();
    }
    
    /// Get configuration
    pub fn get_config(&self) -> &EvasionConfig {
        &self.config
    }
}

/// Evasion technique builder for easy configuration
#[derive(Debug, Default)]
pub struct EvasionConfigBuilder {
    config: EvasionConfig,
}

impl EvasionConfigBuilder {
    /// Create a new builder
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Enable packet fragmentation
    pub fn with_fragmentation(mut self, fragment_size: Option<u16>) -> Self {
        self.config.fragment_packets = true;
        self.config.fragment_size = fragment_size;
        self
    }
    
    /// Enable decoy scanning
    pub fn with_decoys(mut self, decoys: Vec<IpAddr>, random_count: u8) -> Self {
        self.config.use_decoys = true;
        self.config.decoy_addresses = decoys;
        self.config.random_decoys = random_count;
        self
    }
    
    /// Enable source spoofing
    pub fn with_source_spoofing(mut self, spoofed_ip: Option<IpAddr>) -> Self {
        self.config.spoof_source = true;
        self.config.spoofed_source = spoofed_ip;
        self
    }
    
    /// Enable timing randomization
    pub fn with_timing_randomization(mut self, min_delay: u64, max_delay: u64) -> Self {
        self.config.randomize_timing = true;
        self.config.min_packet_delay = min_delay;
        self.config.max_packet_delay = max_delay;
        self
    }
    
    /// Enable source port randomization
    pub fn with_source_port_randomization(mut self, port_range: Option<(u16, u16)>) -> Self {
        self.config.randomize_source_port = true;
        self.config.source_port_range = port_range;
        self
    }
    
    /// Enable payload randomization
    pub fn with_payload_randomization(mut self, max_size: usize) -> Self {
        self.config.randomize_payload = true;
        self.config.max_payload_size = max_size;
        self
    }
    
    /// Enable TCP sequence randomization
    pub fn with_tcp_sequence_randomization(mut self) -> Self {
        self.config.randomize_tcp_seq = true;
        self
    }
    
    /// Enable IP ID randomization
    pub fn with_ip_id_randomization(mut self) -> Self {
        self.config.randomize_ip_id = true;
        self
    }
    
    /// Set custom TTL
    pub fn with_custom_ttl(mut self, ttl: u8) -> Self {
        self.config.custom_ttl = Some(ttl);
        self
    }
    
    /// Enable bad checksum
    pub fn with_bad_checksum(mut self) -> Self {
        self.config.bad_checksum = true;
        self
    }
    
    /// Build the configuration
    pub fn build(self) -> EvasionConfig {
        self.config
    }
}

/// Predefined evasion profiles
impl EvasionConfig {
    /// Stealth profile with moderate evasion
    pub fn stealth_profile() -> Self {
        EvasionConfigBuilder::new()
            .with_timing_randomization(100, 2000)
            .with_source_port_randomization(Some((32768, 65535)))
            .with_tcp_sequence_randomization()
            .with_ip_id_randomization()
            .build()
    }
    
    /// Paranoid profile with maximum evasion
    pub fn paranoid_profile() -> Self {
        EvasionConfigBuilder::new()
            .with_fragmentation(Some(8))
            .with_decoys(Vec::new(), 5)
            .with_timing_randomization(500, 5000)
            .with_source_port_randomization(Some((32768, 65535)))
            .with_payload_randomization(32)
            .with_tcp_sequence_randomization()
            .with_ip_id_randomization()
            .build()
    }
    
    /// Firewall evasion profile
    pub fn firewall_evasion_profile() -> Self {
        EvasionConfigBuilder::new()
            .with_fragmentation(Some(8))
            .with_source_port_randomization(Some((1024, 65535)))
            .with_custom_ttl(64)
            .build()
    }
    
    /// IDS evasion profile
    pub fn ids_evasion_profile() -> Self {
        EvasionConfigBuilder::new()
            .with_timing_randomization(1000, 10000)
            .with_payload_randomization(64)
            .with_tcp_sequence_randomization()
            .with_ip_id_randomization()
            .build()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    
    #[test]
    fn test_evasion_config_default() {
        let config = EvasionConfig::default();
        assert!(!config.fragment_packets);
        assert!(!config.use_decoys);
        assert!(!config.spoof_source);
    }
    
    #[test]
    fn test_evasion_config_builder() {
        let config = EvasionConfigBuilder::new()
            .with_fragmentation(Some(16))
            .with_timing_randomization(100, 1000)
            .build();
            
        assert!(config.fragment_packets);
        assert_eq!(config.fragment_size, Some(16));
        assert!(config.randomize_timing);
        assert_eq!(config.min_packet_delay, 100);
        assert_eq!(config.max_packet_delay, 1000);
    }
    
    #[test]
    fn test_evasion_manager_creation() {
        let config = EvasionConfig::stealth_profile();
        let manager = EvasionManager::new(config);
        
        assert!(!manager.active_techniques.is_empty());
        assert!(manager.is_technique_active(EvasionTechnique::TimingRandomization));
    }
    
    #[test]
    fn test_decoy_generation() {
        let config = EvasionConfigBuilder::new()
            .with_decoys(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))], 2)
            .build();
            
        let mut manager = EvasionManager::new(config);
        let real_source = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let target = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        
        let decoys = manager.get_decoy_addresses(target, real_source);
        assert!(decoys.len() >= 3); // 1 configured + 2 random + 1 real
        assert!(decoys.contains(&real_source));
    }
    
    #[test]
    fn test_predefined_profiles() {
        let stealth = EvasionConfig::stealth_profile();
        assert!(stealth.randomize_timing);
        assert!(stealth.randomize_source_port);
        
        let paranoid = EvasionConfig::paranoid_profile();
        assert!(paranoid.fragment_packets);
        assert!(paranoid.use_decoys);
        
        let firewall = EvasionConfig::firewall_evasion_profile();
        assert!(firewall.fragment_packets);
        assert!(firewall.custom_ttl.is_some());
        
        let ids = EvasionConfig::ids_evasion_profile();
        assert!(ids.randomize_timing);
        assert!(ids.randomize_payload);
    }
}
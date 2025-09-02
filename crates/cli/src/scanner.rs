//! CLI scanner implementation

use anyhow::{Context, Result};
use colored::*;
use cynetmapper_core::{
    config::Config,
    types::{IpAddr, Protocol},
};
use cynetmapper_probes::{ComprehensiveProbeResult, ProbeManager, ProbeManagerConfig};
use futures::stream::{self, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::time::sleep;
use tracing::{debug, info, warn};

use crate::utils;

/// CLI scanner for coordinating scans
pub struct CliScanner {
    config: Arc<Config>,
    probe_manager: ProbeManager,
    stats: ScanStats,
}

/// Scan statistics
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    pub total_targets: AtomicUsize,
    pub completed_targets: AtomicUsize,
    pub total_ports: AtomicUsize,
    pub completed_ports: AtomicUsize,
    pub open_ports: AtomicUsize,
    pub closed_ports: AtomicUsize,
    pub filtered_ports: AtomicUsize,
    pub errors: AtomicUsize,
    pub start_time: Option<Instant>,
    pub end_time: Option<Instant>,
}

impl ScanStats {
    /// Create new scan statistics
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Start timing
    pub fn start(&mut self) {
        self.start_time = Some(Instant::now());
    }
    
    /// End timing
    pub fn end(&mut self) {
        self.end_time = Some(Instant::now());
    }
    
    /// Get elapsed time
    pub fn elapsed(&self) -> Option<Duration> {
        match (self.start_time, self.end_time) {
            (Some(start), Some(end)) => Some(end.duration_since(start)),
            (Some(start), None) => Some(start.elapsed()),
            _ => None,
        }
    }
    
    /// Get completion percentage
    pub fn completion_percentage(&self) -> f64 {
        let total = self.total_ports.load(Ordering::Relaxed);
        if total == 0 {
            return 0.0;
        }
        
        let completed = self.completed_ports.load(Ordering::Relaxed);
        (completed as f64 / total as f64) * 100.0
    }
    
    /// Get scan rate (ports per second)
    pub fn scan_rate(&self) -> f64 {
        if let Some(elapsed) = self.elapsed() {
            let completed = self.completed_ports.load(Ordering::Relaxed);
            let elapsed_secs = elapsed.as_secs_f64();
            if elapsed_secs > 0.0 {
                return completed as f64 / elapsed_secs;
            }
        }
        0.0
    }
    
    /// Get estimated time remaining
    pub fn eta(&self) -> Option<Duration> {
        let total = self.total_ports.load(Ordering::Relaxed);
        let completed = self.completed_ports.load(Ordering::Relaxed());
        
        if completed == 0 || total == completed {
            return None;
        }
        
        let rate = self.scan_rate();
        if rate <= 0.0 {
            return None;
        }
        
        let remaining = total - completed;
        let eta_secs = remaining as f64 / rate;
        Some(Duration::from_secs_f64(eta_secs))
    }
}

impl CliScanner {
    /// Create a new CLI scanner
    pub fn new(config: Arc<Config>) -> Result<Self> {
        let probe_config = ProbeManagerConfig::from_config(&config)?;
        let probe_manager = ProbeManager::with_config(config.clone(), probe_config);
        
        Ok(Self {
            config,
            probe_manager,
            stats: ScanStats::new(),
        })
    }
    
    /// Perform a comprehensive scan
    pub async fn scan(
        &self,
        targets: Vec<IpAddr>,
        ports: Vec<u16>,
        protocols: Vec<Protocol>,
        progress_bar: Option<ProgressBar>,
    ) -> Result<Vec<ComprehensiveProbeResult>> {
        let mut stats = self.stats.clone();
        stats.start();
        
        let total_combinations = targets.len() * ports.len() * protocols.len();
        stats.total_ports.store(total_combinations, Ordering::Relaxed);
        stats.total_targets.store(targets.len(), Ordering::Relaxed);
        
        info!(
            "Starting scan: {} targets, {} ports, {} protocols ({} total combinations)",
            targets.len(),
            ports.len(),
            protocols.len(),
            total_combinations
        );
        
        // Setup progress bar
        let pb = progress_bar.unwrap_or_else(|| {
            let pb = ProgressBar::new(total_combinations as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb
        });
        
        // Create scan tasks
        let mut scan_tasks = Vec::new();
        
        for target in &targets {
            for &port in &ports {
                for &protocol in &protocols {
                    scan_tasks.push((*target, port, protocol));
                }
            }
        }
        
        // Randomize scan order if configured
        if self.config.scan.randomize_targets {
            use rand::seq::SliceRandom;
            let mut rng = rand::thread_rng();
            scan_tasks.shuffle(&mut rng);
            debug!("Randomized scan order");
        }
        
        // Execute scans with concurrency control
        let concurrency = self.config.scan.max_concurrent_scans.unwrap_or(100);
        let results = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let stats_ref = Arc::new(stats);
        
        let scan_stream = stream::iter(scan_tasks)
            .map(|(target, port, protocol)| {
                let probe_manager = &self.probe_manager;
                let results = Arc::clone(&results);
                let stats = Arc::clone(&stats_ref);
                let pb = pb.clone();
                
                async move {
                    let scan_result = self.scan_single_port(
                        probe_manager,
                        target,
                        port,
                        protocol,
                        &stats,
                        &pb,
                    ).await;
                    
                    if let Ok(result) = scan_result {
                        let mut results_guard = results.lock().await;
                        results_guard.push(result);
                    }
                }
            })
            .buffer_unordered(concurrency);
        
        // Collect all results
        scan_stream.collect::<Vec<_>>().await;
        
        stats_ref.end();
        pb.finish_with_message("Scan completed");
        
        let final_results = results.lock().await.clone();
        
        info!(
            "Scan completed: {} results in {:.2}s ({:.2} ports/sec)",
            final_results.len(),
            stats_ref.elapsed().unwrap_or_default().as_secs_f64(),
            stats_ref.scan_rate()
        );
        
        Ok(final_results)
    }
    
    /// Scan a single port
    async fn scan_single_port(
        &self,
        probe_manager: &ProbeManager,
        target: IpAddr,
        port: u16,
        protocol: Protocol,
        stats: &Arc<ScanStats>,
        pb: &ProgressBar,
    ) -> Result<ComprehensiveProbeResult> {
        let start_time = Instant::now();
        
        // Apply timing delays
        if let Some(delay) = self.config.timing.scan_delay {
            sleep(delay).await;
        }
        
        let result = match probe_manager.scan_port(target, port, protocol).await {
            Ok(mut result) => {
                // Update statistics based on result
                match result.state {
                    cynetmapper_core::types::PortState::Open => {
                        stats.open_ports.fetch_add(1, Ordering::Relaxed);
                    }
                    cynetmapper_core::types::PortState::Closed => {
                        stats.closed_ports.fetch_add(1, Ordering::Relaxed);
                    }
                    cynetmapper_core::types::PortState::Filtered => {
                        stats.filtered_ports.fetch_add(1, Ordering::Relaxed);
                    }
                }
                
                result.response_time = Some(start_time.elapsed());
                result
            }
            Err(e) => {
                stats.errors.fetch_add(1, Ordering::Relaxed);
                warn!("Scan failed for {}:{}/{:?}: {}", target, port, protocol, e);
                
                // Create a filtered result for failed scans
                let mut result = ComprehensiveProbeResult::new(target, port, protocol);
                result.state = cynetmapper_core::types::PortState::Filtered;
                result.error = Some(format!("Scan error: {}", e));
                result
            }
        };
        
        // Update progress
        let completed = stats.completed_ports.fetch_add(1, Ordering::Relaxed) + 1;
        let total = stats.total_ports.load(Ordering::Relaxed);
        
        // Update progress bar message
        let open_count = stats.open_ports.load(Ordering::Relaxed);
        let rate = stats.scan_rate();
        
        pb.set_message(format!(
            "{} open ports found, {:.1} ports/sec",
            open_count, rate
        ));
        pb.set_position(completed as u64);
        
        debug!(
            "Scanned {}:{}/{:?} -> {:?} ({}/{})",
            target, port, protocol, result.state, completed, total
        );
        
        Ok(result)
    }
    
    /// Perform host discovery
    pub async fn discover_hosts(
        &self,
        targets: Vec<IpAddr>,
        progress_bar: Option<ProgressBar>,
    ) -> Result<Vec<IpAddr>> {
        let mut stats = self.stats.clone();
        stats.start();
        
        stats.total_targets.store(targets.len(), Ordering::Relaxed);
        
        info!("Starting host discovery for {} targets", targets.len());
        
        // Setup progress bar
        let pb = progress_bar.unwrap_or_else(|| {
            let pb = ProgressBar::new(targets.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}")
                    .unwrap()
                    .progress_chars("#>-"),
            );
            pb
        });
        
        let discovered_hosts = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let stats_ref = Arc::new(stats);
        
        // Execute discovery with concurrency control
        let concurrency = self.config.scan.max_concurrent_scans.unwrap_or(50);
        
        let discovery_stream = stream::iter(targets)
            .map(|target| {
                let probe_manager = &self.probe_manager;
                let discovered = Arc::clone(&discovered_hosts);
                let stats = Arc::clone(&stats_ref);
                let pb = pb.clone();
                
                async move {
                    let discovery_result = probe_manager.discover_host(target).await;
                    
                    match discovery_result {
                        Ok(result) => {
                            if result.is_reachable() {
                                let mut discovered_guard = discovered.lock().await;
                                discovered_guard.push(target);
                                debug!("Host {} is up", target);
                            } else {
                                debug!("Host {} is down", target);
                            }
                        }
                        Err(e) => {
                            warn!("Discovery failed for {}: {}", target, e);
                            stats.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    
                    let completed = stats.completed_targets.fetch_add(1, Ordering::Relaxed) + 1;
                    let discovered_count = discovered.lock().await.len();
                    
                    pb.set_message(format!("{} hosts discovered", discovered_count));
                    pb.set_position(completed as u64);
                }
            })
            .buffer_unordered(concurrency);
        
        // Collect all results
        discovery_stream.collect::<Vec<_>>().await;
        
        stats_ref.end();
        pb.finish_with_message("Discovery completed");
        
        let final_hosts = discovered_hosts.lock().await.clone();
        
        info!(
            "Discovery completed: {}/{} hosts up in {:.2}s",
            final_hosts.len(),
            stats_ref.total_targets.load(Ordering::Relaxed),
            stats_ref.elapsed().unwrap_or_default().as_secs_f64()
        );
        
        Ok(final_hosts)
    }
    
    /// Perform a quick scan using common ports
    pub async fn quick_scan(
        &self,
        targets: Vec<IpAddr>,
        protocol: Protocol,
        progress_bar: Option<ProgressBar>,
    ) -> Result<Vec<ComprehensiveProbeResult>> {
        let common_ports = utils::get_top_ports(protocol, 100);
        
        info!(
            "Starting quick scan: {} targets, {} common ports",
            targets.len(),
            common_ports.len()
        );
        
        self.scan(targets, common_ports, vec![protocol], progress_bar).await
    }
    
    /// Perform a full port scan
    pub async fn full_scan(
        &self,
        targets: Vec<IpAddr>,
        protocol: Protocol,
        progress_bar: Option<ProgressBar>,
    ) -> Result<Vec<ComprehensiveProbeResult>> {
        let all_ports: Vec<u16> = (1..=65535).collect();
        
        info!(
            "Starting full scan: {} targets, all {} ports",
            targets.len(),
            all_ports.len()
        );
        
        self.scan(targets, all_ports, vec![protocol], progress_bar).await
    }
    
    /// Get scan statistics
    pub fn get_stats(&self) -> &ScanStats {
        &self.stats
    }
    
    /// Reset scan statistics
    pub fn reset_stats(&mut self) {
        self.stats = ScanStats::new();
    }
}

/// Scan profile for predefined scan configurations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanProfile {
    /// Quick scan with common ports
    Quick,
    /// Comprehensive scan with service detection
    Comprehensive,
    /// Full port range scan
    Full,
    /// Stealth scan with timing delays
    Stealth,
    /// Aggressive scan with high concurrency
    Aggressive,
}

impl ScanProfile {
    /// Get ports for this profile
    pub fn get_ports(&self, protocol: Protocol) -> Vec<u16> {
        match self {
            ScanProfile::Quick => utils::get_top_ports(protocol, 100),
            ScanProfile::Comprehensive => utils::get_top_ports(protocol, 1000),
            ScanProfile::Full => (1..=65535).collect(),
            ScanProfile::Stealth => utils::get_top_ports(protocol, 100),
            ScanProfile::Aggressive => utils::get_top_ports(protocol, 1000),
        }
    }
    
    /// Get concurrency level for this profile
    pub fn get_concurrency(&self) -> usize {
        match self {
            ScanProfile::Quick => 50,
            ScanProfile::Comprehensive => 100,
            ScanProfile::Full => 200,
            ScanProfile::Stealth => 10,
            ScanProfile::Aggressive => 500,
        }
    }
    
    /// Get scan delay for this profile
    pub fn get_delay(&self) -> Option<Duration> {
        match self {
            ScanProfile::Quick => None,
            ScanProfile::Comprehensive => None,
            ScanProfile::Full => None,
            ScanProfile::Stealth => Some(Duration::from_millis(100)),
            ScanProfile::Aggressive => None,
        }
    }
}

impl std::str::FromStr for ScanProfile {
    type Err = anyhow::Error;
    
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "quick" | "q" => Ok(ScanProfile::Quick),
            "comprehensive" | "comp" | "c" => Ok(ScanProfile::Comprehensive),
            "full" | "f" => Ok(ScanProfile::Full),
            "stealth" | "s" => Ok(ScanProfile::Stealth),
            "aggressive" | "aggr" | "a" => Ok(ScanProfile::Aggressive),
            _ => Err(anyhow::anyhow!("Unknown scan profile: {}", s)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_cli_scanner_creation() {
        let config = Arc::new(Config::default());
        let scanner = CliScanner::new(config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_scan_stats() {
        let mut stats = ScanStats::new();
        stats.start();
        
        stats.total_ports.store(100, Ordering::Relaxed);
        stats.completed_ports.store(50, Ordering::Relaxed);
        
        assert_eq!(stats.completion_percentage(), 50.0);
        
        stats.end();
        assert!(stats.elapsed().is_some());
    }

    #[test]
    fn test_scan_profile_parsing() {
        assert_eq!("quick".parse::<ScanProfile>().unwrap(), ScanProfile::Quick);
        assert_eq!("comprehensive".parse::<ScanProfile>().unwrap(), ScanProfile::Comprehensive);
        assert_eq!("full".parse::<ScanProfile>().unwrap(), ScanProfile::Full);
        assert_eq!("stealth".parse::<ScanProfile>().unwrap(), ScanProfile::Stealth);
        assert_eq!("aggressive".parse::<ScanProfile>().unwrap(), ScanProfile::Aggressive);
        assert!("invalid".parse::<ScanProfile>().is_err());
    }

    #[test]
    fn test_scan_profile_ports() {
        let quick = ScanProfile::Quick;
        let tcp_ports = quick.get_ports(Protocol::Tcp);
        assert!(!tcp_ports.is_empty());
        assert!(tcp_ports.len() <= 100);
        
        let full = ScanProfile::Full;
        let all_ports = full.get_ports(Protocol::Tcp);
        assert_eq!(all_ports.len(), 65535);
    }

    #[test]
    fn test_scan_profile_concurrency() {
        assert_eq!(ScanProfile::Quick.get_concurrency(), 50);
        assert_eq!(ScanProfile::Stealth.get_concurrency(), 10);
        assert_eq!(ScanProfile::Aggressive.get_concurrency(), 500);
    }

    #[test]
    fn test_scan_profile_delay() {
        assert!(ScanProfile::Quick.get_delay().is_none());
        assert!(ScanProfile::Stealth.get_delay().is_some());
        assert!(ScanProfile::Aggressive.get_delay().is_none());
    }

    #[tokio::test]
    async fn test_discover_hosts() {
        let config = Arc::new(Config::default());
        let scanner = CliScanner::new(config).unwrap();
        
        let targets = vec!["127.0.0.1".parse().unwrap()];
        let result = scanner.discover_hosts(targets, None).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_quick_scan() {
        let config = Arc::new(Config::default());
        let scanner = CliScanner::new(config).unwrap();
        
        let targets = vec!["127.0.0.1".parse().unwrap()];
        let result = scanner.quick_scan(targets, Protocol::Tcp, None).await;
        
        assert!(result.is_ok());
    }
}
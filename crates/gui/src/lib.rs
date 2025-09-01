//! # cyNetMapper GUI
//!
//! This crate provides the desktop GUI application for cyNetMapper using Tauri.
//! It offers a modern, cross-platform interface for network scanning and analysis.
//!
//! ## Features
//!
//! - Modern web-based UI with native performance
//! - Real-time scan progress and results
//! - Interactive network visualization
//! - Export capabilities (JSON, XML, CSV, PDF)
//! - System tray integration
//! - Auto-updater support
//! - Cross-platform (Windows, macOS, Linux)
//!
//! ## Architecture
//!
//! The GUI is built using:
//! - **Backend**: Rust with Tauri for native functionality
//! - **Frontend**: Modern web technologies (HTML, CSS, JavaScript)
//! - **Communication**: Tauri's command system for frontend-backend interaction
//! - **State Management**: Reactive state management for real-time updates

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{Manager, State, Window};
use tokio::sync::broadcast;
use uuid::Uuid;

// Core dependencies
use cynetmapper_core::{Config, NetworkScanner};
use cynetmapper_probes::{ProbeManager, ProbeManagerConfig};
use cynetmapper_outputs::ScanResults;

// GUI modules
pub mod charts;
pub mod commands;
pub mod config;
pub mod events;
pub mod state;
pub mod utils;
pub mod widgets;
// pub mod export;

// Re-exports
pub use commands::*;
pub use events::*;
pub use state::*;

/// GUI-specific error types
#[derive(Debug, thiserror::Error, Serialize)]
pub enum GuiError {
    #[error("Scan error: {0}")]
    ScanError(String),
    #[error("Configuration error: {0}")]
    ConfigError(String),
    #[error("Export error: {0}")]
    ExportError(String),
    #[error("File system error: {0}")]
    FileSystemError(String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    #[error("Operation not allowed: {0}")]
    NotAllowed(String),
}

/// GUI result type
pub type GuiResult<T> = Result<T, GuiError>;

/// Scan configuration from the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: Option<String>,
    pub scan_type: ScanType,
    pub timeout_ms: u64,
    pub max_concurrent: usize,
    pub enable_service_detection: bool,
    pub enable_os_fingerprinting: bool,
    pub enable_banner_grabbing: bool,
    pub output_format: String,
    pub output_path: Option<PathBuf>,
}

/// Scan types available in the GUI
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanType {
    Quick,
    Full,
    Custom,
    Stealth,
    Aggressive,
}

/// Real-time scan progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanProgress {
    pub scan_id: String,
    pub status: ScanStatus,
    pub progress_percentage: f64,
    pub current_target: Option<String>,
    pub targets_completed: usize,
    pub targets_total: usize,
    pub ports_scanned: usize,
    pub ports_total: usize,
    pub open_ports_found: usize,
    pub elapsed_time: Duration,
    pub estimated_remaining: Option<Duration>,
    pub scan_rate: f64, // ports per second
    pub errors: Vec<String>,
}

/// Scan status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ScanStatus {
    Pending,
    Running,
    Paused,
    Completed,
    Failed,
    Cancelled,
}

/// Application state shared between frontend and backend
#[derive(Debug)]
pub struct AppState {
    pub active_scans: Arc<Mutex<HashMap<String, ScanProgress>>>,
    pub scan_results: Arc<Mutex<HashMap<String, cynetmapper_outputs::ScanResults>>>,
    pub config: Arc<Mutex<AppConfig>>,
    pub progress_sender: broadcast::Sender<ScanProgress>,
}

/// Application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub default_timeout: u64,
    pub default_concurrency: usize,
    pub auto_save_results: bool,
    pub results_directory: PathBuf,
    pub theme: String,
    pub notifications_enabled: bool,
    pub system_tray_enabled: bool,
    pub auto_update_enabled: bool,
    pub recent_targets: Vec<String>,
    pub favorite_port_lists: HashMap<String, Vec<u16>>,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            default_timeout: 5000,
            default_concurrency: 100,
            auto_save_results: true,
            results_directory: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("cyNetMapper"),
            theme: "dark".to_string(),
            notifications_enabled: true,
            system_tray_enabled: true,
            auto_update_enabled: true,
            recent_targets: Vec::new(),
            favorite_port_lists: HashMap::new(),
        }
    }
}

/// Host information for the GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiHostInfo {
    pub address: String,
    pub hostname: Option<String>,
    pub state: String,
    pub ports: Vec<GuiPortInfo>,
    pub os_fingerprint: Option<GuiOsFingerprint>,
    pub response_time: Option<Duration>,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

/// Port information for the GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiPortInfo {
    pub port: u16,
    pub protocol: String,
    pub state: String,
    pub service: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub response_time: Option<Duration>,
    pub confidence: Option<f64>,
}

/// OS fingerprint information for the GUI
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiOsFingerprint {
    pub family: String,
    pub version: Option<String>,
    pub device_type: Option<String>,
    pub confidence: f64,
    pub details: HashMap<String, String>,
}

/// Chart data for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartData {
    pub labels: Vec<String>,
    pub datasets: Vec<ChartDataset>,
}

/// Chart dataset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartDataset {
    pub label: String,
    pub data: Vec<f64>,
    pub background_color: Option<String>,
    pub border_color: Option<String>,
}

/// Network topology data for visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkTopology {
    pub nodes: Vec<NetworkNode>,
    pub edges: Vec<NetworkEdge>,
}

/// Network node for topology visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkNode {
    pub id: String,
    pub label: String,
    pub node_type: String,
    pub status: String,
    pub properties: HashMap<String, String>,
}

/// Network edge for topology visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkEdge {
    pub from: String,
    pub to: String,
    pub label: Option<String>,
    pub edge_type: String,
    pub properties: HashMap<String, String>,
}

impl AppState {
    /// Create a new application state
    pub fn new() -> Self {
        let (progress_sender, _) = broadcast::channel(1000);
        
        Self {
            active_scans: Arc::new(Mutex::new(HashMap::new())),
            scan_results: Arc::new(Mutex::new(HashMap::new())),
            config: Arc::new(Mutex::new(AppConfig::default())),
            progress_sender,
        }
    }
    
    /// Start a new scan
    pub async fn start_scan(
        &self,
        config: ScanConfig,
        window: Window,
    ) -> Result<String, GuiError> {
        let scan_id = Uuid::new_v4().to_string();
        
        // Create initial progress
        let progress = ScanProgress {
            scan_id: scan_id.clone(),
            status: ScanStatus::Pending,
            progress_percentage: 0.0,
            current_target: None,
            targets_completed: 0,
            targets_total: config.targets.len(),
            ports_scanned: 0,
            ports_total: 0,
            open_ports_found: 0,
            elapsed_time: Duration::from_secs(0),
            estimated_remaining: None,
            scan_rate: 0.0,
            errors: Vec::new(),
        };
        
        // Add to active scans
        self.active_scans.lock().unwrap().insert(scan_id.clone(), progress.clone());
        
        // Emit initial progress
        let _ = self.progress_sender.send(progress.clone());
        let _ = window.emit("scan-progress", &progress);
        
        // Start the actual scan in a background task
        let state = self.clone();
        let scan_id_clone = scan_id.clone();
        tokio::spawn(async move {
            if let Err(e) = state.execute_scan(scan_id_clone, config, window).await {
                tracing::error!("Scan execution failed: {}", e);
            }
        });
        
        Ok(scan_id)
    }
    
    /// Execute the actual scan
    async fn execute_scan(
        &self,
        scan_id: String,
        config: ScanConfig,
        window: Window,
    ) -> GuiResult<()> {
        let start_time = Instant::now();
        
        // Update status to running
        self.update_scan_progress(&scan_id, |progress| {
            progress.status = ScanStatus::Running;
        });
        
        // Create core config from scan config
        let mut core_config = Config::default();
        core_config.timing.connect_timeout = Duration::from_millis(config.timeout_ms);
        core_config.scan.max_concurrency = config.max_concurrent;
        let core_config = Arc::new(core_config);
        
        // Create probe manager
        let probe_manager = ProbeManager::new(core_config.clone())
            .map_err(|e| GuiError::ScanError(e.to_string()))?;
        
        // Create network scanner
        let mut network_scanner = NetworkScanner::new(Duration::from_millis(config.timeout_ms));
        
        // Parse targets
        let mut targets = Vec::new();
        for target_str in &config.targets {
            // Try to parse as CIDR first
            if target_str.contains('/') {
                match self.parse_cidr(target_str) {
                    Ok(cidr_ips) => {
                        targets.extend(cidr_ips);
                        continue;
                    },
                    Err(e) => {
                        tracing::warn!("Failed to parse CIDR {}: {}", target_str, e);
                        self.update_scan_progress(&scan_id, |progress| {
                            progress.errors.push(format!("Failed to parse CIDR {}: {}", target_str, e));
                        });
                        continue;
                    }
                }
            }
            
            // Try to parse as single IP
            match target_str.parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    use cynetmapper_core::types::IpAddr;
                    let core_ip = match ip {
                        std::net::IpAddr::V4(v4) => IpAddr::V4(v4),
                        std::net::IpAddr::V6(v6) => IpAddr::V6(v6),
                    };
                    targets.push(core_ip);
                },
                Err(_) => {
                    // Try to resolve hostname
                    match network_scanner.resolve_hostname(target_str).await {
                        Ok(dns_result) => {
                            targets.extend(dns_result.addresses);
                        },
                        Err(e) => {
                            tracing::warn!("Failed to resolve {}: {}", target_str, e);
                            self.update_scan_progress(&scan_id, |progress| {
                                progress.errors.push(format!("Failed to resolve {}: {}", target_str, e));
                            });
                        }
                    }
                }
            }
        }
        
        if targets.is_empty() {
            self.update_scan_progress(&scan_id, |progress| {
                progress.status = ScanStatus::Failed;
                progress.errors.push("No valid targets found".to_string());
            });
            return Err(GuiError::ScanError("No valid targets found".to_string()));
        }
        
        // Parse ports
        let ports = if let Some(port_str) = &config.ports {
            self.parse_ports(port_str)?
        } else {
            // Default common ports
            vec![22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        };
        
        // Update progress with totals
        let total_combinations = targets.len() * ports.len();
        self.update_scan_progress(&scan_id, |progress| {
            progress.targets_total = targets.len();
            progress.ports_total = total_combinations;
        });
        
        // Execute scan using probe manager
        let mut scan_results: Vec<GuiHostInfo> = Vec::new();
        let mut completed_scans = 0;
        
        for (target_idx, target) in targets.iter().enumerate() {
            // Update current target
            self.update_scan_progress(&scan_id, |progress| {
                progress.current_target = Some(target.to_string());
                progress.targets_completed = target_idx;
            });
            
            for port in &ports {
                // Check if scan was cancelled
                {
                    let scans = self.active_scans.lock().unwrap();
                    if let Some(progress) = scans.get(&scan_id) {
                        if progress.status == ScanStatus::Cancelled {
                            return Ok(());
                        }
                    }
                }
                
                // Perform TCP connect scan
                let socket_addr = match target {
                    cynetmapper_core::types::IpAddr::V4(ip) => {
                        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(*ip, *port))
                    },
                    cynetmapper_core::types::IpAddr::V6(ip) => {
                        std::net::SocketAddr::V6(std::net::SocketAddrV6::new(*ip, *port, 0, 0))
                    },
                };
                
                let is_open = tokio::time::timeout(
                    Duration::from_millis(config.timeout_ms),
                    tokio::net::TcpStream::connect(socket_addr)
                ).await.is_ok_and(|result| result.is_ok());
                
                if is_open {
                    self.update_scan_progress(&scan_id, |progress| {
                        progress.open_ports_found += 1;
                    });
                }
                
                completed_scans += 1;
                
                // Update progress
                self.update_scan_progress(&scan_id, |progress| {
                    progress.ports_scanned = completed_scans;
                    progress.progress_percentage = (completed_scans as f64 / total_combinations as f64) * 100.0;
                    progress.elapsed_time = start_time.elapsed();
                    
                    // Calculate scan rate
                    let elapsed_secs = progress.elapsed_time.as_secs_f64();
                    if elapsed_secs > 0.0 {
                        progress.scan_rate = completed_scans as f64 / elapsed_secs;
                    }
                    
                    // Estimate remaining time
                    if progress.scan_rate > 0.0 {
                        let remaining_scans = total_combinations - completed_scans;
                        let remaining_secs = remaining_scans as f64 / progress.scan_rate;
                        progress.estimated_remaining = Some(Duration::from_secs_f64(remaining_secs));
                    }
                });
                
                // Emit progress update to frontend
                if let Ok(scans) = self.active_scans.lock() {
                    if let Some(progress) = scans.get(&scan_id) {
                        let _ = window.emit("scan-progress", progress);
                    }
                }
                
                // Small delay to prevent overwhelming the system
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        
        // Create scan results
        let results = ScanResults::default();
        
        // Store results
        self.scan_results.lock().unwrap().insert(scan_id.clone(), results.clone());
        
        // Update final progress
        self.update_scan_progress(&scan_id, |progress| {
            progress.status = ScanStatus::Completed;
            progress.progress_percentage = 100.0;
            progress.elapsed_time = start_time.elapsed();
            progress.targets_completed = targets.len();
        });
        
        // Emit completion event
        let _ = window.emit("scan-completed", &scan_id);
        
        Ok(())
    }
    
    /// Update scan progress
    fn update_scan_progress<F>(&self, scan_id: &str, updater: F)
    where
        F: FnOnce(&mut ScanProgress),
    {
        if let Ok(mut scans) = self.active_scans.lock() {
            if let Some(progress) = scans.get_mut(scan_id) {
                updater(progress);
                let _ = self.progress_sender.send(progress.clone());
            }
        }
    }
    
    /// Convert GUI scan config to probe manager config
    fn convert_scan_config(&self, config: &ScanConfig) -> GuiResult<Config> {
        let mut core_config = Config::default();
        
        // Map GUI config to core config
        core_config.timing.connect_timeout = Duration::from_millis(config.timeout_ms);
        core_config.scan.max_concurrency = config.max_concurrent;
        
        Ok(core_config)
    }
    
    /// Parse port specification string
    fn parse_ports(&self, port_str: &str) -> GuiResult<Vec<u16>> {
        let mut ports = std::collections::HashSet::new();
        
        for part in port_str.split(',') {
            let part = part.trim();
            
            if part.is_empty() {
                continue;
            }
            
            if part.contains('-') {
                // Parse port range
                let range_parts: Vec<&str> = part.split('-').collect();
                if range_parts.len() != 2 {
                    return Err(GuiError::InvalidInput(format!("Invalid port range format: {}", part)));
                }
                
                let start: u16 = range_parts[0].trim().parse()
                    .map_err(|_| GuiError::InvalidInput(format!("Invalid start port in range: {}", part)))?;
                let end: u16 = range_parts[1].trim().parse()
                    .map_err(|_| GuiError::InvalidInput(format!("Invalid end port in range: {}", part)))?;
                
                if start > end {
                    return Err(GuiError::InvalidInput(format!("Invalid port range: start ({}) > end ({})", start, end)));
                }
                
                for port in start..=end {
                    ports.insert(port);
                }
            } else {
                // Parse single port
                let port: u16 = part.parse()
                    .map_err(|_| GuiError::InvalidInput(format!("Invalid port number: {}", part)))?;
                ports.insert(port);
            }
        }
        
        if ports.is_empty() {
            return Err(GuiError::InvalidInput("No valid ports found".to_string()));
        }
        
        let mut result: Vec<u16> = ports.into_iter().collect();
        result.sort();
        Ok(result)
    }
    
    fn parse_cidr(&self, cidr: &str) -> GuiResult<Vec<cynetmapper_core::types::IpAddr>> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(GuiError::InvalidInput(format!("Invalid CIDR format: {}", cidr)));
        }
        
        let base_ip = parts[0].parse::<std::net::IpAddr>()
            .map_err(|_| GuiError::InvalidInput(format!("Invalid IP in CIDR: {}", parts[0])))?;
        let prefix_len: u8 = parts[1].parse()
            .map_err(|_| GuiError::InvalidInput(format!("Invalid prefix length in CIDR: {}", parts[1])))?;
        
        match base_ip {
            std::net::IpAddr::V4(ipv4) => {
                if prefix_len > 32 {
                    return Err(GuiError::InvalidInput(format!("Invalid IPv4 prefix length: {}", prefix_len)));
                }
                self.parse_ipv4_cidr(ipv4, prefix_len)
            }
            std::net::IpAddr::V6(ipv6) => {
                if prefix_len > 128 {
                    return Err(GuiError::InvalidInput(format!("Invalid IPv6 prefix length: {}", prefix_len)));
                }
                self.parse_ipv6_cidr(ipv6, prefix_len)
            }
        }
    }
    
    fn parse_ipv4_cidr(&self, base_ip: std::net::Ipv4Addr, prefix_len: u8) -> GuiResult<Vec<cynetmapper_core::types::IpAddr>> {
        use cynetmapper_core::types::IpAddr;
        let mut ips = Vec::new();
        
        if prefix_len == 32 {
            ips.push(IpAddr::V4(base_ip));
            return Ok(ips);
        }
        
        let host_bits = 32 - prefix_len;
        let num_hosts = 1u32 << host_bits;
        
        // Limit the number of IPs to prevent memory issues
        if num_hosts > 65536 {
            return Err(GuiError::InvalidInput(format!("CIDR range too large (>{} hosts). Use smaller ranges.", 65536)));
        }
        
        let base_u32 = u32::from(base_ip);
        let network_mask = !((1u32 << host_bits) - 1);
        let network_base = base_u32 & network_mask;
        
        for i in 0..num_hosts {
            let ip_u32 = network_base + i;
            let ip = std::net::Ipv4Addr::from(ip_u32);
            ips.push(IpAddr::V4(ip));
        }
        
        Ok(ips)
    }
    
    fn parse_ipv6_cidr(&self, base_ip: std::net::Ipv6Addr, _prefix_len: u8) -> GuiResult<Vec<cynetmapper_core::types::IpAddr>> {
        use cynetmapper_core::types::IpAddr;
        // For IPv6, we'll only support /128 (single host) for now
        if _prefix_len == 128 {
            Ok(vec![IpAddr::V6(base_ip)])
        } else {
            Err(GuiError::InvalidInput("IPv6 CIDR ranges other than /128 are not supported yet".to_string()))
        }
    }
}

impl Clone for AppState {
    fn clone(&self) -> Self {
        Self {
            active_scans: self.active_scans.clone(),
            scan_results: self.scan_results.clone(),
            config: self.config.clone(),
            progress_sender: self.progress_sender.clone(),
        }
    }
}

/// Initialize the GUI application
pub fn init_app() -> tauri::Builder<tauri::Wry> {
    let app_state = AppState::new();
    
    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            commands::start_scan,
            commands::stop_scan,
            commands::pause_scan,
            commands::resume_scan,
            commands::get_scan_progress,
            commands::get_active_scans,
            commands::get_scan_results,
            commands::export_results,
            commands::get_config,
            commands::update_config,
            commands::get_chart_data,
            commands::get_network_topology,
            commands::validate_scan_config,
            commands::get_system_info
        ])
        .setup(|app| {
            // Setup system tray if enabled
            #[cfg(feature = "system-tray")]
            setup_system_tray(app)?;
            
            // Setup auto-updater if enabled
            #[cfg(feature = "auto-updater")]
            setup_auto_updater(app)?;
            
            // Create results directory
            let app_state: State<AppState> = app.state();
            let config = app_state.config.lock().unwrap();
            if let Err(e) = std::fs::create_dir_all(&config.results_directory) {
                tracing::warn!("Failed to create results directory: {}", e);
            }
            
            Ok(())
        })
}

/// Setup system tray
#[cfg(feature = "system-tray")]
fn setup_system_tray(_app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // System tray functionality disabled - plugin not available
    Ok(())
}

/// Setup auto-updater
#[cfg(feature = "auto-updater")]
fn setup_auto_updater(_app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    // Auto-updater functionality disabled - plugin not available
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_state_creation() {
        let state = AppState::new();
        assert!(state.active_scans.lock().unwrap().is_empty());
        assert!(state.scan_results.lock().unwrap().is_empty());
    }

    #[test]
    fn test_app_config_default() {
        let config = AppConfig::default();
        assert_eq!(config.default_timeout, 5000);
        assert_eq!(config.default_concurrency, 100);
        assert!(config.auto_save_results);
        assert_eq!(config.theme, "dark");
    }

    #[test]
    fn test_scan_config_serialization() {
        let config = ScanConfig {
            targets: vec!["192.168.1.1".to_string()],
            ports: Some("80,443".to_string()),
            scan_type: ScanType::Quick,
            timeout_ms: 5000,
            max_concurrent: 100,
            enable_service_detection: true,
            enable_os_fingerprinting: false,
            enable_banner_grabbing: true,
            output_format: "json".to_string(),
            output_path: None,
        };
        
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: ScanConfig = serde_json::from_str(&json).unwrap();
        
        assert_eq!(config.targets, deserialized.targets);
        assert_eq!(config.timeout_ms, deserialized.timeout_ms);
    }

    #[test]
    fn test_scan_progress_creation() {
        let progress = ScanProgress {
            scan_id: "test-123".to_string(),
            status: ScanStatus::Running,
            progress_percentage: 50.0,
            current_target: Some("192.168.1.1".to_string()),
            targets_completed: 1,
            targets_total: 2,
            ports_scanned: 500,
            ports_total: 1000,
            open_ports_found: 5,
            elapsed_time: Duration::from_secs(30),
            estimated_remaining: Some(Duration::from_secs(30)),
            scan_rate: 16.67,
            errors: Vec::new(),
        };
        
        assert_eq!(progress.scan_id, "test-123");
        assert_eq!(progress.status, ScanStatus::Running);
        assert_eq!(progress.progress_percentage, 50.0);
    }
}
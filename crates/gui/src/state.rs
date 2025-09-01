//! State management for the cyNetMapper GUI
//!
//! This module provides centralized state management for the application,
//! including scan state, configuration, and UI state persistence.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::{
    AppConfig, GuiError, GuiResult, ScanConfig, ScanProgress, ScanStatus,
    GuiHostInfo, events::GuiEvent,
};
use cynetmapper_core::ScanResults;

/// Global application state
#[derive(Debug)]
pub struct GlobalState {
    /// Active scans with their progress
    pub scans: Arc<RwLock<HashMap<String, ScanState>>>,
    /// Application configuration
    pub config: Arc<RwLock<AppConfig>>,
    /// UI state
    pub ui_state: Arc<RwLock<UiState>>,
    /// Event broadcaster
    pub event_sender: broadcast::Sender<GuiEvent>,
    /// Scan history
    pub scan_history: Arc<RwLock<Vec<ScanHistoryEntry>>>,
    /// Performance metrics
    pub metrics: Arc<RwLock<PerformanceMetrics>>,
}

/// State for an individual scan
#[derive(Debug, Clone)]
pub struct ScanState {
    pub id: String,
    pub config: ScanConfig,
    pub progress: ScanProgress,
    pub results: Option<ScanResults>,
    pub start_time: Instant,
    pub end_time: Option<Instant>,
    pub error: Option<String>,
    pub statistics: ScanStatistics,
}

/// UI state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiState {
    /// Current theme
    pub theme: String,
    /// Window dimensions
    pub window_size: (u32, u32),
    /// Window position
    pub window_position: (i32, i32),
    /// Panel visibility
    pub panels: PanelState,
    /// Recent targets
    pub recent_targets: Vec<String>,
    /// Favorite configurations
    pub favorite_configs: Vec<NamedScanConfig>,
    /// View preferences
    pub view_preferences: ViewPreferences,
    /// Last used directories
    pub last_directories: HashMap<String, PathBuf>,
}

/// Panel visibility state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelState {
    pub sidebar_visible: bool,
    pub results_panel_visible: bool,
    pub charts_panel_visible: bool,
    pub logs_panel_visible: bool,
    pub network_view_visible: bool,
}

/// Named scan configuration for favorites
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedScanConfig {
    pub name: String,
    pub description: Option<String>,
    pub config: ScanConfig,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
    pub use_count: usize,
}

/// View preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewPreferences {
    pub default_view: String,
    pub auto_refresh_interval: u64,
    pub show_closed_ports: bool,
    pub show_filtered_ports: bool,
    pub group_by_host: bool,
    pub sort_order: String,
    pub chart_type: String,
    pub network_layout: String,
}

/// Scan history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanHistoryEntry {
    pub id: String,
    pub name: Option<String>,
    pub config: ScanConfig,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub end_time: Option<chrono::DateTime<chrono::Utc>>,
    pub status: ScanStatus,
    pub hosts_found: usize,
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub duration: Option<Duration>,
    pub file_path: Option<PathBuf>,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub total_scans: usize,
    pub successful_scans: usize,
    pub failed_scans: usize,
    pub total_hosts_scanned: usize,
    pub total_ports_scanned: usize,
    pub total_scan_time: Duration,
    pub average_scan_rate: f64,
    pub peak_scan_rate: f64,
    pub memory_usage: MemoryUsage,
}

/// Memory usage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryUsage {
    pub current_mb: f64,
    pub peak_mb: f64,
    pub average_mb: f64,
}

/// Scan statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanStatistics {
    pub hosts_discovered: usize,
    pub hosts_up: usize,
    pub hosts_down: usize,
    pub ports_open: usize,
    pub ports_closed: usize,
    pub ports_filtered: usize,
    pub services_identified: usize,
    pub os_fingerprints: usize,
    pub scan_rate: f64,
    pub data_transferred: u64,
}

impl Default for UiState {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            window_size: (1200, 800),
            window_position: (100, 100),
            panels: PanelState::default(),
            recent_targets: Vec::new(),
            favorite_configs: Vec::new(),
            view_preferences: ViewPreferences::default(),
            last_directories: HashMap::new(),
        }
    }
}

impl Default for PanelState {
    fn default() -> Self {
        Self {
            sidebar_visible: true,
            results_panel_visible: true,
            charts_panel_visible: false,
            logs_panel_visible: false,
            network_view_visible: false,
        }
    }
}

impl Default for ViewPreferences {
    fn default() -> Self {
        Self {
            default_view: "table".to_string(),
            auto_refresh_interval: 1000,
            show_closed_ports: false,
            show_filtered_ports: false,
            group_by_host: true,
            sort_order: "address".to_string(),
            chart_type: "bar".to_string(),
            network_layout: "force".to_string(),
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            total_scans: 0,
            successful_scans: 0,
            failed_scans: 0,
            total_hosts_scanned: 0,
            total_ports_scanned: 0,
            total_scan_time: Duration::from_secs(0),
            average_scan_rate: 0.0,
            peak_scan_rate: 0.0,
            memory_usage: MemoryUsage::default(),
        }
    }
}

impl Default for MemoryUsage {
    fn default() -> Self {
        Self {
            current_mb: 0.0,
            peak_mb: 0.0,
            average_mb: 0.0,
        }
    }
}

impl Default for ScanStatistics {
    fn default() -> Self {
        Self {
            hosts_discovered: 0,
            hosts_up: 0,
            hosts_down: 0,
            ports_open: 0,
            ports_closed: 0,
            ports_filtered: 0,
            services_identified: 0,
            os_fingerprints: 0,
            scan_rate: 0.0,
            data_transferred: 0,
        }
    }
}

impl GlobalState {
    /// Create a new global state
    pub fn new() -> Self {
        let (event_sender, _) = broadcast::channel(1000);
        
        Self {
            scans: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(AppConfig::default())),
            ui_state: Arc::new(RwLock::new(UiState::default())),
            event_sender,
            scan_history: Arc::new(RwLock::new(Vec::new())),
            metrics: Arc::new(RwLock::new(PerformanceMetrics::default())),
        }
    }

    /// Add a new scan
    pub fn add_scan(&self, scan_state: ScanState) -> GuiResult<()> {
        let mut scans = self.scans.write().map_err(|_| {
            GuiError::ScanError("Failed to acquire write lock on scans".to_string())
        })?;
        scans.insert(scan_state.id.clone(), scan_state);
        Ok(())
    }

    /// Update scan progress
    pub fn update_scan_progress(&self, scan_id: &str, progress: ScanProgress) -> GuiResult<()> {
        let mut scans = self.scans.write().map_err(|_| {
            GuiError::ScanError("Failed to acquire write lock on scans".to_string())
        })?;
        
        if let Some(scan_state) = scans.get_mut(scan_id) {
            scan_state.progress = progress.clone();
            
            // Emit progress event
            let _ = self.event_sender.send(crate::events::GuiEvent::ScanProgress(progress));
        }
        
        Ok(())
    }

    /// Complete a scan
    pub fn complete_scan(
        &self,
        scan_id: &str,
        results: Option<ScanResults>,
        error: Option<String>,
    ) -> GuiResult<()> {
        let mut scans = self.scans.write().map_err(|_| {
            GuiError::ScanError("Failed to acquire write lock on scans".to_string())
        })?;
        
        if let Some(scan_state) = scans.get_mut(scan_id) {
            scan_state.end_time = Some(Instant::now());
            scan_state.results = results.clone();
            scan_state.error = error.clone();
            
            let success = error.is_none();
            scan_state.progress.status = if success {
                ScanStatus::Completed
            } else {
                ScanStatus::Failed
            };
            
            // Add to history
            self.add_to_history(scan_state)?;
            
            // Update metrics
            self.update_metrics(scan_state)?;
            
            // Emit completion event
            let _ = self.event_sender.send(crate::events::GuiEvent::ScanCompleted {
                scan_id: scan_id.to_string(),
                success,
                message: error,
            });
        }
        
        Ok(())
    }

    /// Get scan state
    pub fn get_scan(&self, scan_id: &str) -> GuiResult<Option<ScanState>> {
        let scans = self.scans.read().map_err(|_| {
            GuiError::ScanError("Failed to acquire read lock on scans".to_string())
        })?;
        Ok(scans.get(scan_id).cloned())
    }

    /// Get all active scans
    pub fn get_active_scans(&self) -> GuiResult<Vec<ScanState>> {
        let scans = self.scans.read().map_err(|_| {
            GuiError::ScanError("Failed to acquire read lock on scans".to_string())
        })?;
        Ok(scans.values().cloned().collect())
    }

    /// Remove completed scans
    pub fn cleanup_completed_scans(&self) -> GuiResult<()> {
        let mut scans = self.scans.write().map_err(|_| {
            GuiError::ScanError("Failed to acquire write lock on scans".to_string())
        })?;
        
        scans.retain(|_, scan| {
            !matches!(scan.progress.status, ScanStatus::Completed | ScanStatus::Failed | ScanStatus::Cancelled)
        });
        
        Ok(())
    }

    /// Add scan to history
    fn add_to_history(&self, scan_state: &ScanState) -> GuiResult<()> {
        let mut history = self.scan_history.write().map_err(|_| {
            GuiError::ScanError("Failed to acquire write lock on history".to_string())
        })?;
        
        let duration = scan_state.end_time.map(|end| end.duration_since(scan_state.start_time));
        
        let entry = ScanHistoryEntry {
            id: scan_state.id.clone(),
            name: None, // Could be derived from config or user input
            config: scan_state.config.clone(),
            start_time: chrono::DateTime::from_timestamp(
                scan_state.start_time.elapsed().as_secs() as i64, 0
            ).unwrap_or_else(chrono::Utc::now),
            end_time: scan_state.end_time.map(|_| chrono::Utc::now()),
            status: scan_state.progress.status.clone(),
            hosts_found: scan_state.statistics.hosts_discovered,
            ports_scanned: scan_state.progress.ports_scanned,
            open_ports: scan_state.statistics.ports_open,
            duration,
            file_path: scan_state.config.output_path.clone(),
        };
        
        history.push(entry);
        
        // Keep only last 100 entries
        if history.len() > 100 {
            history.remove(0);
        }
        
        Ok(())
    }

    /// Update performance metrics
    fn update_metrics(&self, scan_state: &ScanState) -> GuiResult<()> {
        let mut metrics = self.metrics.write().map_err(|_| {
            GuiError::ScanError("Failed to acquire write lock on metrics".to_string())
        })?;
        
        metrics.total_scans += 1;
        
        if scan_state.error.is_none() {
            metrics.successful_scans += 1;
        } else {
            metrics.failed_scans += 1;
        }
        
        metrics.total_hosts_scanned += scan_state.statistics.hosts_discovered;
        metrics.total_ports_scanned += scan_state.progress.ports_scanned;
        
        if let Some(end_time) = scan_state.end_time {
            let duration = end_time.duration_since(scan_state.start_time);
            metrics.total_scan_time += duration;
            
            // Update scan rate
            if scan_state.statistics.scan_rate > metrics.peak_scan_rate {
                metrics.peak_scan_rate = scan_state.statistics.scan_rate;
            }
            
            // Calculate average scan rate
            if metrics.total_scan_time.as_secs() > 0 {
                metrics.average_scan_rate = metrics.total_ports_scanned as f64 
                    / metrics.total_scan_time.as_secs_f64();
            }
        }
        
        Ok(())
    }

    /// Save UI state to file
    pub fn save_ui_state(&self, path: &PathBuf) -> GuiResult<()> {
        let ui_state = self.ui_state.read().map_err(|_| {
            GuiError::FileSystemError("Failed to acquire read lock on UI state".to_string())
        })?;
        
        let json = serde_json::to_string_pretty(&*ui_state)
            .map_err(|e| GuiError::FileSystemError(format!("Failed to serialize UI state: {}", e)))?;
        
        std::fs::write(path, json)
            .map_err(|e| GuiError::FileSystemError(format!("Failed to write UI state: {}", e)))?;
        
        Ok(())
    }

    /// Load UI state from file
    pub fn load_ui_state(&self, path: &PathBuf) -> GuiResult<()> {
        if !path.exists() {
            return Ok(()); // Use default state
        }
        
        let json = std::fs::read_to_string(path)
            .map_err(|e| GuiError::FileSystemError(format!("Failed to read UI state: {}", e)))?;
        
        let loaded_state: UiState = serde_json::from_str(&json)
            .map_err(|e| GuiError::FileSystemError(format!("Failed to deserialize UI state: {}", e)))?;
        
        let mut ui_state = self.ui_state.write().map_err(|_| {
            GuiError::FileSystemError("Failed to acquire write lock on UI state".to_string())
        })?;
        
        *ui_state = loaded_state;
        
        Ok(())
    }

    /// Get event receiver
    pub fn subscribe_events(&self) -> broadcast::Receiver<GuiEvent> {
        self.event_sender.subscribe()
    }
}

impl ScanState {
    /// Create a new scan state
    pub fn new(id: String, config: ScanConfig) -> Self {
        Self {
            progress: ScanProgress {
                scan_id: id.clone(),
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
            },
            id,
            config,
            results: None,
            start_time: Instant::now(),
            end_time: None,
            error: None,
            statistics: ScanStatistics::default(),
        }
    }

    /// Update statistics from scan results
    pub fn update_statistics(&mut self, results: &ScanResults) {
        self.statistics.hosts_discovered = results.hosts.len();
        
        for host in &results.hosts {
            match host.state {
                cynetmapper_core::types::HostState::Up => self.statistics.hosts_up += 1,
                cynetmapper_core::types::HostState::Down => self.statistics.hosts_down += 1,
                _ => {},
            }
        }
        
        // Update port statistics from port results
        for port in &results.ports {
            match port.state {
                cynetmapper_core::types::PortState::Open => self.statistics.ports_open += 1,
                cynetmapper_core::types::PortState::Closed => self.statistics.ports_closed += 1,
                cynetmapper_core::types::PortState::Filtered => self.statistics.ports_filtered += 1,
                _ => {},
            }
        }
        
        // Update service statistics
        self.statistics.services_identified = results.services.len();
        
        // Update OS fingerprint statistics
        self.statistics.os_fingerprints = results.os_fingerprints.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_state_creation() {
        let state = GlobalState::new();
        assert!(state.get_active_scans().unwrap().is_empty());
    }

    #[test]
    fn test_scan_state_creation() {
        let config = ScanConfig {
            targets: vec!["192.168.1.1".to_string()],
            ports: None,
            scan_type: crate::ScanType::Quick,
            timeout_ms: 1000,
            max_concurrent: 100,
            enable_service_detection: true,
            enable_os_fingerprinting: false,
            enable_banner_grabbing: true,
            output_format: "json".to_string(),
            output_path: None,
        };
        
        let scan_state = ScanState::new("test-scan".to_string(), config);
        assert_eq!(scan_state.id, "test-scan");
        assert_eq!(scan_state.progress.targets_total, 1);
    }

    #[test]
    fn test_ui_state_default() {
        let ui_state = UiState::default();
        assert_eq!(ui_state.theme, "dark");
        assert_eq!(ui_state.window_size, (1200, 800));
        assert!(ui_state.panels.sidebar_visible);
    }
}
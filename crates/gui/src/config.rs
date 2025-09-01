//! Configuration management for the cyNetMapper GUI
//!
//! This module handles loading, saving, and managing application configuration,
//! including user preferences, scan defaults, and application settings.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{GuiError, GuiResult, ScanType};

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuiConfig {
    /// Application settings
    pub app: AppSettings,
    /// Default scan configuration
    pub scan_defaults: ScanDefaults,
    /// UI preferences
    pub ui: UiPreferences,
    /// Export settings
    pub export: ExportSettings,
    /// Network settings
    pub network: NetworkSettings,
    /// Security settings
    pub security: SecuritySettings,
    /// Performance settings
    pub performance: PerformanceSettings,
}

/// Application-level settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Application theme (dark, light, auto)
    pub theme: String,
    /// Language code (en, es, fr, etc.)
    pub language: String,
    /// Enable system tray
    pub system_tray_enabled: bool,
    /// Enable auto-updates
    pub auto_update_enabled: bool,
    /// Enable notifications
    pub notifications_enabled: bool,
    /// Minimize to tray on close
    pub minimize_to_tray: bool,
    /// Start minimized
    pub start_minimized: bool,
    /// Auto-save results
    pub auto_save_results: bool,
    /// Results directory
    pub results_directory: PathBuf,
    /// Log level (trace, debug, info, warn, error)
    pub log_level: String,
    /// Enable crash reporting
    pub crash_reporting: bool,
    /// Check for updates on startup
    pub check_updates_on_startup: bool,
}

/// Default scan configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDefaults {
    /// Default scan type
    pub scan_type: ScanType,
    /// Default timeout in milliseconds
    pub timeout_ms: u64,
    /// Default maximum concurrent connections
    pub max_concurrent: usize,
    /// Default port range
    pub default_ports: String,
    /// Enable service detection by default
    pub enable_service_detection: bool,
    /// Enable OS fingerprinting by default
    pub enable_os_fingerprinting: bool,
    /// Enable banner grabbing by default
    pub enable_banner_grabbing: bool,
    /// Default output format
    pub output_format: String,
    /// Enable reverse DNS lookup
    pub enable_reverse_dns: bool,
    /// Default scan rate limit (packets per second)
    pub rate_limit: Option<u32>,
    /// Default retry count
    pub retry_count: u32,
}

/// UI preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiPreferences {
    /// Window dimensions
    pub window_size: (u32, u32),
    /// Window position
    pub window_position: Option<(i32, i32)>,
    /// Window state (normal, maximized, minimized)
    pub window_state: String,
    /// Default view mode (table, cards, network)
    pub default_view: String,
    /// Auto-refresh interval in milliseconds
    pub auto_refresh_interval: u64,
    /// Show closed ports
    pub show_closed_ports: bool,
    /// Show filtered ports
    pub show_filtered_ports: bool,
    /// Group results by host
    pub group_by_host: bool,
    /// Default sort column
    pub sort_column: String,
    /// Sort order (asc, desc)
    pub sort_order: String,
    /// Panel visibility
    pub panels: PanelVisibility,
    /// Chart preferences
    pub charts: ChartPreferences,
    /// Color scheme
    pub colors: ColorScheme,
    /// Font settings
    pub fonts: FontSettings,
}

/// Panel visibility settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PanelVisibility {
    pub sidebar: bool,
    pub results: bool,
    pub charts: bool,
    pub logs: bool,
    pub network_view: bool,
    pub statistics: bool,
}

/// Chart preferences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartPreferences {
    /// Default chart type (bar, pie, line, doughnut)
    pub default_type: String,
    /// Animation enabled
    pub animations: bool,
    /// Show legends
    pub show_legends: bool,
    /// Show tooltips
    pub show_tooltips: bool,
    /// Color palette
    pub color_palette: Vec<String>,
}

/// Color scheme settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    /// Primary color
    pub primary: String,
    /// Secondary color
    pub secondary: String,
    /// Success color
    pub success: String,
    /// Warning color
    pub warning: String,
    /// Error color
    pub error: String,
    /// Background color
    pub background: String,
    /// Surface color
    pub surface: String,
    /// Text color
    pub text: String,
}

/// Font settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FontSettings {
    /// Font family
    pub family: String,
    /// Font size
    pub size: u32,
    /// Monospace font for code/data
    pub monospace_family: String,
    /// Monospace font size
    pub monospace_size: u32,
}

/// Export settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSettings {
    /// Default export format
    pub default_format: String,
    /// Include closed ports in exports
    pub include_closed_ports: bool,
    /// Include filtered ports in exports
    pub include_filtered_ports: bool,
    /// Include timestamps
    pub include_timestamps: bool,
    /// Include scan configuration
    pub include_scan_config: bool,
    /// Compress exports
    pub compress_exports: bool,
    /// Export directory
    pub export_directory: PathBuf,
    /// Filename template
    pub filename_template: String,
}

/// Network settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// Use system proxy
    pub use_system_proxy: bool,
    /// Custom proxy settings
    pub proxy: Option<ProxySettings>,
    /// DNS servers
    pub dns_servers: Vec<String>,
    /// Network interface to use
    pub interface: Option<String>,
    /// Source IP address
    pub source_ip: Option<String>,
    /// Enable IPv6
    pub enable_ipv6: bool,
    /// Connection timeout
    pub connection_timeout: u64,
    /// Read timeout
    pub read_timeout: u64,
}

/// Proxy settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxySettings {
    /// Proxy type (http, https, socks4, socks5)
    pub proxy_type: String,
    /// Proxy host
    pub host: String,
    /// Proxy port
    pub port: u16,
    /// Username for authentication
    pub username: Option<String>,
    /// Password for authentication
    pub password: Option<String>,
}

/// Security settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    /// Require confirmation for destructive actions
    pub require_confirmation: bool,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Audit log file
    pub audit_log_file: PathBuf,
    /// Encrypt saved configurations
    pub encrypt_configs: bool,
    /// Maximum scan targets per scan
    pub max_targets_per_scan: usize,
    /// Maximum concurrent scans
    pub max_concurrent_scans: usize,
    /// Allowed target networks (CIDR notation)
    pub allowed_networks: Vec<String>,
    /// Blocked target networks (CIDR notation)
    pub blocked_networks: Vec<String>,
}

/// Performance settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceSettings {
    /// Maximum memory usage in MB
    pub max_memory_mb: usize,
    /// Enable result caching
    pub enable_caching: bool,
    /// Cache size in MB
    pub cache_size_mb: usize,
    /// Cache TTL in seconds
    pub cache_ttl_seconds: u64,
    /// Background cleanup interval in seconds
    pub cleanup_interval_seconds: u64,
    /// Maximum log file size in MB
    pub max_log_size_mb: usize,
    /// Number of log files to keep
    pub log_rotation_count: usize,
}

impl Default for GuiConfig {
    fn default() -> Self {
        Self {
            app: AppSettings::default(),
            scan_defaults: ScanDefaults::default(),
            ui: UiPreferences::default(),
            export: ExportSettings::default(),
            network: NetworkSettings::default(),
            security: SecuritySettings::default(),
            performance: PerformanceSettings::default(),
        }
    }
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: "dark".to_string(),
            language: "en".to_string(),
            system_tray_enabled: true,
            auto_update_enabled: true,
            notifications_enabled: true,
            minimize_to_tray: false,
            start_minimized: false,
            auto_save_results: true,
            results_directory: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("cyNetMapper").join("results"),
            log_level: "info".to_string(),
            crash_reporting: true,
            check_updates_on_startup: true,
        }
    }
}

impl Default for ScanDefaults {
    fn default() -> Self {
        Self {
            scan_type: ScanType::Quick,
            timeout_ms: 3000,
            max_concurrent: 100,
            default_ports: "1-1000".to_string(),
            enable_service_detection: true,
            enable_os_fingerprinting: false,
            enable_banner_grabbing: true,
            output_format: "json".to_string(),
            enable_reverse_dns: true,
            rate_limit: None,
            retry_count: 1,
        }
    }
}

impl Default for UiPreferences {
    fn default() -> Self {
        Self {
            window_size: (1200, 800),
            window_position: None,
            window_state: "normal".to_string(),
            default_view: "table".to_string(),
            auto_refresh_interval: 1000,
            show_closed_ports: false,
            show_filtered_ports: false,
            group_by_host: true,
            sort_column: "address".to_string(),
            sort_order: "asc".to_string(),
            panels: PanelVisibility::default(),
            charts: ChartPreferences::default(),
            colors: ColorScheme::default(),
            fonts: FontSettings::default(),
        }
    }
}

impl Default for PanelVisibility {
    fn default() -> Self {
        Self {
            sidebar: true,
            results: true,
            charts: false,
            logs: false,
            network_view: false,
            statistics: true,
        }
    }
}

impl Default for ChartPreferences {
    fn default() -> Self {
        Self {
            default_type: "bar".to_string(),
            animations: true,
            show_legends: true,
            show_tooltips: true,
            color_palette: vec![
                "#3498db".to_string(),
                "#e74c3c".to_string(),
                "#2ecc71".to_string(),
                "#f39c12".to_string(),
                "#9b59b6".to_string(),
                "#1abc9c".to_string(),
                "#34495e".to_string(),
                "#e67e22".to_string(),
            ],
        }
    }
}

impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            primary: "#3498db".to_string(),
            secondary: "#95a5a6".to_string(),
            success: "#2ecc71".to_string(),
            warning: "#f39c12".to_string(),
            error: "#e74c3c".to_string(),
            background: "#2c3e50".to_string(),
            surface: "#34495e".to_string(),
            text: "#ecf0f1".to_string(),
        }
    }
}

impl Default for FontSettings {
    fn default() -> Self {
        Self {
            family: "Inter".to_string(),
            size: 14,
            monospace_family: "JetBrains Mono".to_string(),
            monospace_size: 12,
        }
    }
}

impl Default for ExportSettings {
    fn default() -> Self {
        Self {
            default_format: "json".to_string(),
            include_closed_ports: false,
            include_filtered_ports: false,
            include_timestamps: true,
            include_scan_config: true,
            compress_exports: false,
            export_directory: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("cyNetMapper").join("exports"),
            filename_template: "scan_{timestamp}_{scan_id}".to_string(),
        }
    }
}

impl Default for NetworkSettings {
    fn default() -> Self {
        Self {
            use_system_proxy: true,
            proxy: None,
            dns_servers: vec!["8.8.8.8".to_string(), "8.8.4.4".to_string()],
            interface: None,
            source_ip: None,
            enable_ipv6: true,
            connection_timeout: 5000,
            read_timeout: 10000,
        }
    }
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            require_confirmation: true,
            audit_logging: true,
            audit_log_file: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("cyNetMapper").join("logs").join("audit.log"),
            encrypt_configs: false,
            max_targets_per_scan: 1000,
            max_concurrent_scans: 5,
            allowed_networks: vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            blocked_networks: vec![],
        }
    }
}

impl Default for PerformanceSettings {
    fn default() -> Self {
        Self {
            max_memory_mb: 1024,
            enable_caching: true,
            cache_size_mb: 256,
            cache_ttl_seconds: 3600,
            cleanup_interval_seconds: 300,
            max_log_size_mb: 100,
            log_rotation_count: 5,
        }
    }
}

/// Configuration manager
pub struct ConfigManager {
    config: GuiConfig,
    config_path: PathBuf,
}

impl ConfigManager {
    /// Create a new configuration manager
    pub fn new() -> GuiResult<Self> {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("cyNetMapper");
        
        std::fs::create_dir_all(&config_dir)
            .map_err(|e| GuiError::ConfigError(format!("Failed to create config directory: {}", e)))?;
        
        let config_path = config_dir.join("config.json");
        let config = if config_path.exists() {
            Self::load_config(&config_path)?
        } else {
            GuiConfig::default()
        };
        
        Ok(Self {
            config,
            config_path,
        })
    }

    /// Load configuration from file
    fn load_config(path: &Path) -> GuiResult<GuiConfig> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| GuiError::ConfigError(format!("Failed to read config file: {}", e)))?;
        
        serde_json::from_str(&content)
            .map_err(|e| GuiError::ConfigError(format!("Failed to parse config file: {}", e)))
    }

    /// Save configuration to file
    pub fn save(&self) -> GuiResult<()> {
        let content = serde_json::to_string_pretty(&self.config)
            .map_err(|e| GuiError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(&self.config_path, content)
            .map_err(|e| GuiError::ConfigError(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }

    /// Get current configuration
    pub fn get(&self) -> &GuiConfig {
        &self.config
    }

    /// Get mutable configuration
    pub fn get_mut(&mut self) -> &mut GuiConfig {
        &mut self.config
    }

    /// Update configuration
    pub fn update<F>(&mut self, updater: F) -> GuiResult<()>
    where
        F: FnOnce(&mut GuiConfig),
    {
        updater(&mut self.config);
        self.save()
    }

    /// Reset to default configuration
    pub fn reset_to_default(&mut self) -> GuiResult<()> {
        self.config = GuiConfig::default();
        self.save()
    }

    /// Validate configuration
    pub fn validate(&self) -> GuiResult<()> {
        // Validate timeout values
        if self.config.scan_defaults.timeout_ms == 0 {
            return Err(GuiError::ConfigError("Timeout must be greater than 0".to_string()));
        }
        
        // Validate concurrency values
        if self.config.scan_defaults.max_concurrent == 0 {
            return Err(GuiError::ConfigError("Max concurrent must be greater than 0".to_string()));
        }
        
        // Validate directories exist or can be created
        for dir in [
            &self.config.app.results_directory,
            &self.config.export.export_directory,
        ] {
            if let Some(parent) = dir.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)
                        .map_err(|e| GuiError::ConfigError(
                            format!("Failed to create directory {}: {}", parent.display(), e)
                        ))?;
                }
            }
        }
        
        // Validate color values
        for color in [
            &self.config.ui.colors.primary,
            &self.config.ui.colors.secondary,
            &self.config.ui.colors.success,
            &self.config.ui.colors.warning,
            &self.config.ui.colors.error,
        ] {
            if !color.starts_with('#') || color.len() != 7 {
                return Err(GuiError::ConfigError(
                    format!("Invalid color format: {}", color)
                ));
            }
        }
        
        Ok(())
    }

    /// Export configuration to file
    pub fn export_to_file(&self, path: &Path) -> GuiResult<()> {
        let content = serde_json::to_string_pretty(&self.config)
            .map_err(|e| GuiError::ConfigError(format!("Failed to serialize config: {}", e)))?;
        
        std::fs::write(path, content)
            .map_err(|e| GuiError::ConfigError(format!("Failed to export config: {}", e)))?;
        
        Ok(())
    }

    /// Import configuration from file
    pub fn import_from_file(&mut self, path: &Path) -> GuiResult<()> {
        let imported_config = Self::load_config(path)?;
        self.config = imported_config;
        self.save()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_default_config() {
        let config = GuiConfig::default();
        assert_eq!(config.app.theme, "dark");
        assert_eq!(config.scan_defaults.timeout_ms, 3000);
        assert_eq!(config.ui.window_size, (1200, 800));
    }

    #[test]
    fn test_config_serialization() {
        let config = GuiConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: GuiConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config.app.theme, deserialized.app.theme);
    }

    #[test]
    fn test_config_manager() {
        let temp_dir = tempdir().unwrap();
        let config_path = temp_dir.path().join("test_config.json");
        
        // Create config with custom path
        let mut manager = ConfigManager {
            config: GuiConfig::default(),
            config_path,
        };
        
        // Save and reload
        manager.save().unwrap();
        let loaded_config = ConfigManager::load_config(&manager.config_path).unwrap();
        assert_eq!(manager.config.app.theme, loaded_config.app.theme);
    }

    #[test]
    fn test_config_validation() {
        let mut config = GuiConfig::default();
        let manager = ConfigManager {
            config: config.clone(),
            config_path: PathBuf::from("test"),
        };
        
        // Valid config should pass
        assert!(manager.validate().is_ok());
        
        // Invalid timeout should fail
        config.scan_defaults.timeout_ms = 0;
        let invalid_manager = ConfigManager {
            config,
            config_path: PathBuf::from("test"),
        };
        assert!(invalid_manager.validate().is_err());
    }
}
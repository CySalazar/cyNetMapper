//! Reusable UI widgets and components for the cyNetMapper GUI
//!
//! This module provides custom widgets and UI components that can be used
//! throughout the application, including progress bars, status indicators,
//! data tables, and specialized network scanning widgets.

use std::collections::HashMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::{GuiError, GuiHostInfo, GuiPortInfo, GuiResult, ScanProgress, ScanStatus};

/// Progress bar widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressBarConfig {
    /// Show percentage text
    pub show_percentage: bool,
    /// Show elapsed time
    pub show_elapsed: bool,
    /// Show estimated remaining time
    pub show_eta: bool,
    /// Progress bar color scheme
    pub color_scheme: ProgressColorScheme,
    /// Animation settings
    pub animation: AnimationConfig,
}

/// Color scheme for progress bars
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressColorScheme {
    /// Background color
    pub background: String,
    /// Progress fill color
    pub fill: String,
    /// Text color
    pub text: String,
    /// Border color
    pub border: String,
}

/// Animation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnimationConfig {
    /// Enable animations
    pub enabled: bool,
    /// Animation duration in milliseconds
    pub duration: u32,
    /// Animation easing function
    pub easing: String,
}

/// Status indicator widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusIndicator {
    /// Current status
    pub status: ScanStatus,
    /// Status message
    pub message: String,
    /// Show icon
    pub show_icon: bool,
    /// Show timestamp
    pub show_timestamp: bool,
    /// Color mapping for different statuses
    pub colors: HashMap<String, String>,
}

/// Data table configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTableConfig {
    /// Enable sorting
    pub sortable: bool,
    /// Enable filtering
    pub filterable: bool,
    /// Enable pagination
    pub paginated: bool,
    /// Rows per page
    pub rows_per_page: usize,
    /// Show row numbers
    pub show_row_numbers: bool,
    /// Enable row selection
    pub selectable: bool,
    /// Column configurations
    pub columns: Vec<ColumnConfig>,
}

/// Column configuration for data tables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnConfig {
    /// Column key/field name
    pub key: String,
    /// Display title
    pub title: String,
    /// Column width
    pub width: Option<String>,
    /// Is sortable
    pub sortable: bool,
    /// Is filterable
    pub filterable: bool,
    /// Data type for proper sorting/filtering
    pub data_type: DataType,
    /// Custom formatter function name
    pub formatter: Option<String>,
}

/// Data types for table columns
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataType {
    String,
    Number,
    Boolean,
    Date,
    Duration,
    IpAddress,
    Port,
    Status,
}

/// Host information widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostWidget {
    /// Host information
    pub host: GuiHostInfo,
    /// Expanded state
    pub expanded: bool,
    /// Show detailed port information
    pub show_port_details: bool,
    /// Show OS fingerprint
    pub show_os_info: bool,
    /// Show response times
    pub show_timing: bool,
}

/// Port information widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortWidget {
    /// Port information
    pub port: GuiPortInfo,
    /// Show service banner
    pub show_banner: bool,
    /// Show version information
    pub show_version: bool,
    /// Highlight security-relevant ports
    pub highlight_security: bool,
}

/// Network topology widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyWidgetConfig {
    /// Layout algorithm
    pub layout: String,
    /// Node size scaling
    pub node_size: f32,
    /// Edge thickness
    pub edge_thickness: f32,
    /// Show labels
    pub show_labels: bool,
    /// Enable physics simulation
    pub physics_enabled: bool,
    /// Color scheme
    pub colors: TopologyColors,
}

/// Color scheme for topology visualization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TopologyColors {
    /// Node colors by type
    pub nodes: HashMap<String, String>,
    /// Edge colors by type
    pub edges: HashMap<String, String>,
    /// Background color
    pub background: String,
    /// Text color
    pub text: String,
}

/// Scan configuration widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfigWidget {
    /// Available scan types
    pub scan_types: Vec<String>,
    /// Available port ranges
    pub port_ranges: Vec<String>,
    /// Available timing templates
    pub timing_templates: Vec<String>,
    /// Show advanced options
    pub show_advanced: bool,
    /// Validation rules
    pub validation: ValidationConfig,
}

/// Validation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Enable real-time validation
    pub real_time: bool,
    /// Show validation messages
    pub show_messages: bool,
    /// Validation rules
    pub rules: HashMap<String, ValidationRule>,
}

/// Validation rule definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    /// Rule type
    pub rule_type: String,
    /// Rule parameters
    pub parameters: HashMap<String, serde_json::Value>,
    /// Error message
    pub message: String,
}

/// Log viewer widget configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogViewerConfig {
    /// Maximum number of log entries to display
    pub max_entries: usize,
    /// Enable auto-scroll
    pub auto_scroll: bool,
    /// Show timestamps
    pub show_timestamps: bool,
    /// Show log levels
    pub show_levels: bool,
    /// Enable filtering by level
    pub level_filtering: bool,
    /// Enable search
    pub searchable: bool,
    /// Color scheme for different log levels
    pub level_colors: HashMap<String, String>,
}

/// Widget factory for creating configured widgets
pub struct WidgetFactory {
    default_configs: HashMap<String, serde_json::Value>,
}

impl Default for ProgressBarConfig {
    fn default() -> Self {
        Self {
            show_percentage: true,
            show_elapsed: true,
            show_eta: true,
            color_scheme: ProgressColorScheme::default(),
            animation: AnimationConfig::default(),
        }
    }
}

impl Default for ProgressColorScheme {
    fn default() -> Self {
        Self {
            background: "#ecf0f1".to_string(),
            fill: "#3498db".to_string(),
            text: "#2c3e50".to_string(),
            border: "#bdc3c7".to_string(),
        }
    }
}

impl Default for AnimationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            duration: 300,
            easing: "ease-in-out".to_string(),
        }
    }
}

impl Default for StatusIndicator {
    fn default() -> Self {
        let mut colors = HashMap::new();
        colors.insert("idle".to_string(), "#95a5a6".to_string());
        colors.insert("running".to_string(), "#3498db".to_string());
        colors.insert("paused".to_string(), "#f39c12".to_string());
        colors.insert("completed".to_string(), "#2ecc71".to_string());
        colors.insert("error".to_string(), "#e74c3c".to_string());
        colors.insert("cancelled".to_string(), "#e67e22".to_string());

        Self {
            status: ScanStatus::Pending,
            message: "Ready".to_string(),
            show_icon: true,
            show_timestamp: true,
            colors,
        }
    }
}

impl Default for DataTableConfig {
    fn default() -> Self {
        Self {
            sortable: true,
            filterable: true,
            paginated: true,
            rows_per_page: 50,
            show_row_numbers: true,
            selectable: true,
            columns: Vec::new(),
        }
    }
}

impl Default for TopologyWidgetConfig {
    fn default() -> Self {
        let mut node_colors = HashMap::new();
        node_colors.insert("host".to_string(), "#3498db".to_string());
        node_colors.insert("router".to_string(), "#e74c3c".to_string());
        node_colors.insert("switch".to_string(), "#2ecc71".to_string());
        node_colors.insert("server".to_string(), "#9b59b6".to_string());

        let mut edge_colors = HashMap::new();
        edge_colors.insert("connection".to_string(), "#95a5a6".to_string());
        edge_colors.insert("route".to_string(), "#f39c12".to_string());

        Self {
            layout: "force-directed".to_string(),
            node_size: 1.0,
            edge_thickness: 1.0,
            show_labels: true,
            physics_enabled: true,
            colors: TopologyColors {
                nodes: node_colors,
                edges: edge_colors,
                background: "#2c3e50".to_string(),
                text: "#ecf0f1".to_string(),
            },
        }
    }
}

impl Default for ScanConfigWidget {
    fn default() -> Self {
        Self {
            scan_types: vec![
                "TCP Connect".to_string(),
                "TCP SYN".to_string(),
                "UDP".to_string(),
                "Comprehensive".to_string(),
                "Stealth".to_string(),
                "Aggressive".to_string(),
            ],
            port_ranges: vec![
                "Top 100".to_string(),
                "Top 1000".to_string(),
                "All ports (1-65535)".to_string(),
                "Common ports".to_string(),
                "Custom range".to_string(),
            ],
            timing_templates: vec![
                "Paranoid (T0)".to_string(),
                "Sneaky (T1)".to_string(),
                "Polite (T2)".to_string(),
                "Normal (T3)".to_string(),
                "Aggressive (T4)".to_string(),
                "Insane (T5)".to_string(),
            ],
            show_advanced: false,
            validation: ValidationConfig::default(),
        }
    }
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            real_time: true,
            show_messages: true,
            rules: HashMap::new(),
        }
    }
}

impl Default for LogViewerConfig {
    fn default() -> Self {
        let mut level_colors = HashMap::new();
        level_colors.insert("error".to_string(), "#e74c3c".to_string());
        level_colors.insert("warn".to_string(), "#f39c12".to_string());
        level_colors.insert("info".to_string(), "#3498db".to_string());
        level_colors.insert("debug".to_string(), "#95a5a6".to_string());
        level_colors.insert("trace".to_string(), "#9b59b6".to_string());

        Self {
            max_entries: 1000,
            auto_scroll: true,
            show_timestamps: true,
            show_levels: true,
            level_filtering: true,
            searchable: true,
            level_colors,
        }
    }
}

impl WidgetFactory {
    /// Create a new widget factory
    pub fn new() -> Self {
        Self {
            default_configs: HashMap::new(),
        }
    }

    /// Create a progress bar widget with scan progress
    pub fn create_progress_bar(
        &self,
        progress: &ScanProgress,
        config: Option<ProgressBarConfig>,
    ) -> GuiResult<ProgressBarWidget> {
        let config = config.unwrap_or_default();
        
        Ok(ProgressBarWidget {
            progress: progress.clone(),
            config,
        })
    }

    /// Create a status indicator widget
    pub fn create_status_indicator(
        &self,
        status: ScanStatus,
        message: String,
        config: Option<StatusIndicator>,
    ) -> GuiResult<StatusIndicator> {
        let mut indicator = config.unwrap_or_default();
        indicator.status = status;
        indicator.message = message;
        Ok(indicator)
    }

    /// Create a host information widget
    pub fn create_host_widget(
        &self,
        host: GuiHostInfo,
        expanded: bool,
    ) -> GuiResult<HostWidget> {
        Ok(HostWidget {
            host,
            expanded,
            show_port_details: true,
            show_os_info: true,
            show_timing: true,
        })
    }

    /// Create a port information widget
    pub fn create_port_widget(&self, port: GuiPortInfo) -> GuiResult<PortWidget> {
        Ok(PortWidget {
            port,
            show_banner: true,
            show_version: true,
            highlight_security: true,
        })
    }

    /// Create a data table for hosts
    pub fn create_hosts_table(
        &self,
        hosts: Vec<GuiHostInfo>,
        config: Option<DataTableConfig>,
    ) -> GuiResult<DataTable<GuiHostInfo>> {
        let mut table_config = config.unwrap_or_default();
        
        if table_config.columns.is_empty() {
            table_config.columns = vec![
                ColumnConfig {
                    key: "address".to_string(),
                    title: "IP Address".to_string(),
                    width: Some("150px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::IpAddress,
                    formatter: None,
                },
                ColumnConfig {
                    key: "hostname".to_string(),
                    title: "Hostname".to_string(),
                    width: Some("200px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::String,
                    formatter: None,
                },
                ColumnConfig {
                    key: "state".to_string(),
                    title: "State".to_string(),
                    width: Some("80px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::Status,
                    formatter: Some("status_badge".to_string()),
                },
                ColumnConfig {
                    key: "ports".to_string(),
                    title: "Open Ports".to_string(),
                    width: Some("120px".to_string()),
                    sortable: false,
                    filterable: false,
                    data_type: DataType::Number,
                    formatter: Some("port_count".to_string()),
                },
                ColumnConfig {
                    key: "os_fingerprint".to_string(),
                    title: "OS".to_string(),
                    width: Some("150px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::String,
                    formatter: Some("os_name".to_string()),
                },
                ColumnConfig {
                    key: "response_time".to_string(),
                    title: "Response Time".to_string(),
                    width: Some("120px".to_string()),
                    sortable: true,
                    filterable: false,
                    data_type: DataType::Duration,
                    formatter: Some("duration_ms".to_string()),
                },
            ];
        }

        Ok(DataTable {
            data: hosts,
            config: table_config,
            current_page: 0,
            selected_rows: Vec::new(),
            sort_column: None,
            sort_direction: SortDirection::Ascending,
            filters: HashMap::new(),
        })
    }

    /// Create a data table for ports
    pub fn create_ports_table(
        &self,
        ports: Vec<GuiPortInfo>,
        config: Option<DataTableConfig>,
    ) -> GuiResult<DataTable<GuiPortInfo>> {
        let mut table_config = config.unwrap_or_default();
        
        if table_config.columns.is_empty() {
            table_config.columns = vec![
                ColumnConfig {
                    key: "port".to_string(),
                    title: "Port".to_string(),
                    width: Some("80px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::Port,
                    formatter: None,
                },
                ColumnConfig {
                    key: "protocol".to_string(),
                    title: "Protocol".to_string(),
                    width: Some("80px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::String,
                    formatter: None,
                },
                ColumnConfig {
                    key: "state".to_string(),
                    title: "State".to_string(),
                    width: Some("80px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::Status,
                    formatter: Some("status_badge".to_string()),
                },
                ColumnConfig {
                    key: "service".to_string(),
                    title: "Service".to_string(),
                    width: Some("120px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::String,
                    formatter: None,
                },
                ColumnConfig {
                    key: "version".to_string(),
                    title: "Version".to_string(),
                    width: Some("150px".to_string()),
                    sortable: true,
                    filterable: true,
                    data_type: DataType::String,
                    formatter: None,
                },
                ColumnConfig {
                    key: "banner".to_string(),
                    title: "Banner".to_string(),
                    width: None,
                    sortable: false,
                    filterable: true,
                    data_type: DataType::String,
                    formatter: Some("truncate".to_string()),
                },
            ];
        }

        Ok(DataTable {
            data: ports,
            config: table_config,
            current_page: 0,
            selected_rows: Vec::new(),
            sort_column: None,
            sort_direction: SortDirection::Ascending,
            filters: HashMap::new(),
        })
    }

    /// Create a log viewer widget
    pub fn create_log_viewer(
        &self,
        config: Option<LogViewerConfig>,
    ) -> GuiResult<LogViewer> {
        Ok(LogViewer {
            config: config.unwrap_or_default(),
            entries: Vec::new(),
            filtered_entries: Vec::new(),
            current_filter: None,
            search_query: String::new(),
        })
    }

    /// Set default configuration for a widget type
    pub fn set_default_config<T: Serialize>(
        &mut self,
        widget_type: &str,
        config: T,
    ) -> GuiResult<()> {
        let value = serde_json::to_value(config)
            .map_err(|e| GuiError::ConfigError(e.to_string()))?;
        self.default_configs.insert(widget_type.to_string(), value);
        Ok(())
    }

    /// Get default configuration for a widget type
    pub fn get_default_config<T: for<'de> Deserialize<'de>>(
        &self,
        widget_type: &str,
    ) -> GuiResult<Option<T>> {
        if let Some(value) = self.default_configs.get(widget_type) {
            let config = serde_json::from_value(value.clone())
                .map_err(|e| GuiError::ConfigError(e.to_string()))?;
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }
}

/// Progress bar widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressBarWidget {
    pub progress: ScanProgress,
    pub config: ProgressBarConfig,
}

/// Generic data table widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTable<T> {
    pub data: Vec<T>,
    pub config: DataTableConfig,
    pub current_page: usize,
    pub selected_rows: Vec<usize>,
    pub sort_column: Option<String>,
    pub sort_direction: SortDirection,
    pub filters: HashMap<String, String>,
}

/// Sort direction for data tables
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SortDirection {
    Ascending,
    Descending,
}

/// Log viewer widget
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogViewer {
    pub config: LogViewerConfig,
    pub entries: Vec<LogEntry>,
    pub filtered_entries: Vec<LogEntry>,
    pub current_filter: Option<String>,
    pub search_query: String,
}

/// Log entry for the log viewer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub level: String,
    pub message: String,
    pub module: Option<String>,
    pub file: Option<String>,
    pub line: Option<u32>,
}

impl Default for WidgetFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> DataTable<T> {
    /// Get the current page of data
    pub fn get_current_page(&self) -> &[T] {
        let start = self.current_page * self.config.rows_per_page;
        let end = std::cmp::min(start + self.config.rows_per_page, self.data.len());
        &self.data[start..end]
    }

    /// Get total number of pages
    pub fn get_total_pages(&self) -> usize {
        (self.data.len() + self.config.rows_per_page - 1) / self.config.rows_per_page
    }

    /// Navigate to a specific page
    pub fn goto_page(&mut self, page: usize) -> GuiResult<()> {
        if page < self.get_total_pages() {
            self.current_page = page;
            Ok(())
        } else {
            Err(GuiError::InvalidInput("Page number out of range".to_string()))
        }
    }

    /// Select/deselect a row
    pub fn toggle_row_selection(&mut self, row_index: usize) {
        if let Some(pos) = self.selected_rows.iter().position(|&x| x == row_index) {
            self.selected_rows.remove(pos);
        } else {
            self.selected_rows.push(row_index);
        }
    }

    /// Clear all selections
    pub fn clear_selection(&mut self) {
        self.selected_rows.clear();
    }

    /// Get selected row indices
    pub fn get_selected_rows(&self) -> &[usize] {
        &self.selected_rows
    }
}

impl LogViewer {
    /// Add a new log entry
    pub fn add_entry(&mut self, entry: LogEntry) {
        self.entries.push(entry);
        
        // Trim to max entries
        if self.entries.len() > self.config.max_entries {
            self.entries.remove(0);
        }
        
        self.apply_filters();
    }

    /// Set log level filter
    pub fn set_level_filter(&mut self, level: Option<String>) {
        self.current_filter = level;
        self.apply_filters();
    }

    /// Set search query
    pub fn set_search_query(&mut self, query: String) {
        self.search_query = query;
        self.apply_filters();
    }

    /// Apply current filters to entries
    fn apply_filters(&mut self) {
        self.filtered_entries = self.entries
            .iter()
            .filter(|entry| {
                // Level filter
                if let Some(ref level_filter) = self.current_filter {
                    if &entry.level != level_filter {
                        return false;
                    }
                }
                
                // Search filter
                if !self.search_query.is_empty() {
                    let query_lower = self.search_query.to_lowercase();
                    if !entry.message.to_lowercase().contains(&query_lower) {
                        return false;
                    }
                }
                
                true
            })
            .cloned()
            .collect();
    }

    /// Clear all log entries
    pub fn clear(&mut self) {
        self.entries.clear();
        self.filtered_entries.clear();
    }

    /// Get filtered entries
    pub fn get_entries(&self) -> &[LogEntry] {
        &self.filtered_entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_widget_factory_creation() {
        let factory = WidgetFactory::new();
        assert!(factory.default_configs.is_empty());
    }

    #[test]
    fn test_progress_bar_config_default() {
        let config = ProgressBarConfig::default();
        assert!(config.show_percentage);
        assert!(config.show_elapsed);
        assert!(config.show_eta);
    }

    #[test]
    fn test_data_table_pagination() {
        let mut table = DataTable {
            data: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            config: DataTableConfig {
                rows_per_page: 3,
                ..Default::default()
            },
            current_page: 0,
            selected_rows: Vec::new(),
            sort_column: None,
            sort_direction: SortDirection::Ascending,
            filters: HashMap::new(),
        };

        assert_eq!(table.get_current_page(), &[1, 2, 3]);
        assert_eq!(table.get_total_pages(), 4);

        table.goto_page(1).unwrap();
        assert_eq!(table.get_current_page(), &[4, 5, 6]);
    }

    #[test]
    fn test_log_viewer_filtering() {
        let mut viewer = LogViewer {
            config: LogViewerConfig::default(),
            entries: vec![
                LogEntry {
                    timestamp: chrono::Utc::now(),
                    level: "info".to_string(),
                    message: "Test info message".to_string(),
                    module: None,
                    file: None,
                    line: None,
                },
                LogEntry {
                    timestamp: chrono::Utc::now(),
                    level: "error".to_string(),
                    message: "Test error message".to_string(),
                    module: None,
                    file: None,
                    line: None,
                },
            ],
            filtered_entries: Vec::new(),
            current_filter: None,
            search_query: String::new(),
        };

        viewer.apply_filters();
        assert_eq!(viewer.get_entries().len(), 2);

        viewer.set_level_filter(Some("error".to_string()));
        assert_eq!(viewer.get_entries().len(), 1);
        assert_eq!(viewer.get_entries()[0].level, "error");

        viewer.set_search_query("info".to_string());
        assert_eq!(viewer.get_entries().len(), 0); // No error messages containing "info"
    }
}
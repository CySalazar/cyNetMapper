//! Chart generation and data visualization for the cyNetMapper GUI
//!
//! This module provides functionality for creating various types of charts
//! and visualizations from scan results, including port status charts,
//! service distribution charts, OS fingerprinting charts, and network topology.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::{ChartData, ChartDataset, GuiError, GuiHostInfo, GuiResult, NetworkTopology};

/// Chart configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartConfig {
    /// Chart type (bar, pie, line, doughnut, radar)
    pub chart_type: String,
    /// Chart title
    pub title: String,
    /// Enable animations
    pub animated: bool,
    /// Show legend
    pub show_legend: bool,
    /// Show tooltips
    pub show_tooltips: bool,
    /// Color scheme
    pub color_scheme: ColorScheme,
    /// Chart dimensions
    pub dimensions: ChartDimensions,
    /// Additional options
    pub options: HashMap<String, serde_json::Value>,
}

/// Color scheme for charts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColorScheme {
    /// Primary colors for data series
    pub primary: Vec<String>,
    /// Background colors
    pub background: Vec<String>,
    /// Border colors
    pub border: Vec<String>,
    /// Grid color
    pub grid: String,
    /// Text color
    pub text: String,
}

/// Chart dimensions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChartDimensions {
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Responsive sizing
    pub responsive: bool,
    /// Maintain aspect ratio
    pub maintain_aspect_ratio: bool,
}

/// Chart generator for creating various visualizations
pub struct ChartGenerator {
    config: ChartConfig,
}

impl Default for ChartConfig {
    fn default() -> Self {
        Self {
            chart_type: "bar".to_string(),
            title: "Chart".to_string(),
            animated: true,
            show_legend: true,
            show_tooltips: true,
            color_scheme: ColorScheme::default(),
            dimensions: ChartDimensions::default(),
            options: HashMap::new(),
        }
    }
}


impl Default for ColorScheme {
    fn default() -> Self {
        Self {
            primary: vec![
                "#3498db".to_string(),
                "#e74c3c".to_string(),
                "#2ecc71".to_string(),
                "#f39c12".to_string(),
                "#9b59b6".to_string(),
                "#1abc9c".to_string(),
                "#34495e".to_string(),
                "#e67e22".to_string(),
            ],
            background: vec![
                "rgba(52, 152, 219, 0.2)".to_string(),
                "rgba(231, 76, 60, 0.2)".to_string(),
                "rgba(46, 204, 113, 0.2)".to_string(),
                "rgba(243, 156, 18, 0.2)".to_string(),
                "rgba(155, 89, 182, 0.2)".to_string(),
                "rgba(26, 188, 156, 0.2)".to_string(),
                "rgba(52, 73, 94, 0.2)".to_string(),
                "rgba(230, 126, 34, 0.2)".to_string(),
            ],
            border: vec![
                "#2980b9".to_string(),
                "#c0392b".to_string(),
                "#27ae60".to_string(),
                "#e67e22".to_string(),
                "#8e44ad".to_string(),
                "#16a085".to_string(),
                "#2c3e50".to_string(),
                "#d35400".to_string(),
            ],
            grid: "rgba(255, 255, 255, 0.1)".to_string(),
            text: "#ecf0f1".to_string(),
        }
    }
}

impl Default for ChartDimensions {
    fn default() -> Self {
        Self {
            width: 800,
            height: 400,
            responsive: true,
            maintain_aspect_ratio: true,
        }
    }
}

impl ChartGenerator {
    /// Create a new chart generator with default configuration
    pub fn new() -> Self {
        Self {
            config: ChartConfig::default(),
        }
    }

    /// Create a new chart generator with custom configuration
    pub fn with_config(config: ChartConfig) -> Self {
        Self { config }
    }

    /// Generate port status distribution chart
    pub fn generate_port_status_chart(
        &self,
        results: &[GuiHostInfo],
    ) -> GuiResult<ChartData> {
        let mut open_count = 0;
        let mut closed_count = 0;
        let mut filtered_count = 0;
        let mut unknown_count = 0;

        for host in results {
            for port in &host.ports {
                match port.state.as_str() {
                    "open" => open_count += 1,
                    "closed" => closed_count += 1,
                    "filtered" => filtered_count += 1,
                    _ => unknown_count += 1,
                }
            }
        }

        let mut labels = Vec::new();
        let mut data = Vec::new();
        let mut colors = Vec::new();

        if open_count > 0 {
            labels.push("Open".to_string());
            data.push(open_count as f64);
            colors.push("#2ecc71".to_string());
        }
        if closed_count > 0 {
            labels.push("Closed".to_string());
            data.push(closed_count as f64);
            colors.push("#e74c3c".to_string());
        }
        if filtered_count > 0 {
            labels.push("Filtered".to_string());
            data.push(filtered_count as f64);
            colors.push("#f39c12".to_string());
        }
        if unknown_count > 0 {
            labels.push("Unknown".to_string());
            data.push(unknown_count as f64);
            colors.push("#95a5a6".to_string());
        }

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Port Status Distribution".to_string(),
                data,
                background_color: colors.first().cloned(),
                border_color: Some("#34495e".to_string()),
            }],
        })
    }

    /// Generate service distribution chart
    pub fn generate_service_chart(&self, results: &[GuiHostInfo]) -> GuiResult<ChartData> {
        let mut service_counts: HashMap<String, u32> = HashMap::new();

        for host in results {
            for port in &host.ports {
                if port.state == "open" {
                    let service = port
                        .service
                        .as_ref()
                        .unwrap_or(&"Unknown".to_string())
                        .clone();
                    *service_counts.entry(service).or_insert(0) += 1;
                }
            }
        }

        // Sort by count and take top 10
        let mut services: Vec<_> = service_counts.into_iter().collect();
        services.sort_by(|a, b| b.1.cmp(&a.1));
        services.truncate(10);

        let labels: Vec<String> = services.iter().map(|(name, _)| name.clone()).collect();
        let data: Vec<f64> = services.iter().map(|(_, count)| *count as f64).collect();

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Service Distribution".to_string(),
                data,
                background_color: Some("#3498db".to_string()),
                border_color: Some("#2980b9".to_string()),
            }],
        })
    }

    /// Generate OS distribution chart
    pub fn generate_os_chart(&self, results: &[GuiHostInfo]) -> GuiResult<ChartData> {
        let mut os_counts: HashMap<String, u32> = HashMap::new();

        for host in results {
            if let Some(os) = &host.os_fingerprint {
                let os_name = os.family.clone();
                *os_counts.entry(os_name).or_insert(0) += 1;
            } else {
                *os_counts.entry("Unknown".to_string()).or_insert(0) += 1;
            }
        }

        let mut os_list: Vec<_> = os_counts.into_iter().collect();
        os_list.sort_by(|a, b| b.1.cmp(&a.1));

        let labels: Vec<String> = os_list.iter().map(|(name, _)| name.clone()).collect();
        let data: Vec<f64> = os_list.iter().map(|(_, count)| *count as f64).collect();

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Operating System Distribution".to_string(),
                data,
                background_color: Some("#9b59b6".to_string()),
                border_color: Some("#8e44ad".to_string()),
            }],
        })
    }

    /// Generate scan timeline chart
    pub fn generate_timeline_chart(
        &self,
        scan_history: &[(chrono::DateTime<chrono::Utc>, usize)],
    ) -> GuiResult<ChartData> {
        let labels: Vec<String> = scan_history
            .iter()
            .map(|(timestamp, _)| timestamp.format("%Y-%m-%d %H:%M").to_string())
            .collect();

        let data: Vec<f64> = scan_history
            .iter()
            .map(|(_, count)| *count as f64)
            .collect();

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Hosts Discovered Over Time".to_string(),
                data,
                background_color: Some("rgba(52, 152, 219, 0.2)".to_string()),
                border_color: Some("#3498db".to_string()),
            }],
        })
    }

    /// Generate port range activity chart
    pub fn generate_port_activity_chart(&self, results: &[GuiHostInfo]) -> GuiResult<ChartData> {
        let mut port_ranges = HashMap::new();
        port_ranges.insert("1-1023".to_string(), 0u32);
        port_ranges.insert("1024-49151".to_string(), 0u32);
        port_ranges.insert("49152-65535".to_string(), 0u32);

        for host in results {
            for port in &host.ports {
                if port.state == "open" {
                    let range = match port.port {
                        1..=1023 => "1-1023",
                        1024..=49151 => "1024-49151",
                        49152..=65535 => "49152-65535",
                        _ => continue,
                    };
                    *port_ranges.get_mut(range).unwrap() += 1;
                }
            }
        }

        let labels = vec![
            "Well-known (1-1023)".to_string(),
            "Registered (1024-49151)".to_string(),
            "Dynamic (49152-65535)".to_string(),
        ];
        let data = vec![
            port_ranges["1-1023"] as f64,
            port_ranges["1024-49151"] as f64,
            port_ranges["49152-65535"] as f64,
        ];

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Port Range Activity".to_string(),
                data,
                background_color: Some("#1abc9c".to_string()),
                border_color: Some("#16a085".to_string()),
            }],
        })
    }

    /// Generate response time distribution chart
    pub fn generate_response_time_chart(&self, results: &[GuiHostInfo]) -> GuiResult<ChartData> {
        let mut time_buckets = HashMap::new();
        time_buckets.insert("<10ms".to_string(), 0u32);
        time_buckets.insert("10-50ms".to_string(), 0u32);
        time_buckets.insert("50-100ms".to_string(), 0u32);
        time_buckets.insert("100-500ms".to_string(), 0u32);
        time_buckets.insert(">500ms".to_string(), 0u32);

        for host in results {
            if let Some(response_time) = host.response_time {
                let ms = response_time.as_millis() as u64;
                let bucket = match ms {
                    0..=9 => "<10ms",
                    10..=49 => "10-50ms",
                    50..=99 => "50-100ms",
                    100..=499 => "100-500ms",
                    _ => ">500ms",
                };
                *time_buckets.get_mut(bucket).unwrap() += 1;
            }
        }

        let labels = vec![
            "<10ms".to_string(),
            "10-50ms".to_string(),
            "50-100ms".to_string(),
            "100-500ms".to_string(),
            ">500ms".to_string(),
        ];
        let data = vec![
            time_buckets["<10ms"] as f64,
            time_buckets["10-50ms"] as f64,
            time_buckets["50-100ms"] as f64,
            time_buckets["100-500ms"] as f64,
            time_buckets[">500ms"] as f64,
        ];

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Response Time Distribution".to_string(),
                data,
                background_color: Some("#e67e22".to_string()),
                border_color: Some("#d35400".to_string()),
            }],
        })
    }

    /// Generate vulnerability severity chart (placeholder)
    pub fn generate_vulnerability_chart(&self, _results: &[GuiHostInfo]) -> GuiResult<ChartData> {
        // This would be implemented when vulnerability scanning is added
        let labels = vec![
            "Critical".to_string(),
            "High".to_string(),
            "Medium".to_string(),
            "Low".to_string(),
            "Info".to_string(),
        ];
        let data = vec![0.0, 0.0, 0.0, 0.0, 0.0];

        Ok(ChartData {
            labels,
            datasets: vec![ChartDataset {
                label: "Vulnerability Severity".to_string(),
                data,
                background_color: Some("#e74c3c".to_string()),
                border_color: Some("#c0392b".to_string()),
            }],
        })
    }

    /// Generate network topology data
    pub fn generate_network_topology(&self, results: &[GuiHostInfo]) -> GuiResult<NetworkTopology> {
        crate::utils::results_to_network_topology(results)
    }

    /// Export chart data to various formats
    pub fn export_chart_data(
        &self,
        chart_data: &ChartData,
        format: &str,
    ) -> GuiResult<String> {
        match format.to_lowercase().as_str() {
            "json" => {
                serde_json::to_string_pretty(chart_data)
                    .map_err(|e| GuiError::ExportError(e.to_string()))
            }
            "csv" => self.export_to_csv(chart_data),
            _ => Err(GuiError::InvalidInput(format!(
                "Unsupported export format: {}",
                format
            ))),
        }
    }

    /// Export chart data to CSV format
    fn export_to_csv(&self, chart_data: &ChartData) -> GuiResult<String> {
        let mut csv = String::new();
        
        // Header
        csv.push_str("Label");
        for dataset in &chart_data.datasets {
            csv.push(',');
            csv.push_str(&dataset.label);
        }
        csv.push('\n');
        
        // Data rows
        for (i, label) in chart_data.labels.iter().enumerate() {
            csv.push_str(label);
            for dataset in &chart_data.datasets {
                csv.push(',');
                if let Some(value) = dataset.data.get(i) {
                    csv.push_str(&value.to_string());
                }
            }
            csv.push('\n');
        }
        
        Ok(csv)
    }

    /// Update chart configuration
    pub fn update_config(&mut self, config: ChartConfig) {
        self.config = config;
    }

    /// Get current configuration
    pub fn get_config(&self) -> &ChartConfig {
        &self.config
    }
}

impl Default for ChartGenerator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GuiHostInfo, GuiPortInfo};
    use std::time::Duration;

    fn create_test_host(address: &str, ports: Vec<(u16, &str)>) -> GuiHostInfo {
        GuiHostInfo {
            address: address.to_string(),
            hostname: None,
            state: "up".to_string(),
            ports: ports
                .into_iter()
                .map(|(port, state)| GuiPortInfo {
                    port,
                    protocol: "tcp".to_string(),
                    state: state.to_string(),
                    service: None,
                    version: None,
                    banner: None,
                    response_time: Some(Duration::from_millis(10)),
                    confidence: Some(0.9),
                })
                .collect(),
            os_fingerprint: None,
            response_time: Some(Duration::from_millis(10)),
            last_seen: None,
        }
    }

    #[test]
    fn test_port_status_chart() {
        let generator = ChartGenerator::new();
        let hosts = vec![
            create_test_host("192.168.1.1", vec![(80, "open"), (443, "open")]),
            create_test_host("192.168.1.2", vec![(22, "closed"), (80, "filtered")]),
        ];

        let chart = generator.generate_port_status_chart(&hosts).unwrap();
        assert_eq!(chart.labels.len(), 3); // open, closed, filtered
        assert_eq!(chart.datasets.len(), 1);
    }

    #[test]
    fn test_service_chart() {
        let generator = ChartGenerator::new();
        let mut hosts = vec![create_test_host("192.168.1.1", vec![(80, "open")])];
        hosts[0].ports[0].service = Some("http".to_string());

        let chart = generator.generate_service_chart(&hosts).unwrap();
        assert!(!chart.labels.is_empty());
        assert_eq!(chart.datasets.len(), 1);
    }

    #[test]
    fn test_chart_config_default() {
        let config = ChartConfig::default();
        assert_eq!(config.chart_type, "bar");
        assert!(config.animated);
        assert!(config.show_legend);
    }

    #[test]
    fn test_export_to_csv() {
        let generator = ChartGenerator::new();
        let chart_data = ChartData {
            labels: vec!["A".to_string(), "B".to_string()],
            datasets: vec![ChartDataset {
                label: "Test".to_string(),
                data: vec![1.0, 2.0],
                background_color: None,
                border_color: None,
            }],
        };

        let csv = generator.export_to_csv(&chart_data).unwrap();
        assert!(csv.contains("Label,Test"));
        assert!(csv.contains("A,1"));
        assert!(csv.contains("B,2"));
    }
}
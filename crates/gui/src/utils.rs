//! Utility functions for the cyNetMapper GUI
//!
//! This module provides various utility functions for data formatting,
//! validation, conversion, and other common operations used throughout the GUI.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::{GuiError, GuiResult};

/// Format a duration in a human-readable way
pub fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;
    let millis = duration.subsec_millis();

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else if seconds > 0 {
        format!("{}.{}s", seconds, millis / 100)
    } else {
        format!("{}ms", millis)
    }
}

/// Format a timestamp in ISO 8601 format
pub fn format_timestamp(timestamp: SystemTime) -> String {
    let datetime = chrono::DateTime::<chrono::Utc>::from(timestamp);
    datetime.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

/// Format a timestamp in a human-readable format
pub fn format_timestamp_human(timestamp: SystemTime) -> String {
    let datetime = chrono::DateTime::<chrono::Local>::from(timestamp);
    datetime.format("%Y-%m-%d %H:%M:%S").to_string()
}

/// Format bytes in a human-readable way
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    const THRESHOLD: f64 = 1024.0;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let mut size = bytes as f64;
    let mut unit_index = 0;

    while size >= THRESHOLD && unit_index < UNITS.len() - 1 {
        size /= THRESHOLD;
        unit_index += 1;
    }

    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Format a percentage with specified decimal places
pub fn format_percentage(value: f64, decimal_places: usize) -> String {
    format!("{:.prec$}%", value * 100.0, prec = decimal_places)
}

/// Validate an IP address string
pub fn validate_ip_address(ip: &str) -> GuiResult<IpAddr> {
    IpAddr::from_str(ip)
        .map_err(|_| GuiError::InvalidInput(format!("Invalid IP address: {}", ip)))
}

/// Validate a CIDR notation string
pub fn validate_cidr(cidr: &str) -> GuiResult<(IpAddr, u8)> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(GuiError::InvalidInput(
            "CIDR must be in format IP/prefix".to_string(),
        ));
    }

    let ip = validate_ip_address(parts[0])?;
    let prefix: u8 = parts[1]
        .parse()
        .map_err(|_| GuiError::InvalidInput("Invalid prefix length".to_string()))?;

    // Validate prefix length based on IP version
    let max_prefix = match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };

    if prefix > max_prefix {
        return Err(GuiError::InvalidInput(format!(
            "Prefix length {} exceeds maximum {} for {:?}",
            prefix,
            max_prefix,
            if ip.is_ipv4() { "IPv4" } else { "IPv6" }
        )));
    }

    Ok((ip, prefix))
}

/// Parse port range string (e.g., "80", "80-443", "80,443,8080")
pub fn parse_port_range(ports: &str) -> GuiResult<Vec<u16>> {
    let mut result = Vec::new();

    for part in ports.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(GuiError::InvalidInput(
                    "Invalid port range format".to_string(),
                ));
            }

            let start: u16 = range_parts[0]
                .parse()
                .map_err(|_| GuiError::InvalidInput("Invalid start port".to_string()))?;
            let end: u16 = range_parts[1]
                .parse()
                .map_err(|_| GuiError::InvalidInput("Invalid end port".to_string()))?;

            if start > end {
                return Err(GuiError::InvalidInput(
                    "Start port must be less than or equal to end port".to_string(),
                ));
            }

            for port in start..=end {
                result.push(port);
            }
        } else {
            let port: u16 = part
                .parse()
                .map_err(|_| GuiError::InvalidInput("Invalid port number".to_string()))?;
            result.push(port);
        }
    }

    result.sort_unstable();
    result.dedup();
    Ok(result)
}

/// Validate hostname
pub fn validate_hostname(hostname: &str) -> GuiResult<()> {
    if hostname.is_empty() {
        return Err(GuiError::InvalidInput("Hostname cannot be empty".to_string()));
    }

    if hostname.len() > 253 {
        return Err(GuiError::InvalidInput(
            "Hostname too long (max 253 characters)".to_string(),
        ));
    }

    // Check for valid characters and format
    let parts: Vec<&str> = hostname.split('.').collect();
    for part in parts {
        if part.is_empty() {
            return Err(GuiError::InvalidInput(
                "Hostname parts cannot be empty".to_string(),
            ));
        }

        if part.len() > 63 {
            return Err(GuiError::InvalidInput(
                "Hostname part too long (max 63 characters)".to_string(),
            ));
        }

        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(GuiError::InvalidInput(
                "Hostname contains invalid characters".to_string(),
            ));
        }

        if part.starts_with('-') || part.ends_with('-') {
            return Err(GuiError::InvalidInput(
                "Hostname parts cannot start or end with hyphen".to_string(),
            ));
        }
    }

    Ok(())
}

/// Generate a unique scan ID
pub fn generate_scan_id() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let random: u32 = rand::random();
    format!("{:x}-{:x}", timestamp, random)
}

/// Sanitize filename for safe file operations
pub fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Convert scan results to chart data
pub fn results_to_chart_data(
    results: &[crate::GuiHostInfo],
    chart_type: &str,
) -> GuiResult<crate::ChartData> {
    match chart_type {
        "port_status" => {
            let mut open_count = 0;
            let mut closed_count = 0;
            let mut filtered_count = 0;

            for host in results {
                for port in &host.ports {
                    match port.state.as_str() {
                        "open" => open_count += 1,
                        "closed" => closed_count += 1,
                        "filtered" => filtered_count += 1,
                        _ => {}
                    }
                }
            }

            Ok(crate::ChartData {
                labels: vec!["Open".to_string(), "Closed".to_string(), "Filtered".to_string()],
                datasets: vec![crate::ChartDataset {
                    label: "Port Status".to_string(),
                    data: vec![open_count as f64, closed_count as f64, filtered_count as f64],
                    background_color: Some("#2ecc71".to_string()),
                    border_color: Some("#27ae60".to_string()),
                }],
            })
        }
        "services" => {
            let mut service_counts: HashMap<String, u32> = HashMap::new();

            for host in results {
                for port in &host.ports {
                    if let Some(service) = &port.service {
                        *service_counts.entry(service.clone()).or_insert(0) += 1;
                    }
                }
            }

            let mut labels = Vec::new();
            let mut data = Vec::new();

            for (service, count) in service_counts {
                labels.push(service);
                data.push(count as f64);
            }

            Ok(crate::ChartData {
                labels,
                datasets: vec![crate::ChartDataset {
                    label: "Services".to_string(),
                    data,
                    background_color: Some("#3498db".to_string()),
                    border_color: Some("#2980b9".to_string()),
                }],
            })
        }
        "os_distribution" => {
            let mut os_counts: HashMap<String, u32> = HashMap::new();

            for host in results {
                if let Some(os) = &host.os_fingerprint {
                    let os_name = os.family.clone();
                    *os_counts.entry(os_name).or_insert(0) += 1;
                }
            }

            let mut labels = Vec::new();
            let mut data = Vec::new();

            for (os, count) in os_counts {
                labels.push(os);
                data.push(count as f64);
            }

            Ok(crate::ChartData {
                labels,
                datasets: vec![crate::ChartDataset {
                    label: "Operating Systems".to_string(),
                    data,
                    background_color: Some("#9b59b6".to_string()),
                    border_color: Some("#8e44ad".to_string()),
                }],
            })
        }
        _ => Err(GuiError::InvalidInput(format!(
            "Unknown chart type: {}",
            chart_type
        ))),
    }
}

/// Generate colors for charts
fn generate_colors(count: usize) -> Vec<String> {
    let base_colors = [
        "#3498db", "#e74c3c", "#2ecc71", "#f39c12", "#9b59b6",
        "#1abc9c", "#34495e", "#e67e22", "#95a5a6", "#16a085",
    ];

    (0..count)
        .map(|i| base_colors[i % base_colors.len()].to_string())
        .collect()
}

/// Convert results to network topology
pub fn results_to_network_topology(
    results: &[crate::GuiHostInfo],
) -> GuiResult<crate::NetworkTopology> {
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    // Create nodes for each host
    for (i, host) in results.iter().enumerate() {
        let node_type = if host.ports.iter().any(|p| p.state == "open") {
            "active"
        } else {
            "inactive"
        };

        nodes.push(crate::NetworkNode {
            id: format!("host_{}", i),
            label: host.address.clone(),
            node_type: node_type.to_string(),
            status: if host.ports.iter().any(|p| p.state == "open") {
                "active".to_string()
            } else {
                "inactive".to_string()
            },
            properties: {
                let mut props = HashMap::new();
                props.insert("address".to_string(), host.address.clone());
                if let Some(hostname) = &host.hostname {
                    props.insert("hostname".to_string(), hostname.clone());
                }
                props.insert(
                    "open_ports".to_string(),
                    host.ports.iter().filter(|p| p.state == "open").count().to_string(),
                );
                props
            },
        });
    }

    // Create edges based on network relationships
    // This is a simplified approach - in a real implementation,
    // you might want to analyze network topology more thoroughly
    for i in 0..results.len() {
        for j in (i + 1)..results.len() {
            let host1 = &results[i];
            let host2 = &results[j];

            // Check if hosts are in the same subnet (simplified)
            if are_in_same_subnet(&host1.address, &host2.address) {
                edges.push(crate::NetworkEdge {
                    from: format!("host_{}", i),
                    to: format!("host_{}", j),
                    label: Some("subnet".to_string()),
                    edge_type: "subnet".to_string(),
                    properties: HashMap::new(),
                });
            }
        }
    }

    Ok(crate::NetworkTopology { nodes, edges })
}

/// Check if two IP addresses are in the same /24 subnet (simplified)
fn are_in_same_subnet(ip1: &str, ip2: &str) -> bool {
    if let (Ok(addr1), Ok(addr2)) = (IpAddr::from_str(ip1), IpAddr::from_str(ip2)) {
        match (addr1, addr2) {
            (IpAddr::V4(v4_1), IpAddr::V4(v4_2)) => {
                let octets1 = v4_1.octets();
                let octets2 = v4_2.octets();
                octets1[0] == octets2[0] && octets1[1] == octets2[1] && octets1[2] == octets2[2]
            }
            (IpAddr::V6(v6_1), IpAddr::V6(v6_2)) => {
                let segments1 = v6_1.segments();
                let segments2 = v6_2.segments();
                segments1[0] == segments2[0]
                    && segments1[1] == segments2[1]
                    && segments1[2] == segments2[2]
                    && segments1[3] == segments2[3]
            }
            _ => false,
        }
    } else {
        false
    }
}

/// Escape HTML characters for safe display
pub fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

/// Truncate string to specified length with ellipsis
pub fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len.saturating_sub(3)])
    }
}

/// Calculate scan progress percentage
pub fn calculate_progress(completed: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (completed as f64 / total as f64).min(1.0)
    }
}

/// Estimate remaining time based on progress
pub fn estimate_remaining_time(
    start_time: SystemTime,
    completed: usize,
    total: usize,
) -> Option<Duration> {
    if completed == 0 || completed >= total {
        return None;
    }

    let elapsed = start_time.elapsed().ok()?;
    let rate = completed as f64 / elapsed.as_secs_f64();
    let remaining_items = total - completed;
    let remaining_seconds = remaining_items as f64 / rate;

    Some(Duration::from_secs_f64(remaining_seconds))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(Duration::from_secs(30)), "30.0s");
        assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1536), "1.5 KB");
        assert_eq!(format_bytes(1048576), "1.0 MB");
    }

    #[test]
    fn test_validate_ip_address() {
        assert!(validate_ip_address("192.168.1.1").is_ok());
        assert!(validate_ip_address("::1").is_ok());
        assert!(validate_ip_address("invalid").is_err());
    }

    #[test]
    fn test_validate_cidr() {
        assert!(validate_cidr("192.168.1.0/24").is_ok());
        assert!(validate_cidr("2001:db8::/32").is_ok());
        assert!(validate_cidr("192.168.1.0/33").is_err());
        assert!(validate_cidr("invalid/24").is_err());
    }

    #[test]
    fn test_parse_port_range() {
        assert_eq!(parse_port_range("80").unwrap(), vec![80]);
        assert_eq!(parse_port_range("80-82").unwrap(), vec![80, 81, 82]);
        assert_eq!(parse_port_range("80,443,8080").unwrap(), vec![80, 443, 8080]);
        assert!(parse_port_range("invalid").is_err());
    }

    #[test]
    fn test_validate_hostname() {
        assert!(validate_hostname("example.com").is_ok());
        assert!(validate_hostname("sub.example.com").is_ok());
        assert!(validate_hostname("").is_err());
        assert!(validate_hostname("invalid..com").is_err());
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("test file.txt"), "test_file.txt");
        assert_eq!(sanitize_filename("scan<>results"), "scan__results");
    }

    #[test]
    fn test_calculate_progress() {
        assert_eq!(calculate_progress(0, 100), 0.0);
        assert_eq!(calculate_progress(50, 100), 0.5);
        assert_eq!(calculate_progress(100, 100), 1.0);
        assert_eq!(calculate_progress(0, 0), 0.0);
    }
}
//! Tauri commands for the cyNetMapper GUI
//!
//! This module contains all the Tauri commands that can be invoked from the frontend.
//! Commands handle the communication between the web frontend and the Rust backend.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tauri::{State, Window};
use uuid::Uuid;

use crate::{
    AppState, GuiError, GuiResult, ScanConfig, ScanProgress, ScanStatus,
    GuiHostInfo, ChartData, NetworkTopology, AppConfig
};
use cynetmapper_outputs::{OutputManager, OutputFormat, PortState};

/// Start a new network scan
#[tauri::command]
pub async fn start_scan(
    config: ScanConfig,
    state: State<'_, AppState>,
    window: Window,
) -> Result<String, String> {
    state
        .start_scan(config, window)
        .await
        .map_err(|e| e.to_string())
}

/// Stop an active scan
#[tauri::command]
pub async fn stop_scan(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut scans = state.active_scans.lock().unwrap();
    if let Some(progress) = scans.get_mut(&scan_id) {
        progress.status = ScanStatus::Cancelled;
        Ok(())
    } else {
        Err("Scan not found".to_string())
    }
}

/// Pause an active scan
#[tauri::command]
pub async fn pause_scan(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut scans = state.active_scans.lock().unwrap();
    if let Some(progress) = scans.get_mut(&scan_id) {
        if progress.status == ScanStatus::Running {
            progress.status = ScanStatus::Paused;
            Ok(())
        } else {
            Err("Scan is not running".to_string())
        }
    } else {
        Err("Scan not found".to_string())
    }
}

/// Resume a paused scan
#[tauri::command]
pub async fn resume_scan(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut scans = state.active_scans.lock().unwrap();
    if let Some(progress) = scans.get_mut(&scan_id) {
        if progress.status == ScanStatus::Paused {
            progress.status = ScanStatus::Running;
            Ok(())
        } else {
            Err("Scan is not paused".to_string())
        }
    } else {
        Err("Scan not found".to_string())
    }
}

/// Get the progress of a specific scan
#[tauri::command]
pub async fn get_scan_progress(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<Option<ScanProgress>, String> {
    let scans = state.active_scans.lock().unwrap();
    Ok(scans.get(&scan_id).cloned())
}

/// Get all active scans
#[tauri::command]
pub async fn get_active_scans(
    state: State<'_, AppState>,
) -> Result<Vec<ScanProgress>, String> {
    let scans = state.active_scans.lock().unwrap();
    Ok(scans.values().cloned().collect())
}

/// Get scan results
#[tauri::command]
pub async fn get_scan_results(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<Option<Vec<GuiHostInfo>>, String> {
    let results = state.scan_results.lock().unwrap();
    if let Some(scan_results) = results.get(&scan_id) {
        // Convert core ScanResults to GUI format
        let gui_hosts = scan_results.hosts.iter().map(|host| {
            GuiHostInfo {
                address: host.address.to_string(),
                hostname: host.hostnames.first().cloned(),
                state: format!("{:?}", host.state),
                ports: host.ports.iter().map(|port| {
                    crate::GuiPortInfo {
                        port: port.port,
                        protocol: format!("{:?}", port.protocol).to_lowercase(),
                        state: format!("{:?}", port.state),
                        service: port.service.as_ref().map(|s| s.name.clone()),
                        version: port.service.as_ref().and_then(|s| s.version.clone()),
                        banner: port.banner.clone(),
                        response_time: port.response_time,
                        confidence: Some(port.service.as_ref().map(|s| s.confidence).unwrap_or(0.0)),
                    }
                }).collect(),
                os_fingerprint: host.os_fingerprint.as_ref().map(|os| {
                    crate::GuiOsFingerprint {
                        family: os.family.clone(),
                        version: os.version.clone(),
                        device_type: os.device_type.clone(),
                        confidence: os.confidence,
                         details: {
                             let mut details = HashMap::new();
                             details.insert("family".to_string(), os.family.clone());
                             if let Some(version) = &os.version {
                                 details.insert("version".to_string(), version.clone());
                             }
                             details
                         },
                    }
                }),
                response_time: host.response_times.first().copied(),
                last_seen: None, // Not available in HostResult
            }
        }).collect();
        Ok(Some(gui_hosts))
    } else {
        Ok(None)
    }
}

/// Export scan results to file
#[tauri::command]
pub async fn export_results(
    scan_id: String,
    format: String,
    file_path: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let results = state.scan_results.lock().unwrap();
    if let Some(scan_results) = results.get(&scan_id) {
        let path = PathBuf::from(file_path);
        
        match format.as_str() {
            "json" => {
                // TODO: Implement proper JSON export
                return Err("JSON export not yet implemented".to_string());
            },
            "xml" => {
                // TODO: Implement proper XML export
                return Err("XML export not yet implemented".to_string());
            },
            _ => return Err("Unsupported export format".to_string()),
         }
    } else {
        Err("Scan results not found".to_string())
    }
}

/// Get application configuration
#[tauri::command]
pub async fn get_config(
    state: State<'_, AppState>,
) -> Result<AppConfig, String> {
    let config = state.config.lock().unwrap();
    Ok(config.clone())
}

/// Update application configuration
#[tauri::command]
pub async fn update_config(
    new_config: AppConfig,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let mut config = state.config.lock().unwrap();
    *config = new_config;
    Ok(())
}

/// Get chart data for visualization
#[tauri::command]
pub async fn get_chart_data(
    scan_id: String,
    chart_type: String,
    state: State<'_, AppState>,
) -> Result<Option<ChartData>, String> {
    let results = state.scan_results.lock().unwrap();
    if let Some(scan_results) = results.get(&scan_id) {
        match chart_type.as_str() {
            "port_distribution" => {
                let mut port_counts: HashMap<u16, usize> = HashMap::new();
                for host in &scan_results.hosts {
                    for port in &host.ports {
                        if matches!(port.state, PortState::Open) {
                            *port_counts.entry(port.port).or_insert(0) += 1;
                        }
                    }
                }
                
                let mut labels = Vec::new();
                let mut data = Vec::new();
                for (port, count) in port_counts {
                    labels.push(port.to_string());
                    data.push(count as f64);
                }
                
                Ok(Some(ChartData {
                    labels,
                    datasets: vec![crate::ChartDataset {
                        label: "Open Ports".to_string(),
                        data,
                        background_color: Some("rgba(54, 162, 235, 0.6)".to_string()),
                        border_color: Some("rgba(54, 162, 235, 1)".to_string()),
                    }],
                }))
            },
            "host_status" => {
                let mut status_counts: HashMap<String, usize> = HashMap::new();
                for host in &scan_results.hosts {
                    let status = format!("{:?}", host.state);
                    *status_counts.entry(status).or_insert(0) += 1;
                }
                
                let mut labels = Vec::new();
                let mut data = Vec::new();
                for (status, count) in status_counts {
                    labels.push(status);
                    data.push(count as f64);
                }
                
                Ok(Some(ChartData {
                    labels,
                    datasets: vec![crate::ChartDataset {
                        label: "Host Status".to_string(),
                        data,
                        background_color: Some("rgba(255, 99, 132, 0.6)".to_string()),
                        border_color: Some("rgba(255, 99, 132, 1)".to_string()),
                    }],
                }))
            },
            _ => Ok(None),
        }
    } else {
        Ok(None)
    }
}

/// Get network topology data
#[tauri::command]
pub async fn get_network_topology(
    scan_id: String,
    state: State<'_, AppState>,
) -> Result<Option<NetworkTopology>, String> {
    let results = state.scan_results.lock().unwrap();
    if let Some(scan_results) = results.get(&scan_id) {
        let mut nodes = Vec::new();
        let mut edges = Vec::new();
        
        // Create nodes for each host
        for host in &scan_results.hosts {
            let mut properties = HashMap::new();
            properties.insert("address".to_string(), host.address.to_string());
            if let Some(hostname) = host.hostnames.first() {
                properties.insert("hostname".to_string(), hostname.clone());
            }
            properties.insert("open_ports".to_string(), 
                host.ports.iter()
                    .filter(|p| matches!(p.state, PortState::Open))
                    .count().to_string());
            
            nodes.push(crate::NetworkNode {
                id: host.address.to_string(),
                label: host.hostnames.first().unwrap_or(&host.address.to_string()).clone(),
                node_type: "host".to_string(),
                status: format!("{:?}", host.state),
                properties,
            });
        }
        
        // Create edges based on network relationships
        // This is a simplified example - in practice, you might want to
        // analyze network topology more sophisticatedly
        for (i, host1) in scan_results.hosts.iter().enumerate() {
            for host2 in scan_results.hosts.iter().skip(i + 1) {
                // Simple subnet-based connection logic
                if let (Ok(addr1), Ok(addr2)) = (host1.address.to_string().parse::<std::net::IpAddr>(), host2.address.to_string().parse::<std::net::IpAddr>()) {
                    if hosts_in_same_subnet(&addr1, &addr2) {
                        edges.push(crate::NetworkEdge {
                            from: host1.address.to_string(),
                            to: host2.address.to_string(),
                            label: Some("subnet".to_string()),
                            edge_type: "network".to_string(),
                            properties: HashMap::new(),
                        });
                    }
                }
            }
        }
        
        Ok(Some(NetworkTopology { nodes, edges }))
    } else {
        Ok(None)
    }
}

/// Validate scan configuration
#[tauri::command]
pub async fn validate_scan_config(
    config: ScanConfig,
) -> Result<bool, String> {
    // Basic validation
    if config.targets.is_empty() {
        return Err("No targets specified".to_string());
    }
    
    if config.timeout_ms == 0 {
        return Err("Timeout must be greater than 0".to_string());
    }
    
    if config.max_concurrent == 0 {
        return Err("Max concurrent must be greater than 0".to_string());
    }
    
    // Validate target formats
    for target in &config.targets {
        if target.trim().is_empty() {
            return Err("Empty target specified".to_string());
        }
        // Add more sophisticated target validation here
    }
    
    Ok(true)
}

/// Get system information
#[tauri::command]
pub async fn get_system_info() -> Result<HashMap<String, String>, String> {
    let mut info = HashMap::new();
    
    info.insert("os".to_string(), std::env::consts::OS.to_string());
    info.insert("arch".to_string(), std::env::consts::ARCH.to_string());
    info.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    
    Ok(info)
}

// Helper function to determine if two IP addresses are in the same subnet
fn hosts_in_same_subnet(addr1: &std::net::IpAddr, addr2: &std::net::IpAddr) -> bool {
    match (addr1, addr2) {
        (std::net::IpAddr::V4(ip1), std::net::IpAddr::V4(ip2)) => {
            // Simple /24 subnet check
            let octets1 = ip1.octets();
            let octets2 = ip2.octets();
            octets1[0] == octets2[0] && octets1[1] == octets2[1] && octets1[2] == octets2[2]
        },
        (std::net::IpAddr::V6(ip1), std::net::IpAddr::V6(ip2)) => {
            // Simple /64 subnet check
            let segments1 = ip1.segments();
            let segments2 = ip2.segments();
            segments1[0..4] == segments2[0..4]
        },
        _ => false,
    }
}
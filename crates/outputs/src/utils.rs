//! Utility functions for output processing
//!
//! This module provides utilities for comparing scan results,
//! generating diffs, and other output-related operations.

use std::collections::{HashMap, HashSet};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::{ScanResults, HostResult, PortResult, PortState, OutputError, OutputResult};

/// Comparison result between two scan results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDiff {
    /// Metadata about the comparison
    pub metadata: DiffMetadata,
    /// Hosts that were added
    pub hosts_added: Vec<HostResult>,
    /// Hosts that were removed
    pub hosts_removed: Vec<HostResult>,
    /// Hosts that changed
    pub hosts_changed: Vec<HostDiff>,
    /// Summary statistics
    pub summary: DiffSummary,
}

/// Metadata about the diff operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffMetadata {
    /// Timestamp when diff was generated
    pub generated_at: std::time::SystemTime,
    /// Source scan metadata
    pub source_scan: String,
    /// Target scan metadata
    pub target_scan: String,
    /// Diff tool version
    pub diff_version: String,
}

/// Differences for a specific host
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostDiff {
    /// Host address
    pub address: String,
    /// State change (if any)
    pub state_change: Option<StateChange>,
    /// Hostname changes
    pub hostname_changes: Vec<String>,
    /// Port changes
    pub port_changes: Vec<PortDiff>,
    /// OS fingerprint changes
    pub os_changes: Option<String>,
}

/// State change information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    /// Previous state
    pub from: String,
    /// New state
    pub to: String,
}

/// Port-specific differences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortDiff {
    /// Port number
    pub port: u16,
    /// Protocol
    pub protocol: String,
    /// Type of change
    pub change_type: PortChangeType,
    /// Previous state (if applicable)
    pub previous_state: Option<String>,
    /// New state (if applicable)
    pub new_state: Option<String>,
    /// Service changes
    pub service_changes: Option<String>,
}

/// Types of port changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortChangeType {
    /// Port was added
    Added,
    /// Port was removed
    Removed,
    /// Port state changed
    StateChanged,
    /// Service information changed
    ServiceChanged,
}

/// Summary of differences
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffSummary {
    /// Total hosts in source scan
    pub source_hosts: usize,
    /// Total hosts in target scan
    pub target_hosts: usize,
    /// Number of hosts added
    pub hosts_added: usize,
    /// Number of hosts removed
    pub hosts_removed: usize,
    /// Number of hosts changed
    pub hosts_changed: usize,
    /// Total ports in source scan
    pub source_ports: usize,
    /// Total ports in target scan
    pub target_ports: usize,
    /// Number of ports added
    pub ports_added: usize,
    /// Number of ports removed
    pub ports_removed: usize,
    /// Number of ports with state changes
    pub ports_changed: usize,
}

/// Compare two scan results and generate a diff
pub fn compare_scan_results(
    source: &ScanResults,
    target: &ScanResults,
) -> OutputResult<ScanDiff> {
    let mut diff = ScanDiff {
        metadata: DiffMetadata {
            generated_at: std::time::SystemTime::now(),
            source_scan: format!("{} ({})", 
                source.metadata.scanner_version,
                source.metadata.start_time.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs()),
            target_scan: format!("{} ({})", 
                target.metadata.scanner_version,
                target.metadata.start_time.duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default().as_secs()),
            diff_version: "cyNetMapper-diff 1.0.0".to_string(),
        },
        hosts_added: Vec::new(),
        hosts_removed: Vec::new(),
        hosts_changed: Vec::new(),
        summary: DiffSummary {
            source_hosts: source.hosts.len(),
            target_hosts: target.hosts.len(),
            hosts_added: 0,
            hosts_removed: 0,
            hosts_changed: 0,
            source_ports: source.hosts.iter().map(|h| h.ports.len()).sum(),
            target_ports: target.hosts.iter().map(|h| h.ports.len()).sum(),
            ports_added: 0,
            ports_removed: 0,
            ports_changed: 0,
        },
    };
    
    // Create maps for efficient lookup
    let source_hosts: HashMap<String, &HostResult> = source.hosts.iter()
        .map(|h| (h.address.clone(), h))
        .collect();
    
    let target_hosts: HashMap<String, &HostResult> = target.hosts.iter()
        .map(|h| (h.address.clone(), h))
        .collect();
    
    let source_addresses: HashSet<String> = source_hosts.keys().cloned().collect();
    let target_addresses: HashSet<String> = target_hosts.keys().cloned().collect();
    
    // Find added hosts
    for address in target_addresses.difference(&source_addresses) {
        if let Some(host) = target_hosts.get(address) {
            diff.hosts_added.push((*host).clone());
            diff.summary.hosts_added += 1;
        }
    }
    
    // Find removed hosts
    for address in source_addresses.difference(&target_addresses) {
        if let Some(host) = source_hosts.get(address) {
            diff.hosts_removed.push((*host).clone());
            diff.summary.hosts_removed += 1;
        }
    }
    
    // Find changed hosts
    for address in source_addresses.intersection(&target_addresses) {
        if let (Some(source_host), Some(target_host)) = 
            (source_hosts.get(address), target_hosts.get(address)) {
            
            if let Some(host_diff) = compare_hosts(source_host, target_host)? {
                diff.summary.hosts_changed += 1;
                
                // Count port changes
                for port_change in &host_diff.port_changes {
                    match port_change.change_type {
                        PortChangeType::Added => diff.summary.ports_added += 1,
                        PortChangeType::Removed => diff.summary.ports_removed += 1,
                        PortChangeType::StateChanged | PortChangeType::ServiceChanged => 
                            diff.summary.ports_changed += 1,
                    }
                }
                
                diff.hosts_changed.push(host_diff);
            }
        }
    }
    
    Ok(diff)
}

/// Compare two hosts and return differences
fn compare_hosts(
    source: &HostResult,
    target: &HostResult,
) -> OutputResult<Option<HostDiff>> {
    let mut changes: Vec<PortDiff> = Vec::new();
    let mut has_changes = false;
    
    // Check state changes
    let state_change = if source.state != target.state {
        has_changes = true;
        Some(StateChange {
            from: format!("{:?}", source.state),
            to: format!("{:?}", target.state),
        })
    } else {
        None
    };
    
    // Check hostname changes
    let source_hostnames: HashSet<&String> = source.hostnames.iter().collect();
    let target_hostnames: HashSet<&String> = target.hostnames.iter().collect();
    
    let hostname_changes: Vec<String> = target_hostnames
        .difference(&source_hostnames)
        .map(|h| format!("Added: {}", h))
        .chain(
            source_hostnames
                .difference(&target_hostnames)
                .map(|h| format!("Removed: {}", h))
        )
        .collect();
    
    if !hostname_changes.is_empty() {
        has_changes = true;
    }
    
    // Compare ports
    let port_changes = compare_ports(&source.ports, &target.ports)?;
    if !port_changes.is_empty() {
        has_changes = true;
    }
    
    // Check OS fingerprint changes
    let os_changes = match (&source.os_fingerprint, &target.os_fingerprint) {
        (None, Some(target_os)) => {
            has_changes = true;
            Some(format!("Added: {} {}", 
                target_os.family, 
                target_os.version.as_deref().unwrap_or("")))
        },
        (Some(source_os), None) => {
            has_changes = true;
            Some(format!("Removed: {} {}", 
                source_os.family, 
                source_os.version.as_deref().unwrap_or("")))
        },
        (Some(source_os), Some(target_os)) => {
            if source_os.family != target_os.family || 
               source_os.version != target_os.version {
                has_changes = true;
                Some(format!("Changed: {} {} -> {} {}", 
                    source_os.family, 
                    source_os.version.as_deref().unwrap_or(""),
                    target_os.family, 
                    target_os.version.as_deref().unwrap_or("")))
            } else {
                None
            }
        },
        (None, None) => None,
    };
    
    if has_changes {
        Ok(Some(HostDiff {
            address: source.address.clone(),
            state_change,
            hostname_changes,
            port_changes,
            os_changes,
        }))
    } else {
        Ok(None)
    }
}

/// Compare port lists and return differences
fn compare_ports(
    source_ports: &[PortResult],
    target_ports: &[PortResult],
) -> OutputResult<Vec<PortDiff>> {
    let mut port_diffs = Vec::new();
    
    // Create maps for efficient lookup
    let source_map: HashMap<(u16, String), &PortResult> = source_ports.iter()
        .map(|p| ((p.port, format!("{:?}", p.protocol)), p))
        .collect();
    
    let target_map: HashMap<(u16, String), &PortResult> = target_ports.iter()
        .map(|p| ((p.port, format!("{:?}", p.protocol)), p))
        .collect();
    
    let source_keys: HashSet<(u16, String)> = source_map.keys().cloned().collect();
    let target_keys: HashSet<(u16, String)> = target_map.keys().cloned().collect();
    
    // Find added ports
    for key in target_keys.difference(&source_keys) {
        if let Some(port) = target_map.get(key) {
            port_diffs.push(PortDiff {
                port: port.port,
                protocol: format!("{:?}", port.protocol),
                change_type: PortChangeType::Added,
                previous_state: None,
                new_state: Some(format!("{:?}", port.state)),
                service_changes: port.service.as_ref()
                    .map(|s| format!("Added: {}", s.name)),
            });
        }
    }
    
    // Find removed ports
    for key in source_keys.difference(&target_keys) {
        if let Some(port) = source_map.get(key) {
            port_diffs.push(PortDiff {
                port: port.port,
                protocol: format!("{:?}", port.protocol),
                change_type: PortChangeType::Removed,
                previous_state: Some(format!("{:?}", port.state)),
                new_state: None,
                service_changes: port.service.as_ref()
                    .map(|s| format!("Removed: {}", s.name)),
            });
        }
    }
    
    // Find changed ports
    for key in source_keys.intersection(&target_keys) {
        if let (Some(source_port), Some(target_port)) = 
            (source_map.get(key), target_map.get(key)) {
            
            let mut change_type = None;
            let mut service_changes = None;
            
            // Check state changes
            if source_port.state != target_port.state {
                change_type = Some(PortChangeType::StateChanged);
            }
            
            // Check service changes
            match (&source_port.service, &target_port.service) {
                (None, Some(target_service)) => {
                    change_type = Some(PortChangeType::ServiceChanged);
                    service_changes = Some(format!("Added: {}", target_service.name));
                },
                (Some(source_service), None) => {
                    change_type = Some(PortChangeType::ServiceChanged);
                    service_changes = Some(format!("Removed: {}", source_service.name));
                },
                (Some(source_service), Some(target_service)) => {
                    if source_service.name != target_service.name ||
                       source_service.version != target_service.version {
                        change_type = Some(PortChangeType::ServiceChanged);
                        service_changes = Some(format!(
                            "Changed: {} {} -> {} {}",
                            source_service.name,
                            source_service.version.as_deref().unwrap_or(""),
                            target_service.name,
                            target_service.version.as_deref().unwrap_or("")
                        ));
                    }
                },
                (None, None) => {},
            }
            
            if let Some(ct) = change_type {
                port_diffs.push(PortDiff {
                    port: source_port.port,
                    protocol: format!("{:?}", source_port.protocol),
                    change_type: ct,
                    previous_state: Some(format!("{:?}", source_port.state)),
                    new_state: Some(format!("{:?}", target_port.state)),
                    service_changes,
                });
            }
        }
    }
    
    Ok(port_diffs)
}

/// Generate a human-readable diff report
pub fn generate_diff_report(diff: &ScanDiff) -> String {
    let mut report = String::new();
    
    // Header
    report.push_str(&format!(
        "cyNetMapper Scan Comparison Report\n"
    ));
    report.push_str(&format!(
        "Generated: {}\n",
        chrono::DateTime::<chrono::Utc>::from(diff.metadata.generated_at)
            .format("%Y-%m-%d %H:%M:%S UTC")
    ));
    report.push_str(&format!(
        "Source: {}\n",
        diff.metadata.source_scan
    ));
    report.push_str(&format!(
        "Target: {}\n\n",
        diff.metadata.target_scan
    ));
    
    // Summary
    report.push_str("SUMMARY\n");
    report.push_str("=======\n");
    report.push_str(&format!(
        "Hosts: {} -> {} ({:+} hosts)\n",
        diff.summary.source_hosts,
        diff.summary.target_hosts,
        diff.summary.target_hosts as i32 - diff.summary.source_hosts as i32
    ));
    report.push_str(&format!(
        "  Added: {}\n",
        diff.summary.hosts_added
    ));
    report.push_str(&format!(
        "  Removed: {}\n",
        diff.summary.hosts_removed
    ));
    report.push_str(&format!(
        "  Changed: {}\n\n",
        diff.summary.hosts_changed
    ));
    
    report.push_str(&format!(
        "Ports: {} -> {} ({:+} ports)\n",
        diff.summary.source_ports,
        diff.summary.target_ports,
        diff.summary.target_ports as i32 - diff.summary.source_ports as i32
    ));
    report.push_str(&format!(
        "  Added: {}\n",
        diff.summary.ports_added
    ));
    report.push_str(&format!(
        "  Removed: {}\n",
        diff.summary.ports_removed
    ));
    report.push_str(&format!(
        "  Changed: {}\n\n",
        diff.summary.ports_changed
    ));
    
    // Detailed changes
    if !diff.hosts_added.is_empty() {
        report.push_str("HOSTS ADDED\n");
        report.push_str("===========\n");
        for host in &diff.hosts_added {
            report.push_str(&format!(
                "+ {} ({} ports)\n",
                host.address,
                host.ports.len()
            ));
        }
        report.push('\n');
    }
    
    if !diff.hosts_removed.is_empty() {
        report.push_str("HOSTS REMOVED\n");
        report.push_str("=============\n");
        for host in &diff.hosts_removed {
            report.push_str(&format!(
                "- {} ({} ports)\n",
                host.address,
                host.ports.len()
            ));
        }
        report.push('\n');
    }
    
    if !diff.hosts_changed.is_empty() {
        report.push_str("HOSTS CHANGED\n");
        report.push_str("=============\n");
        for host_diff in &diff.hosts_changed {
            report.push_str(&format!("Host: {}\n", host_diff.address));
            
            if let Some(state_change) = &host_diff.state_change {
                report.push_str(&format!(
                    "  State: {} -> {}\n",
                    state_change.from,
                    state_change.to
                ));
            }
            
            for hostname_change in &host_diff.hostname_changes {
                report.push_str(&format!("  Hostname: {}\n", hostname_change));
            }
            
            if let Some(os_change) = &host_diff.os_changes {
                report.push_str(&format!("  OS: {}\n", os_change));
            }
            
            for port_change in &host_diff.port_changes {
                match port_change.change_type {
                    PortChangeType::Added => {
                        report.push_str(&format!(
                            "  + Port {}/{}: {}\n",
                            port_change.port,
                            port_change.protocol,
                            port_change.new_state.as_deref().unwrap_or("unknown")
                        ));
                    },
                    PortChangeType::Removed => {
                        report.push_str(&format!(
                            "  - Port {}/{}: {}\n",
                            port_change.port,
                            port_change.protocol,
                            port_change.previous_state.as_deref().unwrap_or("unknown")
                        ));
                    },
                    PortChangeType::StateChanged => {
                        report.push_str(&format!(
                            "  ~ Port {}/{}: {} -> {}\n",
                            port_change.port,
                            port_change.protocol,
                            port_change.previous_state.as_deref().unwrap_or("unknown"),
                            port_change.new_state.as_deref().unwrap_or("unknown")
                        ));
                    },
                    PortChangeType::ServiceChanged => {
                        report.push_str(&format!(
                            "  ~ Port {}/{} service: {}\n",
                            port_change.port,
                            port_change.protocol,
                            port_change.service_changes.as_deref().unwrap_or("changed")
                        ));
                    },
                }
            }
            
            report.push('\n');
        }
    }
    
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ScanResults, HostResult, PortResult, ServiceInfo, HostState, PortState, Protocol};
    
    #[test]
    fn test_scan_diff() {
        let mut source = ScanResults::default();
        let mut target = ScanResults::default();
        
        // Add a host to source
        source.hosts.push(HostResult {
            address: "192.168.1.1".to_string(),
            state: HostState::Up,
            hostnames: vec![],
            ports: vec![PortResult {
                port: 80,
                protocol: Protocol::Tcp,
                state: PortState::Open,
                service: Some(ServiceInfo {
                    name: "http".to_string(),
                    version: Some("1.0".to_string()),
                    product: None,
                    extra_info: None,
                    confidence: 0.9,
                }),
                banner: None,
                response_time: None,
            }],
            os_fingerprint: None,
            discovery_method: None,
            response_times: vec![],
        });
        
        // Add same host to target but with different port state
        target.hosts.push(HostResult {
            address: "192.168.1.1".to_string(),
            state: HostState::Up,
            hostnames: vec![],
            ports: vec![PortResult {
                port: 80,
                protocol: Protocol::Tcp,
                state: PortState::Closed,
                service: None,
                banner: None,
                response_time: None,
            }],
            os_fingerprint: None,
            discovery_method: None,
            response_times: vec![],
        });
        
        let diff = compare_scan_results(&source, &target).unwrap();
        
        assert_eq!(diff.hosts_added.len(), 0);
        assert_eq!(diff.hosts_removed.len(), 0);
        assert_eq!(diff.hosts_changed.len(), 1);
        assert_eq!(diff.hosts_changed[0].port_changes.len(), 1);
        
        let port_change = &diff.hosts_changed[0].port_changes[0];
        assert_eq!(port_change.port, 80);
        assert!(matches!(port_change.change_type, PortChangeType::StateChanged));
    }
    
    #[test]
    fn test_diff_report_generation() {
        let diff = ScanDiff {
            metadata: DiffMetadata {
                generated_at: std::time::SystemTime::now(),
                source_scan: "scan1".to_string(),
                target_scan: "scan2".to_string(),
                diff_version: "1.0.0".to_string(),
            },
            hosts_added: vec![],
            hosts_removed: vec![],
            hosts_changed: vec![],
            summary: DiffSummary {
                source_hosts: 1,
                target_hosts: 1,
                hosts_added: 0,
                hosts_removed: 0,
                hosts_changed: 0,
                source_ports: 1,
                target_ports: 1,
                ports_added: 0,
                ports_removed: 0,
                ports_changed: 0,
            },
        };
        
        let report = generate_diff_report(&diff);
        assert!(report.contains("cyNetMapper Scan Comparison Report"));
        assert!(report.contains("SUMMARY"));
    }
}
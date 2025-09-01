//! CLI command implementations

use anyhow::{Context, Result};
use colored::*;
use cynetmapper_core::{
    config::Config,
    types::{IpAddr, Protocol},
};
use cynetmapper_probes::{ProbeManager, ComprehensiveProbeResult};
use std::{
    path::PathBuf,
    sync::Arc,
    time::Instant,
};
use tracing::{debug, info, warn};

use crate::{
    utils,
    output::OutputManager,
    scanner::CliScanner,
    Cli, DiscoveryMethod, ScanType, ConfigFormat,
};

/// Execute host discovery command
pub async fn execute_discovery(
    targets: &[String],
    method: &DiscoveryMethod,
    config: &Arc<Config>,
    cli: &Cli,
) -> Result<()> {
    let start_time = Instant::now();
    
    if !cli.quiet {
        println!("{}", "Starting host discovery...".cyan());
        println!("{}: {:?}", "Method".bold(), method);
        println!("{}: {}", "Targets".bold(), targets.join(", "));
        println!();
    }
    
    // Parse targets
    let parsed_targets = utils::parse_targets(targets)?;
    
    // Create probe manager
    let probe_manager = ProbeManager::new(config.clone());
    
    let mut discovered_hosts = Vec::new();
    let mut total_hosts = 0;
    
    for target in parsed_targets {
        total_hosts += 1;
        
        if !cli.quiet {
            print!("{} {}", "Discovering".cyan(), target);
        }
        
        let result = match method {
            DiscoveryMethod::Icmp => {
                probe_manager.discover_host(target).await
            }
            DiscoveryMethod::Tcp => {
                // TCP discovery using common ports
                discover_host_tcp(&probe_manager, target).await
            }
            DiscoveryMethod::Udp => {
                // UDP discovery using common ports
                discover_host_udp(&probe_manager, target).await
            }
            DiscoveryMethod::Arp => {
                // ARP discovery (not implemented yet)
                warn!("ARP discovery not implemented yet");
                continue;
            }
        };
        
        match result {
            Ok(probe_result) => {
                if probe_result.is_reachable() {
                    discovered_hosts.push(target);
                    if !cli.quiet {
                        println!(" - {}", "UP".green());
                    }
                } else {
                    if !cli.quiet {
                        println!(" - {}", "DOWN".red());
                    }
                }
            }
            Err(e) => {
                if !cli.quiet {
                    println!(" - {}: {}", "ERROR".red(), e);
                }
                warn!("Discovery failed for {}: {}", target, e);
            }
        }
    }
    
    let elapsed = start_time.elapsed();
    
    if !cli.quiet {
        println!();
        println!("{}", "Discovery Summary:".bold());
        println!("{}: {}", "Total hosts".cyan(), total_hosts);
        println!("{}: {}", "Hosts up".green(), discovered_hosts.len());
        println!("{}: {}", "Hosts down".red(), total_hosts - discovered_hosts.len());
        println!("{}: {:.2}s", "Time elapsed".cyan(), elapsed.as_secs_f64());
        
        if !discovered_hosts.is_empty() {
            println!();
            println!("{}", "Discovered hosts:".bold());
            for host in &discovered_hosts {
                println!("  {}", host.to_string().green());
            }
        }
    }
    
    // Output results in specified format
    let output_manager = OutputManager::new(config.clone());
    let discovery_results: Vec<ComprehensiveProbeResult> = discovered_hosts
        .into_iter()
        .map(|host| {
            let mut result = ComprehensiveProbeResult::new(host, 0, Protocol::Icmp);
            result.state = cynetmapper_core::types::PortState::Open;
            result
        })
        .collect();
    
    output_manager.output_results(&discovery_results).await?;
    
    Ok(())
}

/// Execute port scanning command
pub async fn execute_scan(
    targets: &[String],
    ports: &str,
    scan_type: &ScanType,
    config: &Arc<Config>,
    cli: &Cli,
) -> Result<()> {
    let start_time = Instant::now();
    
    if !cli.quiet {
        println!("{}", "Starting port scan...".cyan());
        println!("{}: {:?}", "Scan type".bold(), scan_type);
        println!("{}: {}", "Targets".bold(), targets.join(", "));
        println!("{}: {}", "Ports".bold(), ports);
        println!();
    }
    
    // Parse targets and ports
    let parsed_targets = utils::parse_targets(targets)?;
    let parsed_ports = utils::parse_ports(ports)?;
    
    // Determine protocol based on scan type
    let protocol = match scan_type {
        ScanType::TcpConnect | ScanType::TcpSyn => Protocol::Tcp,
        ScanType::UdpScan => Protocol::Udp,
        ScanType::IcmpScan => Protocol::Icmp,
    };
    
    // Create scanner
    let scanner = CliScanner::new(config.clone())?;
    
    // Execute scan
    let results = scanner.scan(
        parsed_targets,
        parsed_ports,
        vec![protocol],
        None, // No progress bar for subcommand
    ).await?;
    
    let elapsed = start_time.elapsed();
    
    if !cli.quiet {
        println!();
        println!("{}", "Scan Summary:".bold());
        println!("{}: {}", "Total ports scanned".cyan(), results.len());
        
        let open_ports = results.iter().filter(|r| r.is_reachable()).count();
        let closed_ports = results.len() - open_ports;
        
        println!("{}: {}", "Open ports".green(), open_ports);
        println!("{}: {}", "Closed/filtered ports".red(), closed_ports);
        println!("{}: {:.2}s", "Time elapsed".cyan(), elapsed.as_secs_f64());
        
        if open_ports > 0 {
            println!();
            println!("{}", "Open ports:".bold());
            for result in results.iter().filter(|r| r.is_reachable()) {
                let service = result.get_service_name().unwrap_or("unknown");
                println!("  {}:{}/{:?} - {}", 
                    result.target.to_string().cyan(),
                    result.port.to_string().green(),
                    result.protocol,
                    service.yellow()
                );
            }
        }
    }
    
    // Output results
    let output_manager = OutputManager::new(config.clone());
    output_manager.output_results(&results).await?;
    
    Ok(())
}

/// Execute configuration file generation
pub async fn execute_config_generation(
    output_path: &PathBuf,
    format: &ConfigFormat,
    config: &Arc<Config>,
) -> Result<()> {
    println!("{}", "Generating configuration file...".cyan());
    println!("{}: {:?}", "Output path".bold(), output_path);
    println!("{}: {:?}", "Format".bold(), format);
    
    match format {
        ConfigFormat::Toml => {
            config.save_toml(output_path)
                .with_context(|| format!("Failed to save TOML config to {:?}", output_path))?
        }
        ConfigFormat::Yaml => {
            config.save_yaml(output_path)
                .with_context(|| format!("Failed to save YAML config to {:?}", output_path))?
        }
        ConfigFormat::Json => {
            config.save_json(output_path)
                .with_context(|| format!("Failed to save JSON config to {:?}", output_path))?
        }
    }
    
    println!("{}", format!("Configuration saved to {:?}", output_path).green());
    
    Ok(())
}

/// Execute version command
pub async fn execute_version() -> Result<()> {
    println!("{} {}", "cyNetMapper".bold().cyan(), env!("CARGO_PKG_VERSION"));
    println!("{}", env!("CARGO_PKG_DESCRIPTION"));
    println!();
    
    println!("{}", "Build Information:".bold());
    println!("  {}: {}", "Version".cyan(), env!("CARGO_PKG_VERSION"));
    println!("  {}: {}", "Git commit".cyan(), option_env!("GIT_HASH").unwrap_or("unknown"));
    println!("  {}: {}", "Build date".cyan(), option_env!("BUILD_DATE").unwrap_or("unknown"));
    println!("  {}: {}", "Rust version".cyan(), option_env!("RUSTC_VERSION").unwrap_or("unknown"));
    println!();
    
    println!("{}", "Features:".bold());
    println!("  {}: {}", "TCP Connect".cyan(), "✓".green());
    println!("  {}: {}", "UDP Scan".cyan(), "✓".green());
    println!("  {}: {}", "ICMP Ping".cyan(), "✓".green());
    println!("  {}: {}", "Service Detection".cyan(), "✓".green());
    println!("  {}: {}", "Banner Grabbing".cyan(), "✓".green());
    println!("  {}: {}", "OS Fingerprinting".cyan(), "✓".green());
    
    #[cfg(feature = "raw-sockets")]
    println!("  {}: {}", "Raw Sockets".cyan(), "✓".green());
    #[cfg(not(feature = "raw-sockets"))]
    println!("  {}: {}", "Raw Sockets".cyan(), "✗".red());
    
    println!();
    
    println!("{}", "Output Formats:".bold());
    println!("  {}: {}", "Human-readable".cyan(), "✓".green());
    
    #[cfg(feature = "json-output")]
    println!("  {}: {}", "JSON".cyan(), "✓".green());
    #[cfg(not(feature = "json-output"))]
    println!("  {}: {}", "JSON".cyan(), "✗".red());
    
    #[cfg(feature = "yaml-output")]
    println!("  {}: {}", "YAML".cyan(), "✓".green());
    #[cfg(not(feature = "yaml-output"))]
    println!("  {}: {}", "YAML".cyan(), "✗".red());
    
    #[cfg(feature = "xml-output")]
    println!("  {}: {}", "XML".cyan(), "✓".green());
    #[cfg(not(feature = "xml-output"))]
    println!("  {}: {}", "XML".cyan(), "✗".red());
    
    println!("  {}: {}", "CSV".cyan(), "✓".green());
    
    println!();
    println!("{}", "Repository: https://github.com/matteosala/cyNetMapper".dimmed());
    println!("{}", "License: MIT OR Apache-2.0".dimmed());
    
    Ok(())
}

/// Discover host using TCP probes
async fn discover_host_tcp(
    probe_manager: &ProbeManager,
    target: IpAddr,
) -> Result<ComprehensiveProbeResult> {
    let common_tcp_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900];
    
    for &port in &common_tcp_ports {
        match probe_manager.scan_port(target, port, Protocol::Tcp).await {
            Ok(result) => {
                if result.is_reachable() {
                    debug!("Host {} discovered via TCP port {}", target, port);
                    return Ok(result);
                }
            }
            Err(_) => continue,
        }
    }
    
    // If no TCP ports respond, return a negative result
    let mut result = ComprehensiveProbeResult::new(target, 0, Protocol::Tcp);
    result.state = cynetmapper_core::types::PortState::Filtered;
    Ok(result)
}

/// Discover host using UDP probes
async fn discover_host_udp(
    probe_manager: &ProbeManager,
    target: IpAddr,
) -> Result<ComprehensiveProbeResult> {
    let common_udp_ports = [53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 520, 631, 1434, 1900, 4500, 5353];
    
    for &port in &common_udp_ports {
        match probe_manager.scan_port(target, port, Protocol::Udp).await {
            Ok(result) => {
                if result.is_reachable() {
                    debug!("Host {} discovered via UDP port {}", target, port);
                    return Ok(result);
                }
            }
            Err(_) => continue,
        }
    }
    
    // If no UDP ports respond, return a negative result
    let mut result = ComprehensiveProbeResult::new(target, 0, Protocol::Udp);
    result.state = cynetmapper_core::types::PortState::Filtered;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cynetmapper_core::config::Config;
    use std::sync::Arc;
    use tempfile::NamedTempFile;

    #[tokio::test]
    async fn test_execute_version() {
        let result = execute_version().await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_config_generation() {
        let config = Arc::new(Config::default());
        let temp_file = NamedTempFile::new().unwrap();
        let output_path = temp_file.path().to_path_buf();
        
        let result = execute_config_generation(
            &output_path,
            &ConfigFormat::Toml,
            &config,
        ).await;
        
        assert!(result.is_ok());
        assert!(output_path.exists());
    }

    #[tokio::test]
    async fn test_discover_host_tcp() {
        let config = Arc::new(Config::default());
        let probe_manager = ProbeManager::new(config);
        
        // Test with localhost
        let target = "127.0.0.1".parse().unwrap();
        let result = discover_host_tcp(&probe_manager, target).await;
        
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_discover_host_udp() {
        let config = Arc::new(Config::default());
        let probe_manager = ProbeManager::new(config);
        
        // Test with localhost
        let target = "127.0.0.1".parse().unwrap();
        let result = discover_host_udp(&probe_manager, target).await;
        
        assert!(result.is_ok());
    }
}
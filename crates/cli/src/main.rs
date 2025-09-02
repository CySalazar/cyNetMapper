//! cyNetMapper CLI - Network Scanner Command Line Interface

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use cynetmapper_core::{
    config::Config,
    scanner::{Scanner, ScanOptions},
    types::{Target, PortRange, IpAddr, Protocol},
};
use std::{
    path::PathBuf,
    sync::Arc,
};
use tracing::{debug, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, Layer};

/// cyNetMapper - Advanced Network Scanner
#[derive(Parser, Debug)]
#[command(name = "cynetmapper")]
#[command(version = env!("CARGO_PKG_VERSION"))]
#[command(about = "Advanced network scanner and security assessment tool")]
struct Cli {
    /// Target specification (IP, CIDR, hostname, or range)
    #[arg(value_name = "TARGET")]
    targets: Vec<String>,

    /// Ports to scan (e.g., 22,80,443 or 1-1000)
    #[arg(short = 'p', long = "ports", value_name = "PORTS")]
    ports: Option<String>,

    /// Output format
    #[arg(short = 'o', long = "output", value_enum, default_value = "human")]
    output_format: CliOutputFormat,

    /// Output file
    #[arg(short = 'f', long = "file", value_name = "FILE")]
    output_file: Option<PathBuf>,

    /// Verbose output
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    verbose: u8,

    /// Quiet mode
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Maximum concurrent connections
    #[arg(long = "max-concurrent", value_name = "NUM", default_value = "100")]
    max_concurrent: usize,

    /// Connection timeout in seconds
    #[arg(long = "timeout", value_name = "SECONDS", default_value = "3")]
    timeout: u64,
}

#[derive(ValueEnum, Clone, Debug)]
enum CliOutputFormat {
    Human,
    Json,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    init_logging(&cli).context("Failed to initialize logging")?;

    info!("cyNetMapper CLI starting");
    debug!("CLI arguments: {:?}", cli);

    // Check if targets are provided
    if cli.targets.is_empty() {
        eprintln!("{}", "Error: No targets specified".red().bold());
        eprintln!("Use --help for usage information");
        std::process::exit(1);
    }

    // Create a basic config
    let config = Arc::new(Config::default());
    
    // Execute scan
    execute_scan(&cli, &config).await?;
    
    Ok(())
}

/// Initialize logging based on CLI arguments
fn init_logging(cli: &Cli) -> Result<()> {
    let log_level = if cli.quiet {
        tracing::Level::ERROR
    } else {
        match cli.verbose {
            0 => tracing::Level::WARN,
            1 => tracing::Level::INFO,
            2 => tracing::Level::DEBUG,
            _ => tracing::Level::TRACE,
        }
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer()
                .with_target(false)
                .with_level(true)
                .with_filter(tracing_subscriber::filter::LevelFilter::from_level(log_level)),
        )
        .init();

    Ok(())
}

/// Parse port range from string
fn parse_port_range(ports: &str) -> Result<PortRange> {
    if ports.contains(',') {
        // Parse comma-separated list
        let port_list: Result<Vec<u16>, _> = ports
            .split(',')
            .map(|p| p.trim().parse::<u16>())
            .collect();
        Ok(PortRange::list(port_list.with_context(|| "Invalid port in list")?))
    } else if ports.contains('-') {
        // Parse range
        let parts: Vec<&str> = ports.split('-').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Invalid port range format"));
        }
        let start = parts[0].trim().parse::<u16>()
            .with_context(|| "Invalid start port")?;
        let end = parts[1].trim().parse::<u16>()
            .with_context(|| "Invalid end port")?;
        Ok(PortRange::range(start, end))
    } else {
        // Single port
        let port = ports.trim().parse::<u16>()
            .with_context(|| "Invalid port number")?;
        Ok(PortRange::single(port))
    }
}

/// Execute the scan
async fn execute_scan(cli: &Cli, config: &Arc<Config>) -> Result<()> {
    info!("Starting cyNetMapper scan");
    
    // Parse targets
    let mut targets = Vec::new();
    for target_str in &cli.targets {
        let target = target_str.parse::<Target>()
            .with_context(|| format!("Failed to parse target: {}", target_str))?;
        targets.push(target);
    }
    
    if targets.is_empty() {
        println!("{}", "No valid targets specified".red());
        return Ok(());
    }
    
    // Parse ports
    let port_range = if let Some(ports) = &cli.ports {
        parse_port_range(ports)
            .with_context(|| format!("Failed to parse ports: {}", ports))?
    } else {
        PortRange::range(1, 1000)
    };
    
    println!("Targets: {}", targets.len());
    println!("Ports: {}", port_range.to_string().yellow());
    
    // Create scan options
    let scan_options = ScanOptions {
        max_concurrency: cli.max_concurrent,
        timeout: std::time::Duration::from_secs(cli.timeout),
        protocols: vec![Protocol::Tcp], // Only TCP for CLI
        host_discovery: true, // Enable host discovery to populate results.hosts
        ..Default::default()
    };
    
    // Create scanner and execute scan
    let mut scanner = Scanner::new(config.as_ref().clone())
        .context("Failed to create scanner")?;
    
    debug!("Executing scan with core scanner");
    let scan_results = scanner.scan(targets, port_range, scan_options).await
        .context("Failed to execute scan")?;
    
    // Display results
    println!("\n{}", "Scan Results:".green().bold());
    println!("Debug: Found {} hosts, {} ports total", scan_results.hosts.len(), scan_results.ports.len());
    
    for host_result in &scan_results.hosts {
        println!("\nHost: {} (state: {:?})", host_result.address.to_string().cyan(), host_result.state);
        
        if let Some(hostname) = &host_result.hostname {
            println!("  Hostname: {}", hostname.yellow());
        }
        
        // Get open ports for this host
        let open_ports = scan_results.open_ports_for_host(&host_result.address);
        println!("  Debug: Found {} open ports for this host", open_ports.len());
        
        if open_ports.is_empty() {
            println!("  {}", "No open ports found".yellow());
        } else {
            println!("  Open ports:");
            for port_result in open_ports {
                let service_info = if let Some(service) = &port_result.service {
                    format!(" ({})", service)
                } else {
                    String::new()
                };
                println!("    {}/{}{}", 
                    port_result.address.port(), 
                    port_result.protocol.to_string().to_lowercase(),
                    service_info.green()
                );
            }
        }
    }
    
    println!("\n{}", "Scan completed".green().bold());
    info!("Scan completed successfully");
    
    Ok(())
}
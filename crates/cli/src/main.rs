//! cyNetMapper CLI - Network Scanner Command Line Interface

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;
use cynetmapper_core::{
    config::Config,
    types::{Target, PortRange, IpAddr},
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
    println!("{}", "Starting cyNetMapper scan...".green().bold());
    
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
    
    // Simple TCP connect scan
    for target in targets {
        println!("\nScanning {}...", target.to_string().cyan());
        
        let mut open_ports = Vec::new();
        
        for port in port_range.expand() {
            let target_ip = match &target {
                 Target::Ip(ip) => *ip,
                 Target::Hostname(hostname) => {
                     // For simplicity, skip hostname resolution for now
                     println!("  Skipping hostname: {}", hostname);
                     continue;
                 },
                 _ => {
                     println!("  Skipping complex target: {}", target);
                     continue;
                 }
             };
             let addr = format!("{}:{}", target_ip, port);
            
            match tokio::time::timeout(
                std::time::Duration::from_secs(cli.timeout),
                tokio::net::TcpStream::connect(&addr)
            ).await {
                Ok(Ok(_)) => {
                    open_ports.push(port);
                    println!("  {}/tcp {}", port, "open".green());
                },
                _ => {
                    if cli.verbose > 0 {
                        println!("  {}/tcp {}", port, "closed".red());
                    }
                }
            }
        }
        
        if open_ports.is_empty() {
            println!("  {}", "No open ports found".yellow());
        } else {
            println!("  Found {} open ports", open_ports.len().to_string().green());
        }
    }
    
    println!("\n{}", "Scan completed".green().bold());
    
    Ok(())
}
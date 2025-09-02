//! # cyNetMapper Core
//!
//! Core discovery engine for cross-platform network mapping and discovery.
//! Provides the fundamental building blocks for host discovery, port scanning,
//! service detection, and OS fingerprinting.
//!
//! ## Features
//!
//! - **Host Discovery**: ARP, ICMP, TCP, UDP probes
//! - **Port Scanning**: TCP Connect, SYN, UDP scanning
//! - **Service Detection**: Banner grabbing, protocol fingerprinting
//! - **OS Fingerprinting**: Passive and active techniques
//! - **Rate Limiting**: Adaptive timing and congestion control
//! - **Security**: Authorization checks and safe defaults
//!
//! ## Example
//!
//! ```rust,no_run
//! use cynetmapper_core::{
//!     Scanner, ScanConfig, Target, Profile
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ScanConfig::builder()
//!         .profile(Profile::Safe)
//!         .target("192.168.1.0/24".parse()?)
//!         .build();
//!
//!     let scanner = Scanner::new(config).await?;
//!     let results = scanner.scan().await?;
//!
//!     println!("Found {} hosts", results.hosts().len());
//!     Ok(())
//! }
//! ```

pub mod config;
pub mod discovery;
pub mod error;
pub mod evasion;
pub mod network;
pub mod rate_limiter;
pub mod results;
pub mod scanner;
pub mod security;
pub mod timing;
pub mod types;

// Re-export main types
pub use config::{Config};
pub use discovery::{DiscoveryEngine};
pub use error::{Error, Result};
pub use evasion::{EvasionConfig, EvasionManager, EvasionTechnique};
pub use network::{NetworkScanner};
pub use results::{ScanResults, HostResult, PortResult};
pub use scanner::Scanner;
pub use security::{SecurityContext};
pub use timing::{TimingController};
pub use types::{IpAddr, PortRange, Protocol, Target};

/// Current version of the cyNetMapper core library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// User-Agent string for HTTP requests
pub const USER_AGENT: &str = concat!("cyNetMapper/", env!("CARGO_PKG_VERSION"));

/// Default timeout for network operations (in seconds)
pub const DEFAULT_TIMEOUT: u64 = 30;

/// Maximum number of concurrent operations
pub const MAX_CONCURRENCY: usize = 1000;

/// Minimum delay between probes (in milliseconds)
pub const MIN_PROBE_DELAY: u64 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_user_agent() {
        assert!(USER_AGENT.starts_with("cyNetMapper/"));
    }

    #[test]
    fn test_constants() {
        assert!(DEFAULT_TIMEOUT > 0);
        assert!(MAX_CONCURRENCY > 0);
        assert!(MIN_PROBE_DELAY > 0);
    }
}
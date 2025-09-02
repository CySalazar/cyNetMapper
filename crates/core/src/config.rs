//! Configuration management for cyNetMapper

use crate::error::{ConfigError, Error, Result};
use crate::types::{PortRange, Protocol, Target};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

/// Main configuration structure for cyNetMapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Scan configuration
    pub scan: ScanConfig,
    /// Timing configuration
    pub timing: TimingConfig,
    /// Output configuration
    pub output: OutputConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Platform-specific configuration
    pub platform: PlatformConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

/// Scan-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    /// Targets to scan
    pub targets: Vec<Target>,
    /// Ports to scan
    pub ports: PortRange,
    /// Protocols to use
    pub protocols: Vec<Protocol>,
    /// Scan profile
    pub profile: ScanProfile,
    /// Enable host discovery
    pub host_discovery: bool,
    /// Enable port scanning
    pub port_scanning: bool,
    /// Enable service detection
    pub service_detection: bool,
    /// Enable OS fingerprinting
    pub os_fingerprinting: bool,
    /// Enable banner grabbing
    pub banner_grabbing: bool,
    /// Maximum number of concurrent scans
    pub max_concurrency: usize,
    /// Source IP address (if specified)
    pub source_ip: Option<IpAddr>,
    /// Source port range
    pub source_ports: Option<PortRange>,
    /// Network interface to use
    pub interface: Option<String>,
    /// Enable IPv6 scanning
    pub ipv6: bool,
    /// Randomize target order
    pub randomize_targets: bool,
    /// Randomize port order
    pub randomize_ports: bool,
}

/// Timing configuration for scans
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingConfig {
    /// Connection timeout
    pub connect_timeout: Duration,
    /// Read timeout for banner grabbing
    pub read_timeout: Duration,
    /// Overall scan timeout
    pub scan_timeout: Option<Duration>,
    /// Delay between probes
    pub probe_delay: Duration,
    /// Maximum retries for failed probes
    pub max_retries: u32,
    /// Retry delay multiplier
    pub retry_multiplier: f64,
    /// Rate limiting (probes per second)
    pub rate_limit: Option<f64>,
    /// Adaptive timing
    pub adaptive_timing: bool,
    /// Timing template
    pub timing_template: TimingTemplate,
    /// Advanced timing parameters
    pub advanced: AdvancedTimingConfig,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// Output format
    pub format: OutputFormat,
    /// Output file path
    pub file: Option<PathBuf>,
    /// Include timestamps
    pub timestamps: bool,
    /// Include scan statistics
    pub statistics: bool,
    /// Include debug information
    pub debug_info: bool,
    /// Pretty print JSON
    pub pretty_json: bool,
    /// Compress output
    pub compress: bool,
    /// Include only open ports
    pub open_only: bool,
    /// Include host discovery results
    pub include_host_discovery: bool,
    /// Include failed probes
    pub include_failed: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Enable privilege checks
    pub privilege_checks: bool,
    /// Require explicit consent for dangerous operations
    pub require_consent: bool,
    /// Enable audit logging
    pub audit_logging: bool,
    /// Audit log file path
    pub audit_log_file: Option<PathBuf>,
    /// Rate limiting policies
    pub rate_limit_policies: HashMap<String, RateLimitPolicy>,
    /// Allowed target networks (CIDR)
    pub allowed_networks: Vec<String>,
    /// Blocked target networks (CIDR)
    pub blocked_networks: Vec<String>,
    /// Maximum scan duration
    pub max_scan_duration: Option<Duration>,
    /// Enable safe mode (conservative settings)
    pub safe_mode: bool,
}

/// Platform-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Enable raw sockets (if available)
    pub raw_sockets: bool,
    /// Use system resolver
    pub system_resolver: bool,
    /// Custom DNS servers
    pub dns_servers: Vec<IpAddr>,
    /// Socket buffer sizes
    pub socket_buffer_size: Option<usize>,
    /// Enable TCP keepalive
    pub tcp_keepalive: bool,
    /// TCP keepalive settings
    pub tcp_keepalive_time: Option<Duration>,
    /// Enable SO_REUSEADDR
    pub reuse_addr: bool,
    /// Enable SO_REUSEPORT (Linux/BSD)
    pub reuse_port: bool,
    /// Custom user agent for HTTP probes
    pub user_agent: Option<String>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Log to file
    pub file: Option<PathBuf>,
    /// Log to console
    pub console: bool,
    /// Include timestamps in logs
    pub timestamps: bool,
    /// Include thread IDs
    pub thread_ids: bool,
    /// Include module names
    pub module_names: bool,
    /// Log format
    pub format: LogFormat,
    /// Enable structured logging (JSON)
    pub structured: bool,
}

/// Scan profiles with predefined settings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanProfile {
    /// Fast scan with minimal probes
    Fast,
    /// Balanced scan with moderate thoroughness
    Balanced,
    /// Thorough scan with comprehensive probes
    Thorough,
    /// Stealth scan with evasion techniques
    Stealth,
    /// Aggressive scan with maximum speed
    Aggressive,
    /// Custom profile
    Custom,
}

/// Timing templates
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TimingTemplate {
    /// Paranoid timing (very slow)
    T0,
    /// Sneaky timing (slow)
    T1,
    /// Polite timing (slow)
    T2,
    /// Normal timing (default)
    T3,
    /// Aggressive timing (fast)
    T4,
    /// Insane timing (very fast)
    T5,
}

/// Output formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OutputFormat {
    /// JSON format
    Json,
    /// Nmap XML format
    NmapXml,
    /// CSV format
    Csv,
    /// Plain text format
    Text,
    /// YAML format
    Yaml,
}

/// Log levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Error level
    Error,
    /// Warning level
    Warn,
    /// Info level
    Info,
    /// Debug level
    Debug,
    /// Trace level
    Trace,
}

/// Log formats
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Human-readable format
    Human,
    /// JSON format
    Json,
    /// Compact format
    Compact,
}

/// Rate limiting policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitPolicy {
    /// Maximum requests per time window
    pub max_requests: u32,
    /// Time window duration
    pub window: Duration,
    /// Burst allowance
    pub burst: Option<u32>,
}

/// Advanced timing configuration compatible with nmap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvancedTimingConfig {
    /// Minimum RTT timeout
    pub min_rtt_timeout: Duration,
    /// Maximum RTT timeout
    pub max_rtt_timeout: Duration,
    /// Initial RTT timeout
    pub initial_rtt_timeout: Duration,
    /// Maximum host group size
    pub max_hostgroup: u32,
    /// Minimum host group size
    pub min_hostgroup: u32,
    /// Maximum parallelism
    pub max_parallelism: u32,
    /// Minimum parallelism
    pub min_parallelism: u32,
    /// Maximum scan delay
    pub max_scan_delay: Duration,
    /// Minimum scan delay
    pub min_scan_delay: Duration,
    /// Host timeout
    pub host_timeout: Option<Duration>,
    /// Defeat reset rate limiting
    pub defeat_rst_ratelimit: bool,
    /// Defeat ICMP rate limiting
    pub defeat_icmp_ratelimit: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            timing: TimingConfig::default(),
            output: OutputConfig::default(),
            security: SecurityConfig::default(),
            platform: PlatformConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: PortRange::TopPorts(1000),
            protocols: vec![Protocol::Tcp],
            profile: ScanProfile::Balanced,
            host_discovery: true,
            port_scanning: true,
            service_detection: false,
            os_fingerprinting: false,
            banner_grabbing: false,
            max_concurrency: 100,
            source_ip: None,
            source_ports: None,
            interface: None,
            ipv6: false,
            randomize_targets: false,
            randomize_ports: false,
        }
    }
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            read_timeout: Duration::from_secs(5),
            scan_timeout: None,
            probe_delay: Duration::from_millis(0),
            max_retries: 3,
            retry_multiplier: 2.0,
            rate_limit: None,
            adaptive_timing: true,
            timing_template: TimingTemplate::T3,
            advanced: AdvancedTimingConfig::default(),
        }
    }
}

impl Default for AdvancedTimingConfig {
    fn default() -> Self {
        Self {
            min_rtt_timeout: Duration::from_millis(100),
            max_rtt_timeout: Duration::from_secs(10),
            initial_rtt_timeout: Duration::from_secs(1),
            max_hostgroup: 128,
            min_hostgroup: 1,
            max_parallelism: 300,
            min_parallelism: 1,
            max_scan_delay: Duration::from_secs(10),
            min_scan_delay: Duration::from_millis(0),
            host_timeout: Some(Duration::from_secs(900)),
            defeat_rst_ratelimit: false,
            defeat_icmp_ratelimit: false,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            format: OutputFormat::Json,
            file: None,
            timestamps: true,
            statistics: true,
            debug_info: false,
            pretty_json: true,
            compress: false,
            open_only: false,
            include_host_discovery: true,
            include_failed: false,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            privilege_checks: true,
            require_consent: true,
            audit_logging: false,
            audit_log_file: None,
            rate_limit_policies: HashMap::new(),
            allowed_networks: Vec::new(),
            blocked_networks: Vec::new(),
            max_scan_duration: Some(Duration::from_secs(3600)), // 1 hour
            safe_mode: true,
        }
    }
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            raw_sockets: false,
            system_resolver: true,
            dns_servers: Vec::new(),
            socket_buffer_size: None,
            tcp_keepalive: false,
            tcp_keepalive_time: None,
            reuse_addr: true,
            reuse_port: false,
            user_agent: Some("cyNetMapper/1.0".to_string()),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            file: None,
            console: true,
            timestamps: true,
            thread_ids: false,
            module_names: true,
            format: LogFormat::Human,
            structured: false,
        }
    }
}

impl ScanProfile {
    /// Get timing configuration for this profile
    pub fn timing_config(&self) -> TimingConfig {
        match self {
            ScanProfile::Fast => TimingConfig {
                timing_template: TimingTemplate::T4,
                connect_timeout: Duration::from_secs(1),
                read_timeout: Duration::from_secs(2),
                max_retries: 1,
                advanced: AdvancedTimingConfig {
                    max_hostgroup: 256,
                    max_parallelism: 500,
                    min_rtt_timeout: Duration::from_millis(50),
                    max_rtt_timeout: Duration::from_secs(5),
                    ..AdvancedTimingConfig::default()
                },
                ..TimingConfig::default()
            },
            ScanProfile::Balanced => TimingConfig::default(),
            ScanProfile::Thorough => TimingConfig {
                timing_template: TimingTemplate::T2,
                connect_timeout: Duration::from_secs(5),
                read_timeout: Duration::from_secs(10),
                max_retries: 5,
                probe_delay: Duration::from_millis(100),
                advanced: AdvancedTimingConfig {
                    max_hostgroup: 32,
                    max_parallelism: 100,
                    min_rtt_timeout: Duration::from_millis(200),
                    max_rtt_timeout: Duration::from_secs(20),
                    host_timeout: Some(Duration::from_secs(1800)),
                    ..AdvancedTimingConfig::default()
                },
                ..TimingConfig::default()
            },
            ScanProfile::Stealth => TimingConfig {
                timing_template: TimingTemplate::T1,
                connect_timeout: Duration::from_secs(10),
                read_timeout: Duration::from_secs(15),
                max_retries: 3,
                probe_delay: Duration::from_millis(500),
                rate_limit: Some(1.0), // 1 probe per second
                advanced: AdvancedTimingConfig {
                    max_hostgroup: 8,
                    max_parallelism: 20,
                    min_rtt_timeout: Duration::from_millis(500),
                    max_rtt_timeout: Duration::from_secs(30),
                    max_scan_delay: Duration::from_secs(30),
                    defeat_rst_ratelimit: true,
                    defeat_icmp_ratelimit: true,
                    ..AdvancedTimingConfig::default()
                },
                ..TimingConfig::default()
            },
            ScanProfile::Aggressive => TimingConfig {
                timing_template: TimingTemplate::T5,
                connect_timeout: Duration::from_millis(500),
                read_timeout: Duration::from_secs(1),
                max_retries: 0,
                advanced: AdvancedTimingConfig {
                    max_hostgroup: 512,
                    max_parallelism: 1000,
                    min_rtt_timeout: Duration::from_millis(25),
                    max_rtt_timeout: Duration::from_secs(2),
                    host_timeout: Some(Duration::from_secs(300)),
                    ..AdvancedTimingConfig::default()
                },
                ..TimingConfig::default()
            },
            ScanProfile::Custom => TimingConfig::default(),
        }
    }

    /// Get scan configuration for this profile
    pub fn scan_config(&self) -> ScanConfig {
        match self {
            ScanProfile::Fast => ScanConfig {
                ports: PortRange::TopPorts(100),
                max_concurrency: 200,
                service_detection: false,
                banner_grabbing: false,
                ..ScanConfig::default()
            },
            ScanProfile::Balanced => ScanConfig::default(),
            ScanProfile::Thorough => ScanConfig {
                ports: PortRange::TopPorts(10000),
                max_concurrency: 50,
                service_detection: true,
                banner_grabbing: true,
                os_fingerprinting: true,
                ..ScanConfig::default()
            },
            ScanProfile::Stealth => ScanConfig {
                max_concurrency: 10,
                randomize_targets: true,
                randomize_ports: true,
                ..ScanConfig::default()
            },
            ScanProfile::Aggressive => ScanConfig {
                max_concurrency: 500,
                service_detection: true,
                banner_grabbing: true,
                ..ScanConfig::default()
            },
            ScanProfile::Custom => ScanConfig::default(),
        }
    }
}

impl TimingTemplate {
    /// Get timing values for this template
    /// Returns (connect_timeout, read_timeout, probe_delay, max_retries)
    pub fn values(&self) -> (Duration, Duration, Duration, u32) {
        match self {
            TimingTemplate::T0 => (
                Duration::from_secs(300),  // 5 minutes
                Duration::from_secs(300),
                Duration::from_secs(5),
                10,
            ),
            TimingTemplate::T1 => (
                Duration::from_secs(15),
                Duration::from_secs(15),
                Duration::from_secs(1),
                5,
            ),
            TimingTemplate::T2 => (
                Duration::from_secs(10),
                Duration::from_secs(10),
                Duration::from_millis(400),
                3,
            ),
            TimingTemplate::T3 => (
                Duration::from_secs(3),
                Duration::from_secs(3),
                Duration::from_millis(100),
                2,
            ),
            TimingTemplate::T4 => (
                Duration::from_secs(1),
                Duration::from_secs(1),
                Duration::from_millis(10),
                1,
            ),
            TimingTemplate::T5 => (
                Duration::from_millis(500),
                Duration::from_millis(500),
                Duration::from_millis(5),
                0,
            ),
        }
    }
    
    /// Get advanced timing configuration for this template
    pub fn advanced_config(&self) -> AdvancedTimingConfig {
        match self {
            TimingTemplate::T0 => AdvancedTimingConfig {
                min_rtt_timeout: Duration::from_secs(1),
                max_rtt_timeout: Duration::from_secs(300),
                initial_rtt_timeout: Duration::from_secs(5),
                max_hostgroup: 1,
                min_hostgroup: 1,
                max_parallelism: 1,
                min_parallelism: 1,
                max_scan_delay: Duration::from_secs(300),
                min_scan_delay: Duration::from_secs(5),
                host_timeout: Some(Duration::from_secs(3600)),
                defeat_rst_ratelimit: false,
                defeat_icmp_ratelimit: false,
            },
            TimingTemplate::T1 => AdvancedTimingConfig {
                min_rtt_timeout: Duration::from_millis(500),
                max_rtt_timeout: Duration::from_secs(60),
                initial_rtt_timeout: Duration::from_secs(2),
                max_hostgroup: 5,
                min_hostgroup: 1,
                max_parallelism: 10,
                min_parallelism: 1,
                max_scan_delay: Duration::from_secs(15),
                min_scan_delay: Duration::from_secs(1),
                host_timeout: Some(Duration::from_secs(1800)),
                defeat_rst_ratelimit: false,
                defeat_icmp_ratelimit: false,
            },
            TimingTemplate::T2 => AdvancedTimingConfig {
                min_rtt_timeout: Duration::from_millis(250),
                max_rtt_timeout: Duration::from_secs(20),
                initial_rtt_timeout: Duration::from_secs(1),
                max_hostgroup: 20,
                min_hostgroup: 1,
                max_parallelism: 40,
                min_parallelism: 1,
                max_scan_delay: Duration::from_secs(10),
                min_scan_delay: Duration::from_millis(400),
                host_timeout: Some(Duration::from_secs(900)),
                defeat_rst_ratelimit: false,
                defeat_icmp_ratelimit: false,
            },
            TimingTemplate::T3 => AdvancedTimingConfig::default(),
            TimingTemplate::T4 => AdvancedTimingConfig {
                min_rtt_timeout: Duration::from_millis(50),
                max_rtt_timeout: Duration::from_secs(5),
                initial_rtt_timeout: Duration::from_millis(500),
                max_hostgroup: 256,
                min_hostgroup: 1,
                max_parallelism: 500,
                min_parallelism: 1,
                max_scan_delay: Duration::from_secs(1),
                min_scan_delay: Duration::from_millis(10),
                host_timeout: Some(Duration::from_secs(300)),
                defeat_rst_ratelimit: false,
                defeat_icmp_ratelimit: false,
            },
            TimingTemplate::T5 => AdvancedTimingConfig {
                min_rtt_timeout: Duration::from_millis(25),
                max_rtt_timeout: Duration::from_secs(2),
                initial_rtt_timeout: Duration::from_millis(250),
                max_hostgroup: 1024,
                min_hostgroup: 1,
                max_parallelism: 2000,
                min_parallelism: 1,
                max_scan_delay: Duration::from_millis(500),
                min_scan_delay: Duration::from_millis(5),
                host_timeout: Some(Duration::from_secs(150)),
                defeat_rst_ratelimit: true,
                defeat_icmp_ratelimit: true,
            },
        }
    }
    
    /// Get description of timing template
    pub fn description(&self) -> &'static str {
        match self {
            TimingTemplate::T0 => "Paranoid (very slow, for IDS evasion)",
            TimingTemplate::T1 => "Sneaky (slow, for IDS evasion)",
            TimingTemplate::T2 => "Polite (slow, uses less bandwidth)",
            TimingTemplate::T3 => "Normal (default timing)",
            TimingTemplate::T4 => "Aggressive (fast, assumes reliable network)",
            TimingTemplate::T5 => "Insane (very fast, may miss results)",
        }
    }
}

impl TimingConfig {
    /// Apply timing template to this configuration
    pub fn apply_template(&mut self, template: TimingTemplate) {
        let (connect_timeout, read_timeout, probe_delay, max_retries) = template.values();
        
        self.connect_timeout = connect_timeout;
        self.read_timeout = read_timeout;
        self.probe_delay = probe_delay;
        self.max_retries = max_retries;
        self.timing_template = template;
        
        // Apply advanced timing configuration
        self.advanced = template.advanced_config();
    }
    
    /// Create timing configuration from template
    pub fn from_template(template: TimingTemplate) -> Self {
        let mut config = Self::default();
        config.apply_template(template);
        config
    }
    
    /// Get effective parallelism based on current configuration
    pub fn effective_parallelism(&self) -> u32 {
        self.advanced.max_parallelism.min(1000) // Cap at reasonable limit
    }
    
    /// Get effective scan delay based on current configuration
    pub fn effective_scan_delay(&self) -> Duration {
        self.probe_delay.max(self.advanced.min_scan_delay)
    }
    
    /// Check if rate limiting defeat is enabled
    pub fn should_defeat_ratelimit(&self) -> bool {
        self.advanced.defeat_rst_ratelimit || self.advanced.defeat_icmp_ratelimit
    }
}

impl Config {
    /// Create a new configuration with the specified profile
    pub fn with_profile(profile: ScanProfile) -> Self {
        let mut config = Self::default();
        config.scan.profile = profile;
        config.scan = profile.scan_config();
        config.timing = profile.timing_config();
        config
    }

    /// Load configuration from file
    pub fn from_file<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(&path).map_err(|_e| {
            Error::config(ConfigError::ConfigFileNotFound {
                path: path.as_ref().display().to_string(),
            })
        })?;

        let config: Config = match path.as_ref().extension().and_then(|s| s.to_str()) {
            Some("json") => serde_json::from_str(&content)?,
            Some("yaml") | Some("yml") => serde_yaml::from_str(&content).map_err(|e| {
                Error::config(ConfigError::InvalidFormat {
                    reason: e.to_string(),
                })
            })?,
            Some("toml") => toml::from_str(&content).map_err(|e| {
                Error::config(ConfigError::InvalidFormat {
                    reason: e.to_string(),
                })
            })?,
            _ => {
                return Err(Error::config(ConfigError::InvalidFormat {
                    reason: "Unsupported configuration file format".to_string(),
                }))
            }
        };

        config.validate()?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn to_file<P: AsRef<std::path::Path>>(&self, path: P) -> Result<()> {
        let content = match path.as_ref().extension().and_then(|s| s.to_str()) {
            Some("json") => serde_json::to_string_pretty(self)?,
            Some("yaml") | Some("yml") => serde_yaml::to_string(self).map_err(|e| {
                Error::config(ConfigError::InvalidFormat {
                    reason: e.to_string(),
                })
            })?,
            Some("toml") => toml::to_string_pretty(self).map_err(|e| {
                Error::config(ConfigError::InvalidFormat {
                    reason: e.to_string(),
                })
            })?,
            _ => {
                return Err(Error::config(ConfigError::InvalidFormat {
                    reason: "Unsupported configuration file format".to_string(),
                }))
            }
        };

        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate timing configuration
        if self.timing.connect_timeout.as_secs() == 0 {
            return Err(Error::config(ConfigError::InvalidTimeout {
                value: self.timing.connect_timeout.as_millis() as u64,
            }));
        }

        if self.timing.max_retries > 10 {
            return Err(Error::config(ConfigError::InvalidTiming {
                reason: "max_retries cannot exceed 10".to_string(),
            }));
        }

        // Validate concurrency
        if self.scan.max_concurrency == 0 || self.scan.max_concurrency > 10000 {
            return Err(Error::config(ConfigError::InvalidConcurrency {
                value: self.scan.max_concurrency,
            }));
        }

        // Validate rate limiting
        if let Some(rate) = self.timing.rate_limit {
            if rate <= 0.0 || rate > 10000.0 {
                return Err(Error::config(ConfigError::InvalidTiming {
                    reason: format!("Invalid rate limit: {}", rate),
                }));
            }
        }

        // Validate output file path
        if let Some(ref path) = self.output.file {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    return Err(Error::config(ConfigError::InvalidFilePath {
                        path: path.display().to_string(),
                    }));
                }
            }
        }

        Ok(())
    }

    /// Merge with another configuration (other takes precedence)
    pub fn merge(&mut self, other: Config) {
        // This is a simplified merge - in practice, you might want more sophisticated merging
        if !other.scan.targets.is_empty() {
            self.scan.targets = other.scan.targets;
        }
        
        // Merge other fields as needed...
        // For brevity, only showing targets merge
    }

    /// Apply security constraints
    pub fn apply_security_constraints(&mut self) {
        if self.security.safe_mode {
            // Limit concurrency in safe mode
            self.scan.max_concurrency = self.scan.max_concurrency.min(50);
            
            // Increase timeouts
            if self.timing.connect_timeout < Duration::from_secs(1) {
                self.timing.connect_timeout = Duration::from_secs(1);
            }
            
            // Limit rate
            if let Some(rate) = self.timing.rate_limit {
                self.timing.rate_limit = Some(rate.min(100.0));
            }
            
            // Disable raw sockets
            self.platform.raw_sockets = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.scan.profile, ScanProfile::Balanced);
        assert_eq!(config.timing.timing_template, TimingTemplate::T3);
        assert_eq!(config.output.format, OutputFormat::Json);
        assert!(config.security.safe_mode);
    }

    #[test]
    fn test_profile_configs() {
        let fast_config = Config::with_profile(ScanProfile::Fast);
        assert_eq!(fast_config.timing.timing_template, TimingTemplate::T4);
        
        let stealth_config = Config::with_profile(ScanProfile::Stealth);
        assert_eq!(stealth_config.timing.timing_template, TimingTemplate::T1);
        assert!(stealth_config.scan.randomize_targets);
    }

    #[test]
    fn test_timing_templates() {
        let (connect, read, delay, retries) = TimingTemplate::T3.values();
        assert_eq!(connect, Duration::from_secs(3));
        assert_eq!(read, Duration::from_secs(5));
        assert_eq!(delay, Duration::from_millis(0));
        assert_eq!(retries, 3);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());
        
        // Test invalid concurrency
        config.scan.max_concurrency = 0;
        assert!(config.validate().is_err());
        
        config.scan.max_concurrency = 100;
        config.timing.max_retries = 20;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_security_constraints() {
        let mut config = Config::default();
        config.scan.max_concurrency = 1000;
        config.timing.connect_timeout = Duration::from_millis(100);
        config.platform.raw_sockets = true;
        
        config.apply_security_constraints();
        
        assert_eq!(config.scan.max_concurrency, 50);
        assert!(config.timing.connect_timeout >= Duration::from_secs(1));
        assert!(!config.platform.raw_sockets);
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        
        // Test JSON serialization
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(config.scan.profile, deserialized.scan.profile);
    }

    #[test]
    fn test_config_file_operations() {
        let config = Config::default();
        
        // Test JSON file
        let json_file = NamedTempFile::new().unwrap();
        let json_path = json_file.path().with_extension("json");
        config.to_file(&json_path).unwrap();
        let loaded_config = Config::from_file(&json_path).unwrap();
        assert_eq!(config.scan.profile, loaded_config.scan.profile);
    }
}
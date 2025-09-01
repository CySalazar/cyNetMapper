//! Error types for cyNetMapper core

use std::fmt;
use thiserror::Error;

/// Result type alias for cyNetMapper operations
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for cyNetMapper operations
#[derive(Error, Debug)]
pub enum Error {
    /// Network-related errors
    #[error("Network error: {0}")]
    Network(#[from] NetworkError),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),

    /// Security and authorization errors
    #[error("Security error: {0}")]
    Security(#[from] SecurityError),

    /// Parsing and validation errors
    #[error("Parse error: {0}")]
    Parse(#[from] ParseError),

    /// I/O errors
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Timeout errors
    #[error("Operation timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    /// Rate limiting errors
    #[error("Rate limit exceeded: {message}")]
    RateLimit { message: String },

    /// Invalid target specification
    #[error("Invalid target: {0}")]
    InvalidTarget(String),

    /// Insufficient privileges
    #[error("Insufficient privileges: {operation}")]
    InsufficientPrivileges { operation: String },

    /// Platform not supported
    #[error("Platform not supported: {platform}")]
    UnsupportedPlatform { platform: String },

    /// Feature not available
    #[error("Feature not available: {feature}")]
    FeatureNotAvailable { feature: String },

    /// Internal errors
    #[error("Internal error: {message}")]
    Internal { message: String },

    /// Multiple errors occurred
    #[error("Multiple errors occurred: {count} errors")]
    Multiple { errors: Vec<Error>, count: usize },
}

/// Network-specific errors
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed to {address}:{port}")]
    ConnectionFailed { address: String, port: u16 },

    #[error("DNS resolution failed for {hostname}")]
    DnsResolutionFailed { hostname: String },

    #[error("Socket creation failed: {reason}")]
    SocketCreationFailed { reason: String },

    #[error("Raw socket access denied")]
    RawSocketDenied,

    #[error("Network interface not found: {interface}")]
    InterfaceNotFound { interface: String },

    #[error("Invalid network address: {address}")]
    InvalidAddress { address: String },

    #[error("Network unreachable: {network}")]
    NetworkUnreachable { network: String },

    #[error("Protocol not supported: {protocol}")]
    ProtocolNotSupported { protocol: String },

    #[error("Packet send failed: {reason}")]
    PacketSendFailed { reason: String },

    #[error("Packet receive failed: {reason}")]
    PacketReceiveFailed { reason: String },
}

/// Configuration-specific errors
#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("Invalid scan profile: {profile}")]
    InvalidProfile { profile: String },

    #[error("Invalid port range: {range}")]
    InvalidPortRange { range: String },

    #[error("Invalid timing configuration: {reason}")]
    InvalidTiming { reason: String },

    #[error("Invalid concurrency setting: {value}")]
    InvalidConcurrency { value: usize },

    #[error("Invalid timeout value: {value}ms")]
    InvalidTimeout { value: u64 },

    #[error("Conflicting options: {option1} and {option2}")]
    ConflictingOptions { option1: String, option2: String },

    #[error("Missing required option: {option}")]
    MissingOption { option: String },

    #[error("Invalid file path: {path}")]
    InvalidFilePath { path: String },

    #[error("Configuration file not found: {path}")]
    ConfigFileNotFound { path: String },

    #[error("Invalid configuration format: {reason}")]
    InvalidFormat { reason: String },
}

/// Security and authorization errors
#[derive(Error, Debug)]
pub enum SecurityError {
    #[error("Authorization required for target: {target}")]
    AuthorizationRequired { target: String },

    #[error("Scan not authorized: {reason}")]
    ScanNotAuthorized { reason: String },

    #[error("Dangerous operation blocked: {operation}")]
    DangerousOperationBlocked { operation: String },

    #[error("Rate limit policy violation: {policy}")]
    RateLimitViolation { policy: String },

    #[error("Privilege escalation required for: {operation}")]
    PrivilegeEscalationRequired { operation: String },

    #[error("Security policy violation: {policy}")]
    PolicyViolation { policy: String },

    #[error("Consent not provided for: {operation}")]
    ConsentNotProvided { operation: String },

    #[error("Audit log verification failed")]
    AuditLogVerificationFailed,

    #[error("Certificate validation failed: {reason}")]
    CertificateValidationFailed { reason: String },

    #[error("Cryptographic operation failed: {operation}")]
    CryptographicOperationFailed { operation: String },
}

/// Parsing and validation errors
#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid IP address: {address}")]
    InvalidIpAddress { address: String },

    #[error("Invalid port number: {port}")]
    InvalidPort { port: String },

    #[error("Invalid CIDR notation: {cidr}")]
    InvalidCidr { cidr: String },

    #[error("Invalid hostname: {hostname}")]
    InvalidHostname { hostname: String },

    #[error("Invalid protocol: {protocol}")]
    InvalidProtocol { protocol: String },

    #[error("Invalid JSON: {reason}")]
    InvalidJson { reason: String },

    #[error("Invalid XML: {reason}")]
    InvalidXml { reason: String },

    #[error("Invalid regular expression: {pattern}")]
    InvalidRegex { pattern: String },

    #[error("Invalid date/time format: {datetime}")]
    InvalidDateTime { datetime: String },

    #[error("Invalid UUID: {uuid}")]
    InvalidUuid { uuid: String },
}

impl Error {
    /// Create a new network error
    pub fn network<E: Into<NetworkError>>(error: E) -> Self {
        Error::Network(error.into())
    }

    /// Create a new configuration error
    pub fn config<E: Into<ConfigError>>(error: E) -> Self {
        Error::Config(error.into())
    }

    /// Create a new security error
    pub fn security<E: Into<SecurityError>>(error: E) -> Self {
        Error::Security(error.into())
    }

    /// Create a new parse error
    pub fn parse<E: Into<ParseError>>(error: E) -> Self {
        Error::Parse(error.into())
    }

    /// Create a timeout error
    pub fn timeout(timeout_ms: u64) -> Self {
        Error::Timeout { timeout_ms }
    }

    /// Create a rate limit error
    pub fn rate_limit<S: Into<String>>(message: S) -> Self {
        Error::RateLimit {
            message: message.into(),
        }
    }

    /// Create an invalid target error
    pub fn invalid_target<S: Into<String>>(target: S) -> Self {
        Error::InvalidTarget(target.into())
    }

    /// Create an insufficient privileges error
    pub fn insufficient_privileges<S: Into<String>>(operation: S) -> Self {
        Error::InsufficientPrivileges {
            operation: operation.into(),
        }
    }

    /// Create an unsupported platform error
    pub fn unsupported_platform<S: Into<String>>(platform: S) -> Self {
        Error::UnsupportedPlatform {
            platform: platform.into(),
        }
    }

    /// Create a feature not available error
    pub fn feature_not_available<S: Into<String>>(feature: S) -> Self {
        Error::FeatureNotAvailable {
            feature: feature.into(),
        }
    }

    /// Create an internal error
    pub fn internal<S: Into<String>>(message: S) -> Self {
        Error::Internal {
            message: message.into(),
        }
    }

    /// Create a multiple errors container
    pub fn multiple(errors: Vec<Error>) -> Self {
        let count = errors.len();
        Error::Multiple { errors, count }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Error::Network(NetworkError::ConnectionFailed { .. }) => true,
            Error::Network(NetworkError::DnsResolutionFailed { .. }) => true,
            Error::Network(NetworkError::NetworkUnreachable { .. }) => true,
            Error::Timeout { .. } => true,
            Error::RateLimit { .. } => true,
            Error::Multiple { errors, .. } => errors.iter().any(|e| e.is_recoverable()),
            _ => false,
        }
    }

    /// Check if this error is related to permissions
    pub fn is_permission_error(&self) -> bool {
        matches!(
            self,
            Error::InsufficientPrivileges { .. }
                | Error::Network(NetworkError::RawSocketDenied)
                | Error::Security(SecurityError::PrivilegeEscalationRequired { .. })
                | Error::Security(SecurityError::AuthorizationRequired { .. })
        )
    }

    /// Check if this error is related to configuration
    pub fn is_config_error(&self) -> bool {
        matches!(self, Error::Config(_) | Error::Parse(_))
    }

    /// Get the error category for logging/metrics
    pub fn category(&self) -> &'static str {
        match self {
            Error::Network(_) => "network",
            Error::Config(_) => "config",
            Error::Security(_) => "security",
            Error::Parse(_) => "parse",
            Error::Io(_) => "io",
            Error::Timeout { .. } => "timeout",
            Error::RateLimit { .. } => "rate_limit",
            Error::InvalidTarget(_) => "invalid_target",
            Error::InsufficientPrivileges { .. } => "privileges",
            Error::UnsupportedPlatform { .. } => "platform",
            Error::FeatureNotAvailable { .. } => "feature",
            Error::Internal { .. } => "internal",
            Error::Multiple { .. } => "multiple",
        }
    }
}

// Implement conversion from common error types
impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Self {
        Error::parse(ParseError::InvalidIpAddress {
            address: err.to_string(),
        })
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::parse(ParseError::InvalidJson {
            reason: err.to_string(),
        })
    }
}

impl From<uuid::Error> for Error {
    fn from(err: uuid::Error) -> Self {
        Error::parse(ParseError::InvalidUuid {
            uuid: err.to_string(),
        })
    }
}

impl From<chrono::ParseError> for Error {
    fn from(err: chrono::ParseError) -> Self {
        Error::parse(ParseError::InvalidDateTime {
            datetime: err.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let timeout_err = Error::timeout(5000);
        assert!(matches!(timeout_err, Error::Timeout { timeout_ms: 5000 }));

        let rate_limit_err = Error::rate_limit("Too many requests");
        assert!(matches!(rate_limit_err, Error::RateLimit { .. }));

        let invalid_target_err = Error::invalid_target("invalid-target");
        assert!(matches!(invalid_target_err, Error::InvalidTarget(_)));
    }

    #[test]
    fn test_error_categories() {
        let network_err = Error::network(NetworkError::ConnectionFailed {
            address: "127.0.0.1".to_string(),
            port: 80,
        });
        assert_eq!(network_err.category(), "network");

        let config_err = Error::config(ConfigError::InvalidProfile {
            profile: "invalid".to_string(),
        });
        assert_eq!(config_err.category(), "config");

        let security_err = Error::security(SecurityError::AuthorizationRequired {
            target: "192.168.1.1".to_string(),
        });
        assert_eq!(security_err.category(), "security");
    }

    #[test]
    fn test_error_properties() {
        let recoverable_err = Error::network(NetworkError::ConnectionFailed {
            address: "127.0.0.1".to_string(),
            port: 80,
        });
        assert!(recoverable_err.is_recoverable());

        let permission_err = Error::insufficient_privileges("raw sockets");
        assert!(permission_err.is_permission_error());

        let config_err = Error::config(ConfigError::InvalidProfile {
            profile: "invalid".to_string(),
        });
        assert!(config_err.is_config_error());
    }

    #[test]
    fn test_multiple_errors() {
        let errors = vec![
            Error::timeout(1000),
            Error::rate_limit("limit exceeded"),
        ];
        let multiple_err = Error::multiple(errors);
        
        if let Error::Multiple { count, .. } = multiple_err {
            assert_eq!(count, 2);
        } else {
            panic!("Expected Multiple error");
        }
    }

    #[test]
    fn test_error_display() {
        let err = Error::network(NetworkError::ConnectionFailed {
            address: "127.0.0.1".to_string(),
            port: 80,
        });
        let display = format!("{}", err);
        assert!(display.contains("Network error"));
        assert!(display.contains("Connection failed"));
        assert!(display.contains("127.0.0.1:80"));
    }
}
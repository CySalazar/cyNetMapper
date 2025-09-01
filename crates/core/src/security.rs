//! Security and authorization module
//!
//! This module provides security controls and validation for network scanning operations.

use crate::config::Config;
use crate::error::{Error, Result, SecurityError};
use crate::scanner::ScanOptions;
use crate::types::{IpAddr, Target};

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tracing::{debug, warn};

/// Security context for validating scan operations
#[derive(Debug, Clone)]
pub struct SecurityContext {
    /// Configuration reference
    config: Arc<Config>,
    /// Maximum concurrent scans allowed
    max_concurrent: usize,
    /// Whether privilege checks are required
    require_privileges: bool,
    /// Whether audit logging is enabled
    audit_logging: bool,
}

/// Privilege levels for different operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeLevel {
    /// No special privileges required
    None,
    /// Network access privileges
    Network,
    /// Raw socket privileges
    RawSocket,
    /// Administrative privileges
    Admin,
}

impl SecurityContext {
    /// Create a new security context
    pub fn new(config: &Config) -> Result<Self> {
        Ok(SecurityContext {
            config: Arc::new(config.clone()),
            max_concurrent: 100,  // Default limit
            require_privileges: config.security.privilege_checks,
            audit_logging: config.security.audit_logging,
        })
    }
    
    /// Validate a list of targets
    pub fn validate_targets(&self, targets: &[Target]) -> Result<()> {
        // Check target count limit
        if targets.len() > 1000 {
            return Err(Error::Security(SecurityError::PolicyViolation {
                policy: format!("Too many targets: {} (max: 1000)", targets.len())
            }));
        }
        
        // Validate each target
        for target in targets {
            self.validate_target(target)?;
        }
        
        Ok(())
    }
    
    /// Validate a single target
    pub fn validate_target(&self, target: &Target) -> Result<()> {
        match target {
            Target::Ip(ip) => self.validate_ip_address(ip)?,
            Target::Cidr { network, prefix: _ } => {
                self.validate_ip_address(network)?;
            },
            Target::Hostname(hostname) => self.validate_hostname(hostname)?,
            Target::Range { start, end } => {
                self.validate_ip_address(start)?;
                self.validate_ip_address(end)?;
            },
        }
        Ok(())
    }
    
    /// Validate an IP address
    pub fn validate_ip_address(&self, ip: &IpAddr) -> Result<()> {
        match ip {
            IpAddr::V4(ipv4) => self.validate_ipv4_address(ipv4),
            IpAddr::V6(ipv6) => self.validate_ipv6_address(ipv6),
        }
    }
    
    /// Validate IPv4 address
    fn validate_ipv4_address(&self, ip: &Ipv4Addr) -> Result<()> {
        // Check for unspecified (0.0.0.0)
        if ip.is_unspecified() {
            return Err(Error::Security(SecurityError::PolicyViolation { 
                policy: "Unspecified address (0.0.0.0) not allowed".to_string() 
            }));
        }
        
        Ok(())
    }
    
    /// Validate IPv6 address
    fn validate_ipv6_address(&self, ip: &Ipv6Addr) -> Result<()> {
        // Check for unspecified (::)
        if ip.is_unspecified() {
            return Err(Error::Security(SecurityError::PolicyViolation { 
                policy: "Unspecified address (::) not allowed".to_string() 
            }));
        }
        
        Ok(())
    }
    
    /// Validate hostname
    fn validate_hostname(&self, hostname: &str) -> Result<()> {
        // Basic hostname validation
        if hostname.is_empty() {
            return Err(Error::Security(SecurityError::PolicyViolation { 
                policy: "Empty hostname not allowed".to_string() 
            }));
        }
        
        if hostname.len() > 253 {
            return Err(Error::Security(SecurityError::PolicyViolation { 
                policy: "Hostname too long".to_string() 
            }));
        }
        
        Ok(())
    }
    
    /// Check scan options for security compliance
    pub fn check_permissions(&self, options: &ScanOptions) -> Result<()> {
        // Check concurrency limits
        if options.max_concurrency > self.max_concurrent {
            return Err(Error::Security(SecurityError::PolicyViolation { 
                policy: format!("Excessive concurrency: requested {}, max allowed {}", 
                    options.max_concurrency, self.max_concurrent)
            }));
        }
        
        // Check privilege requirements
        let required_privilege = self.get_required_privilege_level(options);
        if required_privilege != PrivilegeLevel::None && self.require_privileges {
            if !self.check_privilege_level(required_privilege) {
                return Err(Error::Security(SecurityError::PrivilegeEscalationRequired { 
                    operation: format!("{:?}", required_privilege)
                }));
            }
        }
        
        Ok(())
    }
    
    /// Get required privilege level for scan options
    fn get_required_privilege_level(&self, _options: &ScanOptions) -> PrivilegeLevel {
        // Simplified privilege checking for MVP
        PrivilegeLevel::None
    }
    
    /// Check if current context has required privilege level
    fn check_privilege_level(&self, _required: PrivilegeLevel) -> bool {
        // Simplified privilege checking - always allow for MVP
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::net::{Ipv4Addr, Ipv6Addr};
    
    #[test]
    fn test_security_context_creation() {
        let config = Config::default();
        let security = SecurityContext::new(&config).unwrap();
        assert!(!security.require_privileges);
    }
    
    #[test]
    fn test_ipv4_validation() {
        let config = Config::default();
        let security = SecurityContext::new(&config).unwrap();
        
        // Valid IP should pass
        let valid_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        assert!(security.validate_ip_address(&valid_ip).is_ok());
        
        // Unspecified IP should fail
        let unspecified = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
        assert!(security.validate_ip_address(&unspecified).is_err());
    }
    
    #[test]
    fn test_hostname_validation() {
        let config = Config::default();
        let security = SecurityContext::new(&config).unwrap();
        
        // Valid hostname should pass
        assert!(security.validate_hostname("example.com").is_ok());
        
        // Empty hostname should fail
        assert!(security.validate_hostname("").is_err());
        
        // Too long hostname should fail
        let long_hostname = "a".repeat(300);
        assert!(security.validate_hostname(&long_hostname).is_err());
    }
}
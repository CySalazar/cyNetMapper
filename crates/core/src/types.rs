//! Core types and data structures for cyNetMapper

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::{IpAddr as StdIpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// IP address type that supports both IPv4 and IPv6
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IpAddr {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
}

impl From<StdIpAddr> for IpAddr {
    fn from(addr: StdIpAddr) -> Self {
        match addr {
            StdIpAddr::V4(v4) => IpAddr::V4(v4),
            StdIpAddr::V6(v6) => IpAddr::V6(v6),
        }
    }
}

impl From<IpAddr> for StdIpAddr {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(v4) => StdIpAddr::V4(v4),
            IpAddr::V6(v6) => StdIpAddr::V6(v6),
        }
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpAddr::V4(v4) => write!(f, "{}", v4),
            IpAddr::V6(v6) => write!(f, "{}", v6),
        }
    }
}

impl FromStr for IpAddr {
    type Err = std::net::AddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.parse::<StdIpAddr>().map(Into::into)
    }
}

impl IpAddr {
    /// Returns true if this is an IPv6 address
    pub fn is_ipv6(&self) -> bool {
        matches!(self, IpAddr::V6(_))
    }

    /// Returns true if this is an IPv4 address
    pub fn is_ipv4(&self) -> bool {
        matches!(self, IpAddr::V4(_))
    }

    /// Returns true if this is a loopback address
    pub fn is_loopback(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_loopback(),
            IpAddr::V6(ip) => ip.is_loopback(),
        }
    }

    /// Returns true if this is a private address
    pub fn is_private(&self) -> bool {
        match self {
            IpAddr::V4(ip) => ip.is_private(),
            IpAddr::V6(ip) => {
                // IPv6 private addresses (RFC 4193)
                ip.segments()[0] & 0xfe00 == 0xfc00
            }
        }
    }
}

// Add PartialEq implementation for comparison with std::net::IpAddr
impl PartialEq<StdIpAddr> for IpAddr {
    fn eq(&self, other: &StdIpAddr) -> bool {
        let std_self: StdIpAddr = (*self).into();
        std_self == *other
    }
}

impl PartialEq<IpAddr> for StdIpAddr {
    fn eq(&self, other: &IpAddr) -> bool {
        let std_other: StdIpAddr = (*other).into();
        *self == std_other
    }
}

/// Network protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Sctp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Sctp => write!(f, "sctp"),
        }
    }
}

/// Port range specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortRange {
    Single(u16),
    Range { start: u16, end: u16 },
    List(Vec<u16>),
    TopPorts(u16), // Top N most common ports
}

impl PortRange {
    /// Create a single port range
    pub fn single(port: u16) -> Self {
        PortRange::Single(port)
    }

    /// Create a range of ports
    pub fn range(start: u16, end: u16) -> Self {
        PortRange::Range { start, end }
    }

    /// Create from a list of ports
    pub fn list(ports: Vec<u16>) -> Self {
        PortRange::List(ports)
    }

    /// Create top N ports range
    pub fn top_ports(n: u16) -> Self {
        PortRange::TopPorts(n)
    }

    /// Expand the port range into a vector of individual ports
    pub fn expand(&self) -> Vec<u16> {
        match self {
            PortRange::Single(port) => vec![*port],
            PortRange::Range { start, end } => (*start..=*end).collect(),
            PortRange::List(ports) => ports.clone(),
            PortRange::TopPorts(n) => get_top_ports(*n),
        }
    }

    /// Get the number of ports in this range
    pub fn count(&self) -> usize {
        match self {
            PortRange::Single(_) => 1,
            PortRange::Range { start, end } => (end - start + 1) as usize,
            PortRange::List(ports) => ports.len(),
            PortRange::TopPorts(n) => *n as usize,
        }
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortRange::Single(port) => write!(f, "{}", port),
            PortRange::Range { start, end } => write!(f, "{}-{}", start, end),
            PortRange::List(ports) => {
                let port_strs: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
                write!(f, "{}", port_strs.join(","))
            }
            PortRange::TopPorts(n) => write!(f, "top-{}", n),
        }
    }
}

/// Scan target specification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// Single IP address
    Ip(IpAddr),
    /// CIDR network range
    Cidr { network: IpAddr, prefix: u8 },
    /// Hostname to resolve
    Hostname(String),
    /// IP range
    Range { start: IpAddr, end: IpAddr },
}

impl Target {
    /// Create a target from a single IP
    pub fn ip(addr: IpAddr) -> Self {
        Target::Ip(addr)
    }

    /// Create a target from a CIDR notation
    pub fn cidr(network: IpAddr, prefix: u8) -> Self {
        Target::Cidr { network, prefix }
    }

    /// Create a target from a hostname
    pub fn hostname<S: Into<String>>(hostname: S) -> Self {
        Target::Hostname(hostname.into())
    }

    /// Create a target from an IP range
    pub fn range(start: IpAddr, end: IpAddr) -> Self {
        Target::Range { start, end }
    }

    /// Estimate the number of hosts in this target
    pub fn host_count(&self) -> u64 {
        match self {
            Target::Ip(_) => 1,
            Target::Hostname(_) => 1, // Could resolve to multiple IPs
            Target::Cidr { prefix, network } => {
                match network {
                    IpAddr::V4(_) => {
                        if *prefix >= 32 {
                            1
                        } else {
                            2u64.pow(32 - *prefix as u32)
                        }
                    }
                    IpAddr::V6(_) => {
                        if *prefix >= 128 {
                            1
                        } else {
                            // For IPv6, limit to reasonable size
                            std::cmp::min(2u64.pow(32), 2u64.pow(128 - *prefix as u32))
                        }
                    }
                }
            }
            Target::Range { start, end } => {
                // Simplified calculation for demonstration
                match (start, end) {
                    (IpAddr::V4(s), IpAddr::V4(e)) => {
                        let start_int = u32::from(*s);
                        let end_int = u32::from(*e);
                        if end_int >= start_int {
                            (end_int - start_int + 1) as u64
                        } else {
                            0
                        }
                    }
                    _ => 1, // IPv6 ranges are complex
                }
            }
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(ip) => write!(f, "{}", ip),
            Target::Cidr { network, prefix } => write!(f, "{}/{}", network, prefix),
            Target::Hostname(hostname) => write!(f, "{}", hostname),
            Target::Range { start, end } => write!(f, "{}-{}", start, end),
        }
    }
}

impl FromStr for Target {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try CIDR notation first
        if let Some((network_str, prefix_str)) = s.split_once('/') {
            let network: IpAddr = network_str.parse()
                .map_err(|_| crate::Error::InvalidTarget(s.to_string()))?;
            let prefix: u8 = prefix_str.parse()
                .map_err(|_| crate::Error::InvalidTarget(s.to_string()))?;
            return Ok(Target::cidr(network, prefix));
        }

        // Try IP range notation
        if let Some((start_str, end_str)) = s.split_once('-') {
            if let (Ok(start), Ok(end)) = (start_str.parse::<IpAddr>(), end_str.parse::<IpAddr>()) {
                return Ok(Target::range(start, end));
            }
        }

        // Try single IP
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Target::ip(ip));
        }

        // Assume hostname
        Ok(Target::hostname(s))
    }
}

/// Port state as defined by nmap
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    OpenFiltered,
    ClosedFiltered,
}

impl fmt::Display for PortState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PortState::Open => write!(f, "open"),
            PortState::Closed => write!(f, "closed"),
            PortState::Filtered => write!(f, "filtered"),
            PortState::Unfiltered => write!(f, "unfiltered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::ClosedFiltered => write!(f, "closed|filtered"),
        }
    }
}

/// Host state
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HostState {
    Up,
    Down,
    Unknown,
}

impl fmt::Display for HostState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostState::Up => write!(f, "up"),
            HostState::Down => write!(f, "down"),
            HostState::Unknown => write!(f, "unknown"),
        }
    }
}

/// Get the top N most common ports
fn get_top_ports(n: u16) -> Vec<u16> {
    // Top 1000 most common ports (subset shown here)
    const TOP_PORTS: &[u16] = &[
        80, 23, 443, 21, 22, 25, 53, 110, 111, 995, 993, 143, 993, 995, 587, 465, 109, 102, 3389,
        5900, 135, 139, 445, 1433, 3306, 5432, 1521, 2049, 161, 162, 69, 514, 513, 512, 515,
        631, 873, 902, 989, 990, 636, 389, 88, 464, 749, 750, 751, 752, 754, 760, 1024, 1025,
        1026, 1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039,
        1040, 1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053,
        1054, 1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067,
        1068, 1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080,
    ];

    TOP_PORTS.iter().take(n as usize).copied().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_addr_conversion() {
        let ipv4 = "192.168.1.1".parse::<IpAddr>().unwrap();
        let ipv6 = "::1".parse::<IpAddr>().unwrap();
        
        assert!(matches!(ipv4, IpAddr::V4(_)));
        assert!(matches!(ipv6, IpAddr::V6(_)));
    }

    #[test]
    fn test_port_range_expansion() {
        let single = PortRange::single(80);
        assert_eq!(single.expand(), vec![80]);
        assert_eq!(single.count(), 1);

        let range = PortRange::range(80, 82);
        assert_eq!(range.expand(), vec![80, 81, 82]);
        assert_eq!(range.count(), 3);

        let list = PortRange::list(vec![22, 80, 443]);
        assert_eq!(list.expand(), vec![22, 80, 443]);
        assert_eq!(list.count(), 3);
    }

    #[test]
    fn test_target_parsing() {
        let ip_target: Target = "192.168.1.1".parse().unwrap();
        assert!(matches!(ip_target, Target::Ip(_)));

        let cidr_target: Target = "192.168.1.0/24".parse().unwrap();
        assert!(matches!(cidr_target, Target::Cidr { .. }));

        let hostname_target: Target = "example.com".parse().unwrap();
        assert!(matches!(hostname_target, Target::Hostname(_)));
    }

    #[test]
    fn test_target_host_count() {
        let single = Target::ip("192.168.1.1".parse().unwrap());
        assert_eq!(single.host_count(), 1);

        let cidr = Target::cidr("192.168.1.0".parse().unwrap(), 24);
        assert_eq!(cidr.host_count(), 256);

        let hostname = Target::hostname("example.com");
        assert_eq!(hostname.host_count(), 1);
    }

    #[test]
    fn test_top_ports() {
        let top_10 = get_top_ports(10);
        assert_eq!(top_10.len(), 10);
        assert_eq!(top_10[0], 80); // HTTP should be first
        assert!(top_10.contains(&443)); // HTTPS should be in top 10
    }
}
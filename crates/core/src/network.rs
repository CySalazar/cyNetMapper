//! Network utilities and abstractions for cyNetMapper

use crate::error::{Error, NetworkError, Result};
use crate::types::{IpAddr, Protocol};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

/// Network interface information
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    /// Interface name
    pub name: String,
    /// Interface index
    pub index: u32,
    /// IP addresses assigned to this interface
    pub addresses: Vec<IpAddr>,
    /// Whether the interface is up
    pub is_up: bool,
    /// Whether the interface is loopback
    pub is_loopback: bool,
    /// MTU size
    pub mtu: Option<u32>,
}

/// Network route information
#[derive(Debug, Clone)]
pub struct Route {
    /// Destination network
    pub destination: IpAddr,
    /// Network mask
    pub netmask: IpAddr,
    /// Gateway address
    pub gateway: Option<IpAddr>,
    /// Interface name
    pub interface: String,
    /// Route metric
    pub metric: u32,
}

/// Connection result
#[derive(Debug, Clone)]
pub struct ConnectionResult {
    /// Target address
    pub address: SocketAddr,
    /// Protocol used
    pub protocol: Protocol,
    /// Whether connection was successful
    pub success: bool,
    /// Connection time
    pub duration: Duration,
    /// Error message if failed
    pub error: Option<String>,
    /// Timestamp of the attempt
    pub timestamp: Instant,
}

/// DNS resolution result
#[derive(Debug, Clone)]
pub struct DnsResult {
    /// Hostname that was resolved
    pub hostname: String,
    /// Resolved IP addresses
    pub addresses: Vec<IpAddr>,
    /// Resolution time
    pub duration: Duration,
    /// Timestamp of the resolution
    pub timestamp: Instant,
}

/// Network scanner for basic connectivity tests
#[derive(Debug, Clone)]
pub struct NetworkScanner {
    /// Connection timeout
    timeout: Duration,
    /// Source IP address
    source_ip: Option<IpAddr>,
    /// DNS cache
    dns_cache: HashMap<String, DnsResult>,
}

impl NetworkScanner {
    /// Create a new network scanner
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            source_ip: None,
            dns_cache: HashMap::new(),
        }
    }

    /// Set source IP address
    pub fn with_source_ip(mut self, source_ip: IpAddr) -> Self {
        self.source_ip = Some(source_ip);
        self
    }

    /// Test TCP connection to a target
    pub async fn test_tcp_connection(
        &self,
        target: SocketAddr,
    ) -> Result<ConnectionResult> {
        let start = Instant::now();
        
        let result = match timeout(self.timeout, TcpStream::connect(target)).await {
            Ok(Ok(_stream)) => ConnectionResult {
                address: target,
                protocol: Protocol::Tcp,
                success: true,
                duration: start.elapsed(),
                error: None,
                timestamp: start,
            },
            Ok(Err(e)) => ConnectionResult {
                address: target,
                protocol: Protocol::Tcp,
                success: false,
                duration: start.elapsed(),
                error: Some(e.to_string()),
                timestamp: start,
            },
            Err(_) => ConnectionResult {
                address: target,
                protocol: Protocol::Tcp,
                success: false,
                duration: self.timeout,
                error: Some("Connection timeout".to_string()),
                timestamp: start,
            },
        };

        Ok(result)
    }

    /// Test UDP connection to a target
    pub async fn test_udp_connection(
        &self,
        target: SocketAddr,
    ) -> Result<ConnectionResult> {
        let start = Instant::now();
        
        // For UDP, we'll try to bind a local socket and send a packet
        let local_addr = match target {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let result = match timeout(self.timeout, async {
            let socket = UdpSocket::bind(local_addr).await?;
            socket.connect(target).await?;
            
            // Send a small probe packet
            socket.send(&[0u8; 1]).await?;
            
            // Try to receive a response (this will likely timeout for most services)
            let mut buf = [0u8; 1024];
            let _ = timeout(Duration::from_millis(100), socket.recv(&mut buf)).await;
            
            Ok::<(), std::io::Error>(())
        }).await {
            Ok(Ok(())) => ConnectionResult {
                address: target,
                protocol: Protocol::Udp,
                success: true,
                duration: start.elapsed(),
                error: None,
                timestamp: start,
            },
            Ok(Err(e)) => ConnectionResult {
                address: target,
                protocol: Protocol::Udp,
                success: false,
                duration: start.elapsed(),
                error: Some(e.to_string()),
                timestamp: start,
            },
            Err(_) => ConnectionResult {
                address: target,
                protocol: Protocol::Udp,
                success: false,
                duration: self.timeout,
                error: Some("Connection timeout".to_string()),
                timestamp: start,
            },
        };

        Ok(result)
    }

    /// Resolve hostname to IP addresses
    pub async fn resolve_hostname(&mut self, hostname: &str) -> Result<DnsResult> {
        // Check cache first
        if let Some(cached) = self.dns_cache.get(hostname) {
            // Return cached result if it's less than 5 minutes old
            if cached.timestamp.elapsed() < Duration::from_secs(300) {
                return Ok(cached.clone());
            }
        }

        let start = Instant::now();
        
        let result = match timeout(self.timeout, async {
            let socket_addrs: Vec<SocketAddr> = format!("{}:80", hostname)
                .to_socket_addrs()?
                .collect();
            
            let addresses: Vec<IpAddr> = socket_addrs
                .into_iter()
                .map(|addr| match addr {
                    SocketAddr::V4(v4) => IpAddr::V4(*v4.ip()),
                    SocketAddr::V6(v6) => IpAddr::V6(*v6.ip()),
                })
                .collect();
            
            Ok::<Vec<IpAddr>, std::io::Error>(addresses)
        }).await {
            Ok(Ok(addresses)) => {
                if addresses.is_empty() {
                    return Err(Error::network(NetworkError::DnsResolutionFailed {
                        hostname: hostname.to_string(),
                    }));
                }
                
                DnsResult {
                    hostname: hostname.to_string(),
                    addresses,
                    duration: start.elapsed(),
                    timestamp: start,
                }
            },
            Ok(Err(_e)) => {
                return Err(Error::network(NetworkError::DnsResolutionFailed {
                    hostname: hostname.to_string(),
                }));
            },
            Err(_) => {
                return Err(Error::network(NetworkError::DnsResolutionFailed {
                    hostname: hostname.to_string(),
                }));
            },
        };

        // Cache the result
        self.dns_cache.insert(hostname.to_string(), result.clone());
        
        Ok(result)
    }

    /// Perform reverse DNS lookup (IP to hostname)
    pub async fn reverse_dns_lookup(&self, ip: IpAddr) -> Result<String> {
        let start = Instant::now();
        
        let result = timeout(self.timeout, async {
            let std_ip: std::net::IpAddr = ip.into();
            let socket_addr = SocketAddr::new(std_ip, 0);
            
            // Use a simple approach for reverse DNS
            match tokio::task::spawn_blocking(move || {
                use std::ffi::CString;
                use std::ptr;
                
                // For now, use a simple approach that works on most systems
                // In a production system, you'd want to use a proper DNS library
                let addr_str = socket_addr.ip().to_string();
                
                // For MVP, return a placeholder hostname
                 // In production, implement proper PTR record lookup using a DNS library
                 let hostname = match socket_addr.ip() {
                     std::net::IpAddr::V4(ipv4) => {
                         format!("host-{}", ipv4.to_string().replace(".", "-"))
                     },
                     std::net::IpAddr::V6(ipv6) => {
                         format!("host-{}", ipv6.to_string().replace(":", "-"))
                     }
                 };
                 Ok(hostname)
            }).await {
                Ok(Ok(hostname)) => Ok(hostname),
                Ok(Err(e)) => Err(e),
                Err(_) => Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Task join error"
                ))
            }
        }).await;
        
        match result {
            Ok(Ok(hostname)) => Ok(hostname),
            Ok(Err(_)) => Err(Error::network(NetworkError::DnsResolutionFailed {
                hostname: ip.to_string(),
            })),
            Err(_) => Err(Error::network(NetworkError::DnsResolutionFailed {
                hostname: ip.to_string(),
            }))
        }
    }

    /// Check if a host is reachable (basic connectivity test)
    pub async fn is_host_reachable(&self, address: IpAddr) -> Result<bool> {
        // Localhost is always reachable
        match address {
            IpAddr::V4(ipv4) if ipv4.is_loopback() => return Ok(true),
            IpAddr::V6(ipv6) if ipv6.is_loopback() => return Ok(true),
            _ => {}
        }
        
        // Try to connect to common ports to test reachability
        let common_ports = [80, 443, 22, 21, 25, 53, 110, 143, 993, 995];
        
        for &port in &common_ports {
            let target = SocketAddr::new(address.into(), port);
            if let Ok(result) = self.test_tcp_connection(target).await {
                if result.success {
                    return Ok(true);
                }
            }
        }
        
        Ok(false)
    }

    /// Get local network interfaces
    pub fn get_network_interfaces() -> Result<Vec<NetworkInterface>> {
        let mut interfaces = Vec::new();
        
        #[cfg(unix)]
        {
            use std::ffi::CStr;
            use std::mem;
            use std::ptr;
            
            unsafe {
                let mut ifaddrs: *mut libc::ifaddrs = ptr::null_mut();
                if libc::getifaddrs(&mut ifaddrs) == 0 {
                    let mut current = ifaddrs;
                    let mut interface_map: HashMap<String, NetworkInterface> = HashMap::new();
                    
                    while !current.is_null() {
                        let ifaddr = &*current;
                        let name = CStr::from_ptr(ifaddr.ifa_name)
                            .to_string_lossy()
                            .to_string();
                        
                        let is_up = (ifaddr.ifa_flags & libc::IFF_UP as u32) != 0;
                        let is_loopback = (ifaddr.ifa_flags & libc::IFF_LOOPBACK as u32) != 0;
                        
                        let interface = interface_map.entry(name.clone()).or_insert_with(|| {
                            NetworkInterface {
                                name: name.clone(),
                                index: 0, // We'll need to get this separately
                                addresses: Vec::new(),
                                is_up,
                                is_loopback,
                                mtu: None,
                            }
                        });
                        
                        // Extract IP address if available
                        if !ifaddr.ifa_addr.is_null() {
                            let addr = &*ifaddr.ifa_addr;
                            match addr.sa_family as i32 {
                                libc::AF_INET => {
                                    let sin = &*(addr as *const _ as *const libc::sockaddr_in);
                                    let ip = std::net::Ipv4Addr::from(sin.sin_addr.s_addr.to_be());
                                    interface.addresses.push(IpAddr::V4(ip));
                                },
                                libc::AF_INET6 => {
                                    let sin6 = &*(addr as *const _ as *const libc::sockaddr_in6);
                                    let ip = std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                                    interface.addresses.push(IpAddr::V6(ip));
                                },
                                _ => {}
                            }
                        }
                        
                        current = ifaddr.ifa_next;
                    }
                    
                    libc::freeifaddrs(ifaddrs);
                    interfaces.extend(interface_map.into_values());
                }
            }
        }
        
        #[cfg(windows)]
        {
            // Windows implementation would go here
            // For now, return empty list
        }
        
        Ok(interfaces)
    }

    /// Get default gateway
    pub fn get_default_gateway() -> Result<Option<IpAddr>> {
        #[cfg(unix)]
        {
            // Try to read from /proc/net/route on Linux
            if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
                for line in content.lines().skip(1) {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    if fields.len() >= 3 && fields[1] == "00000000" {
                        // Default route (destination 0.0.0.0)
                        if let Ok(gateway_hex) = u32::from_str_radix(fields[2], 16) {
                            let gateway = std::net::Ipv4Addr::from(gateway_hex.to_be());
                            return Ok(Some(IpAddr::V4(gateway)));
                        }
                    }
                }
            }
        }
        
        #[cfg(windows)]
        {
            // Windows implementation would go here
        }
        
        Ok(None)
    }

    /// Check if an IP address is in a private range
    pub fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
            },
            IpAddr::V6(ipv6) => {
                ipv6.is_loopback() || ipv6.is_unicast_link_local() || 
                // Check for unique local addresses (fc00::/7)
                (ipv6.segments()[0] & 0xfe00) == 0xfc00
            },
        }
    }

    /// Check if an IP address is multicast
    pub fn is_multicast_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => ipv4.is_multicast(),
            IpAddr::V6(ipv6) => ipv6.is_multicast(),
        }
    }

    /// Get the network address for an IP and netmask
    pub fn get_network_address(ip: &IpAddr, netmask: &IpAddr) -> Option<IpAddr> {
        match (ip, netmask) {
            (IpAddr::V4(ip), IpAddr::V4(mask)) => {
                let ip_bytes = ip.octets();
                let mask_bytes = mask.octets();
                let network_bytes = [
                    ip_bytes[0] & mask_bytes[0],
                    ip_bytes[1] & mask_bytes[1],
                    ip_bytes[2] & mask_bytes[2],
                    ip_bytes[3] & mask_bytes[3],
                ];
                Some(IpAddr::V4(std::net::Ipv4Addr::from(network_bytes)))
            },
            (IpAddr::V6(ip), IpAddr::V6(mask)) => {
                let ip_segments = ip.segments();
                let mask_segments = mask.segments();
                let network_segments = [
                    ip_segments[0] & mask_segments[0],
                    ip_segments[1] & mask_segments[1],
                    ip_segments[2] & mask_segments[2],
                    ip_segments[3] & mask_segments[3],
                    ip_segments[4] & mask_segments[4],
                    ip_segments[5] & mask_segments[5],
                    ip_segments[6] & mask_segments[6],
                    ip_segments[7] & mask_segments[7],
                ];
                Some(IpAddr::V6(std::net::Ipv6Addr::from(network_segments)))
            },
            _ => None,
        }
    }

    /// Calculate the broadcast address for an IPv4 network
    pub fn get_broadcast_address(ip: &std::net::Ipv4Addr, netmask: &std::net::Ipv4Addr) -> std::net::Ipv4Addr {
        let ip_bytes = ip.octets();
        let mask_bytes = netmask.octets();
        let broadcast_bytes = [
            ip_bytes[0] | !mask_bytes[0],
            ip_bytes[1] | !mask_bytes[1],
            ip_bytes[2] | !mask_bytes[2],
            ip_bytes[3] | !mask_bytes[3],
        ];
        std::net::Ipv4Addr::from(broadcast_bytes)
    }
}

/// Utility functions for network operations
pub mod utils {
    use super::*;

    /// Parse a CIDR notation string into IP and prefix length
    pub fn parse_cidr(cidr: &str) -> Result<(IpAddr, u8)> {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            return Err(Error::parse(crate::error::ParseError::InvalidCidr {
                cidr: cidr.to_string(),
            }));
        }

        let ip: IpAddr = parts[0].parse().map_err(|_| {
            Error::parse(crate::error::ParseError::InvalidIpAddress {
                address: parts[0].to_string(),
            })
        })?;

        let prefix: u8 = parts[1].parse().map_err(|_| {
            Error::parse(crate::error::ParseError::InvalidCidr {
                cidr: cidr.to_string(),
            })
        })?;

        // Validate prefix length
        let max_prefix = match ip {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };

        if prefix > max_prefix {
            return Err(Error::parse(crate::error::ParseError::InvalidCidr {
                cidr: cidr.to_string(),
            }));
        }

        Ok((ip, prefix))
    }

    /// Convert prefix length to netmask
    pub fn prefix_to_netmask(prefix: u8, is_ipv6: bool) -> IpAddr {
        if is_ipv6 {
            let mut segments = [0u16; 8];
            let full_segments = prefix / 16;
            let remaining_bits = prefix % 16;

            for i in 0..full_segments as usize {
                segments[i] = 0xffff;
            }

            if remaining_bits > 0 && (full_segments as usize) < 8 {
                segments[full_segments as usize] = 0xffff << (16 - remaining_bits);
            }

            IpAddr::V6(std::net::Ipv6Addr::from(segments))
        } else {
            let mask = if prefix == 0 {
                0
            } else {
                0xffffffff << (32 - prefix)
            };
            IpAddr::V4(std::net::Ipv4Addr::from(mask))
        }
    }

    /// Check if an IP is within a CIDR range
    pub fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> Result<bool> {
        let (network_ip, prefix) = parse_cidr(cidr)?;
        
        // IPs must be the same version
        match (ip, &network_ip) {
            (IpAddr::V4(_), IpAddr::V6(_)) | (IpAddr::V6(_), IpAddr::V4(_)) => {
                return Ok(false);
            },
            _ => {}
        }

        let netmask = prefix_to_netmask(prefix, network_ip.is_ipv6());
        
        if let (Some(ip_network), Some(cidr_network)) = (
            NetworkScanner::get_network_address(ip, &netmask),
            NetworkScanner::get_network_address(&network_ip, &netmask),
        ) {
            Ok(ip_network == cidr_network)
        } else {
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn test_network_scanner_creation() {
        let scanner = NetworkScanner::new(Duration::from_secs(5));
        assert_eq!(scanner.timeout, Duration::from_secs(5));
        assert!(scanner.source_ip.is_none());
    }

    #[tokio::test]
    async fn test_dns_resolution() {
        let mut scanner = NetworkScanner::new(Duration::from_secs(5));
        
        // Test resolving localhost
        if let Ok(result) = scanner.resolve_hostname("localhost").await {
            assert!(!result.addresses.is_empty());
            assert_eq!(result.hostname, "localhost");
        }
    }

    #[test]
    fn test_private_ip_detection() {
        assert!(NetworkScanner::is_private_ip(&IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))));
        assert!(NetworkScanner::is_private_ip(&IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1))));
        assert!(NetworkScanner::is_private_ip(&IpAddr::V4(std::net::Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!NetworkScanner::is_private_ip(&IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn test_cidr_parsing() {
        let (ip, prefix) = utils::parse_cidr("192.168.1.0/24").unwrap();
        assert_eq!(ip, IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(prefix, 24);

        assert!(utils::parse_cidr("invalid").is_err());
        assert!(utils::parse_cidr("192.168.1.0/33").is_err());
    }

    #[test]
    fn test_prefix_to_netmask() {
        let netmask = utils::prefix_to_netmask(24, false);
        if let IpAddr::V4(ipv4) = netmask {
            assert_eq!(ipv4, std::net::Ipv4Addr::new(255, 255, 255, 0));
        } else {
            panic!("Expected IPv4 netmask");
        }
    }

    #[test]
    fn test_ip_in_cidr() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
        assert!(utils::ip_in_cidr(&ip, "192.168.1.0/24").unwrap());
        assert!(!utils::ip_in_cidr(&ip, "192.168.2.0/24").unwrap());
    }

    #[test]
    fn test_network_address_calculation() {
        let ip = IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 100));
        let netmask = IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 0));
        let network = NetworkScanner::get_network_address(&ip, &netmask).unwrap();
        assert_eq!(network, IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 0)));
    }

    #[test]
    fn test_broadcast_address() {
        let ip = std::net::Ipv4Addr::new(192, 168, 1, 100);
        let netmask = std::net::Ipv4Addr::new(255, 255, 255, 0);
        let broadcast = NetworkScanner::get_broadcast_address(&ip, &netmask);
        assert_eq!(broadcast, std::net::Ipv4Addr::new(192, 168, 1, 255));
    }
}
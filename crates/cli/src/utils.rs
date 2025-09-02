//! Utility functions for CLI operations

use anyhow::{anyhow, Context, Result};
use cynetmapper_core::types::{IpAddr, Protocol};
use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};
use tracing::{debug, warn};

/// Parse target specifications into IP addresses
/// Supports:
/// - Single IPs: 192.168.1.1
/// - CIDR ranges: 192.168.1.0/24
/// - IP ranges: 192.168.1.1-192.168.1.10
/// - Hostnames: example.com
pub fn parse_targets(targets: &[String]) -> Result<Vec<IpAddr>> {
    let mut parsed_targets = Vec::new();
    
    for target in targets {
        let target = target.trim();
        
        if target.is_empty() {
            continue;
        }
        
        // Try to parse as single IP
        if let Ok(ip) = target.parse::<IpAddr>() {
            parsed_targets.push(ip);
            continue;
        }
        
        // Try to parse as CIDR
        if target.contains('/') {
            let cidr_ips = parse_cidr(target)
                .with_context(|| format!("Failed to parse CIDR: {}", target))?;
            parsed_targets.extend(cidr_ips);
            continue;
        }
        
        // Try to parse as IP range
        if target.contains('-') {
            let range_ips = parse_ip_range(target)
                .with_context(|| format!("Failed to parse IP range: {}", target))?;
            parsed_targets.extend(range_ips);
            continue;
        }
        
        // Try to resolve as hostname
        match resolve_hostname(target).await {
            Ok(ips) => {
                parsed_targets.extend(ips);
            }
            Err(e) => {
                warn!("Failed to resolve hostname '{}': {}", target, e);
                return Err(anyhow!("Failed to resolve hostname '{}': {}", target, e));
            }
        }
    }
    
    if parsed_targets.is_empty() {
        return Err(anyhow!("No valid targets found"));
    }
    
    // Remove duplicates
    let unique_targets: HashSet<IpAddr> = parsed_targets.into_iter().collect();
    let mut result: Vec<IpAddr> = unique_targets.into_iter().collect();
    result.sort();
    
    debug!("Parsed {} unique targets", result.len());
    Ok(result)
}

/// Parse port specifications into port numbers
/// Supports:
/// - Single ports: 80
/// - Port ranges: 80-443
/// - Port lists: 80,443,8080
/// - Mixed: 22,80-443,8080
pub fn parse_ports(ports_str: &str) -> Result<Vec<u16>> {
    let mut ports = HashSet::new();
    
    for part in ports_str.split(',') {
        let part = part.trim();
        
        if part.is_empty() {
            continue;
        }
        
        if part.contains('-') {
            // Parse port range
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(anyhow!("Invalid port range format: {}", part));
            }
            
            let start: u16 = range_parts[0].trim().parse()
                .with_context(|| format!("Invalid start port in range: {}", part))?;
            let end: u16 = range_parts[1].trim().parse()
                .with_context(|| format!("Invalid end port in range: {}", part))?;
            
            if start > end {
                return Err(anyhow!("Invalid port range: start ({}) > end ({})", start, end));
            }
            
            for port in start..=end {
                ports.insert(port);
            }
        } else {
            // Parse single port
            let port: u16 = part.parse()
                .with_context(|| format!("Invalid port number: {}", part))?;
            ports.insert(port);
        }
    }
    
    if ports.is_empty() {
        return Err(anyhow!("No valid ports found"));
    }
    
    let mut result: Vec<u16> = ports.into_iter().collect();
    result.sort();
    
    debug!("Parsed {} unique ports", result.len());
    Ok(result)
}

/// Parse CIDR notation into IP addresses
fn parse_cidr(cidr: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid CIDR format: {}", cidr));
    }
    
    let base_ip = parts[0].parse::<IpAddr>()
        .with_context(|| format!("Invalid IP in CIDR: {}", parts[0]))?;
    let prefix_len: u8 = parts[1].parse()
        .with_context(|| format!("Invalid prefix length in CIDR: {}", parts[1]))?;
    
    match base_ip {
        IpAddr::V4(ipv4) => {
            if prefix_len > 32 {
                return Err(anyhow!("Invalid IPv4 prefix length: {}", prefix_len));
            }
            parse_ipv4_cidr(ipv4, prefix_len)
        }
        IpAddr::V6(ipv6) => {
            if prefix_len > 128 {
                return Err(anyhow!("Invalid IPv6 prefix length: {}", prefix_len));
            }
            parse_ipv6_cidr(ipv6, prefix_len)
        }
    }
}

/// Parse IPv4 CIDR into IP addresses
fn parse_ipv4_cidr(base_ip: Ipv4Addr, prefix_len: u8) -> Result<Vec<IpAddr>> {
    let mut ips = Vec::new();
    
    if prefix_len == 32 {
        ips.push(IpAddr::V4(base_ip));
        return Ok(ips);
    }
    
    let host_bits = 32 - prefix_len;
    let num_hosts = 1u32 << host_bits;
    
    // Limit the number of IPs to prevent memory issues
    if num_hosts > 65536 {
        return Err(anyhow!("CIDR range too large (>{} hosts). Use smaller ranges.", 65536));
    }
    
    let base_u32 = u32::from(base_ip);
    let network_mask = !((1u32 << host_bits) - 1);
    let network_base = base_u32 & network_mask;
    
    for i in 0..num_hosts {
        let ip_u32 = network_base + i;
        let ip = Ipv4Addr::from(ip_u32);
        ips.push(IpAddr::V4(ip));
    }
    
    Ok(ips)
}

/// Parse IPv6 CIDR into IP addresses (enhanced implementation)
fn parse_ipv6_cidr(base_ip: Ipv6Addr, prefix_len: u8) -> Result<Vec<IpAddr>> {
    if prefix_len == 128 {
        return Ok(vec![IpAddr::V6(base_ip)]);
    }
    
    // For IPv6, we support reasonable subnet sizes to avoid memory issues
    // /120 = 256 addresses, /112 = 65536 addresses
    if prefix_len < 112 {
        return Err(anyhow!("IPv6 CIDR prefix too large (minimum /112 supported)"));
    }
    
    let host_bits = 128 - prefix_len;
    let num_hosts = 1u128 << host_bits;
    
    // Limit to prevent memory exhaustion
    if num_hosts > 65536 {
        return Err(anyhow!("IPv6 CIDR range too large (maximum 65536 addresses)"));
    }
    
    let mut ips = Vec::new();
    let base_segments = base_ip.segments();
    
    // Calculate network base by applying prefix mask
    let mut network_segments = base_segments;
    let full_segments = prefix_len / 16;
    let remaining_bits = prefix_len % 16;
    
    // Clear host bits
    for i in (full_segments as usize)..8 {
        if i == full_segments as usize && remaining_bits > 0 {
            let mask = 0xffff << (16 - remaining_bits);
            network_segments[i] &= mask;
        } else if i > full_segments as usize {
            network_segments[i] = 0;
        }
    }
    
    // Generate all addresses in the subnet
    for i in 0..num_hosts {
        let mut addr_segments = network_segments;
        
        // Add the host part
        let mut host_value = i;
        for seg_idx in (0..8).rev() {
            if host_value == 0 {
                break;
            }
            addr_segments[seg_idx] = (addr_segments[seg_idx] as u128 + (host_value & 0xffff)) as u16;
            host_value >>= 16;
        }
        
        ips.push(IpAddr::V6(Ipv6Addr::from(addr_segments)));
    }
    
    Ok(ips)
}

/// Parse IP range notation into IP addresses
fn parse_ip_range(range: &str) -> Result<Vec<IpAddr>> {
    let parts: Vec<&str> = range.split('-').collect();
    if parts.len() != 2 {
        return Err(anyhow!("Invalid IP range format: {}", range));
    }
    
    let start_ip = parts[0].trim().parse::<IpAddr>()
        .with_context(|| format!("Invalid start IP in range: {}", parts[0]))?;
    let end_ip = parts[1].trim().parse::<IpAddr>()
        .with_context(|| format!("Invalid end IP in range: {}", parts[1]))?;
    
    match (start_ip, end_ip) {
        (IpAddr::V4(start), IpAddr::V4(end)) => {
            parse_ipv4_range(start, end)
        }
        (IpAddr::V6(start), IpAddr::V6(end)) => {
            parse_ipv6_range(start, end)
        }
        _ => {
            Err(anyhow!("IP range must use the same IP version"))
        }
    }
}

/// Parse IPv4 range into IP addresses
fn parse_ipv4_range(start: Ipv4Addr, end: Ipv4Addr) -> Result<Vec<IpAddr>> {
    let start_u32 = u32::from(start);
    let end_u32 = u32::from(end);
    
    if start_u32 > end_u32 {
        return Err(anyhow!("Invalid IP range: start IP is greater than end IP"));
    }
    
    let num_ips = end_u32 - start_u32 + 1;
    
    // Limit the number of IPs to prevent memory issues
    if num_ips > 65536 {
        return Err(anyhow!("IP range too large (>{} IPs). Use smaller ranges.", 65536));
    }
    
    let mut ips = Vec::new();
    for ip_u32 in start_u32..=end_u32 {
        let ip = Ipv4Addr::from(ip_u32);
        ips.push(IpAddr::V4(ip));
    }
    
    Ok(ips)
}

/// Parse IPv6 range into IP addresses
fn parse_ipv6_range(start: Ipv6Addr, end: Ipv6Addr) -> Result<Vec<IpAddr>> {
    let start_u128 = u128::from(start);
    let end_u128 = u128::from(end);
    
    if start_u128 > end_u128 {
        return Err(anyhow!("Invalid IPv6 range: start IP is greater than end IP"));
    }
    
    let num_ips = end_u128.saturating_sub(start_u128).saturating_add(1);
    
    // Limit the number of IPs to prevent memory issues
    if num_ips > 65536 {
        return Err(anyhow!("IPv6 range too large (>{} IPs). Use smaller ranges.", 65536));
    }
    
    let mut ips = Vec::new();
    let mut current = start_u128;
    
    while current <= end_u128 && ips.len() < 65536 {
        ips.push(IpAddr::V6(Ipv6Addr::from(current)));
        if current == u128::MAX {
            break; // Prevent overflow
        }
        current += 1;
    }
    
    Ok(ips)
}

/// Resolve hostname to IP addresses
async fn resolve_hostname(hostname: &str) -> Result<Vec<IpAddr>> {
    use tokio::net::lookup_host;
    
    let addresses = lookup_host(format!("{}:80", hostname)).await
        .with_context(|| format!("Failed to resolve hostname: {}", hostname))?;
    
    let ips: Vec<IpAddr> = addresses
        .map(|addr| addr.ip())
        .collect();
    
    if ips.is_empty() {
        return Err(anyhow!("No IP addresses found for hostname: {}", hostname));
    }
    
    debug!("Resolved hostname '{}' to {} IP(s)", hostname, ips.len());
    Ok(ips)
}

/// Get common ports for a protocol
pub fn get_common_ports(protocol: Protocol) -> Vec<u16> {
    match protocol {
        Protocol::Tcp => vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900,
            20, 69, 79, 88, 102, 113, 119, 135, 137, 138, 389, 445, 464, 465, 514, 515, 543,
            544, 548, 554, 587, 631, 636, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028,
            1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000,
            3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432,
            5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081,
            8443, 8888, 9100, 9999, 10000, 32768, 49152, 49153, 49154, 49155, 49156, 49157
        ],
        Protocol::Udp => vec![
            53, 67, 68, 69, 123, 135, 137, 138, 161, 162, 445, 500, 514, 520, 631, 1434,
            1900, 4500, 5353, 111, 177, 427, 443, 497, 500, 518, 626, 631, 996, 997, 998,
            1022, 1023, 1025, 1026, 1027, 1028, 1029, 1030, 1433, 1434, 1645, 1646, 1701,
            1718, 1719, 1720, 1723, 1812, 1813, 1985, 2000, 2048, 2049, 2222, 2223, 3283,
            4045, 4444, 4500, 5000, 5060, 5353, 5632, 9200, 10000, 17185, 20031, 30718,
            31337, 32768, 32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777,
            32778, 32779, 32780, 32781, 32782, 32783, 32784, 49152, 49153, 49154, 49155,
            49156, 49157, 49158, 49159, 49160, 49161, 49162, 49163, 49164, 49165, 49166,
            49167, 49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175, 49176, 49177
        ],
        Protocol::Icmp => vec![], // ICMP doesn't use ports
        Protocol::Sctp => vec![
            22, 80, 443, 2905, 2944, 2945, 3863, 3864, 3865, 4739, 4740, 5060, 5061,
            9899, 9900, 11997, 11998, 11999, 14001, 20049
        ],
    }
}

/// Get top ports for a protocol
pub fn get_top_ports(protocol: Protocol, count: usize) -> Vec<u16> {
    let common_ports = get_common_ports(protocol);
    common_ports.into_iter().take(count).collect()
}

/// Format duration in human-readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_secs = duration.as_secs();
    let millis = duration.subsec_millis();
    
    if total_secs >= 3600 {
        let hours = total_secs / 3600;
        let minutes = (total_secs % 3600) / 60;
        let seconds = total_secs % 60;
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if total_secs >= 60 {
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{}m {}s", minutes, seconds)
    } else if total_secs > 0 {
        format!("{}.{:03}s", total_secs, millis)
    } else {
        format!("{}ms", millis)
    }
}

/// Format bytes in human-readable format
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    
    if bytes == 0 {
        return "0 B".to_string();
    }
    
    let mut size = bytes as f64;
    let mut unit_index = 0;
    
    while size >= 1024.0 && unit_index < UNITS.len() - 1 {
        size /= 1024.0;
        unit_index += 1;
    }
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else {
        format!("{:.2} {}", size, UNITS[unit_index])
    }
}

/// Validate IP address
pub fn is_valid_ip(ip_str: &str) -> bool {
    ip_str.parse::<IpAddr>().is_ok()
}

/// Validate port number
pub fn is_valid_port(port: u16) -> bool {
    port > 0
}

/// Check if IP is in private range
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_private() || ipv4.is_loopback() || ipv4.is_link_local()
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback() || ipv6.is_unicast_link_local() || 
            ipv6.segments()[0] & 0xfe00 == 0xfc00 // Unique local addresses
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ports_single() {
        let ports = parse_ports("80").unwrap();
        assert_eq!(ports, vec![80]);
    }

    #[test]
    fn test_parse_ports_range() {
        let ports = parse_ports("80-82").unwrap();
        assert_eq!(ports, vec![80, 81, 82]);
    }

    #[test]
    fn test_parse_ports_list() {
        let ports = parse_ports("80,443,8080").unwrap();
        assert_eq!(ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_parse_ports_mixed() {
        let ports = parse_ports("22,80-82,443").unwrap();
        assert_eq!(ports, vec![22, 80, 81, 82, 443]);
    }

    #[test]
    fn test_parse_ipv4_cidr() {
        let ips = parse_cidr("192.168.1.0/30").unwrap();
        assert_eq!(ips.len(), 4);
        assert!(ips.contains(&"192.168.1.0".parse().unwrap()));
        assert!(ips.contains(&"192.168.1.3".parse().unwrap()));
    }

    #[test]
    fn test_parse_ipv4_range() {
        let ips = parse_ip_range("192.168.1.1-192.168.1.3").unwrap();
        assert_eq!(ips.len(), 3);
        assert!(ips.contains(&"192.168.1.1".parse().unwrap()));
        assert!(ips.contains(&"192.168.1.2".parse().unwrap()));
        assert!(ips.contains(&"192.168.1.3".parse().unwrap()));
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(std::time::Duration::from_millis(500)), "500ms");
        assert_eq!(format_duration(std::time::Duration::from_secs(1)), "1.000s");
        assert_eq!(format_duration(std::time::Duration::from_secs(65)), "1m 5s");
        assert_eq!(format_duration(std::time::Duration::from_secs(3665)), "1h 1m 5s");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1536), "1.50 KB");
        assert_eq!(format_bytes(1048576), "1.00 MB");
    }

    #[test]
    fn test_is_valid_ip() {
        assert!(is_valid_ip("192.168.1.1"));
        assert!(is_valid_ip("::1"));
        assert!(!is_valid_ip("invalid"));
        assert!(!is_valid_ip("256.256.256.256"));
    }

    #[test]
    fn test_is_valid_port() {
        assert!(is_valid_port(80));
        assert!(is_valid_port(65535));
        assert!(!is_valid_port(0));
    }

    #[test]
    fn test_is_private_ip() {
        assert!(is_private_ip(&"192.168.1.1".parse().unwrap()));
        assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
        assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_get_common_ports() {
        let tcp_ports = get_common_ports(Protocol::Tcp);
        assert!(!tcp_ports.is_empty());
        assert!(tcp_ports.contains(&80));
        assert!(tcp_ports.contains(&443));
        
        let udp_ports = get_common_ports(Protocol::Udp);
        assert!(!udp_ports.is_empty());
        assert!(udp_ports.contains(&53));
        assert!(udp_ports.contains(&123));
    }

    #[test]
    fn test_get_top_ports() {
        let top_tcp = get_top_ports(Protocol::Tcp, 10);
        assert_eq!(top_tcp.len(), 10);
        
        let top_udp = get_top_ports(Protocol::Udp, 5);
        assert_eq!(top_udp.len(), 5);
    }

    #[test]
    fn test_parse_ipv6_cidr() {
        // Test /128 (single host)
        let result = parse_ipv6_cidr("::1".parse().unwrap(), 128).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], IpAddr::V6("::1".parse().unwrap()));
        
        // Test /120 (256 addresses)
        let result = parse_ipv6_cidr("2001:db8::".parse().unwrap(), 120).unwrap();
        assert_eq!(result.len(), 256);
        
        // Test invalid prefix (too large)
        let result = parse_ipv6_cidr("2001:db8::".parse().unwrap(), 64);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ipv6_range() {
        // Test small range
        let start: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::3".parse().unwrap();
        let result = parse_ipv6_range(start, end).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], IpAddr::V6("2001:db8::1".parse().unwrap()));
        assert_eq!(result[1], IpAddr::V6("2001:db8::2".parse().unwrap()));
        assert_eq!(result[2], IpAddr::V6("2001:db8::3".parse().unwrap()));
        
        // Test invalid range (start > end)
        let start: Ipv6Addr = "2001:db8::3".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let result = parse_ipv6_range(start, end);
        assert!(result.is_err());
    }
}
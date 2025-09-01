//! JSON output format implementation
//!
//! This module provides JSON serialization for scan results with schema validation
//! and canonical format support.

use std::path::Path;
use serde_json::{Map, Value};
use crate::{OutputError, OutputResult, ScanResults};

/// JSON schema version
pub const JSON_SCHEMA_VERSION: &str = "1.0.0";

/// Canonical JSON schema for cyNetMapper output
pub const CANONICAL_SCHEMA: &str = r#"{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "cyNetMapper Scan Results",
  "description": "Canonical schema for cyNetMapper network scan results",
  "version": "1.0.0",
  "type": "object",
  "required": ["metadata", "hosts", "statistics"],
  "properties": {
    "metadata": {
      "type": "object",
      "required": ["start_time", "scanner_version", "command_line", "scan_type", "targets"],
      "properties": {
        "start_time": {
          "type": "string",
          "format": "date-time",
          "description": "ISO 8601 timestamp when scan started"
        },
        "end_time": {
          "type": ["string", "null"],
          "format": "date-time",
          "description": "ISO 8601 timestamp when scan ended"
        },
        "scanner_version": {
          "type": "string",
          "description": "Version of cyNetMapper used"
        },
        "command_line": {
          "type": "string",
          "description": "Command line arguments used"
        },
        "scan_type": {
          "type": "string",
          "enum": ["tcp_connect", "tcp_syn", "udp", "icmp", "arp", "discovery"],
          "description": "Type of scan performed"
        },
        "targets": {
          "type": "array",
          "items": {
            "type": "string"
          },
          "description": "Target specifications"
        }
      }
    },
    "hosts": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["address", "state", "hostnames", "ports"],
        "properties": {
          "address": {
            "type": "string",
            "format": "ipv4",
            "description": "IP address of the host"
          },
          "state": {
            "type": "string",
            "enum": ["up", "down", "unknown", "filtered"],
            "description": "Host state"
          },
          "hostnames": {
            "type": "array",
            "items": {
              "type": "string"
            },
            "description": "Resolved hostnames"
          },
          "ports": {
            "type": "array",
            "items": {
              "type": "object",
              "required": ["port", "protocol", "state"],
              "properties": {
                "port": {
                  "type": "integer",
                  "minimum": 1,
                  "maximum": 65535,
                  "description": "Port number"
                },
                "protocol": {
                  "type": "string",
                  "enum": ["tcp", "udp", "sctp", "icmp"],
                  "description": "Protocol type"
                },
                "state": {
                  "type": "string",
                  "enum": ["open", "closed", "filtered", "open_filtered", "closed_filtered", "unfiltered"],
                  "description": "Port state"
                },
                "service": {
                  "type": ["object", "null"],
                  "properties": {
                    "name": {
                      "type": "string",
                      "description": "Service name"
                    },
                    "version": {
                      "type": ["string", "null"],
                      "description": "Service version"
                    },
                    "product": {
                      "type": ["string", "null"],
                      "description": "Service product"
                    },
                    "confidence": {
                      "type": "number",
                      "minimum": 0,
                      "maximum": 1,
                      "description": "Detection confidence"
                    }
                  }
                },
                "banner": {
                  "type": ["string", "null"],
                  "description": "Service banner"
                }
              }
            }
          },
          "os_fingerprint": {
            "type": ["object", "null"],
            "properties": {
              "family": {
                "type": "string",
                "description": "OS family"
              },
              "version": {
                "type": ["string", "null"],
                "description": "OS version"
              },
              "confidence": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "description": "Detection confidence"
              }
            }
          }
        }
      }
    },
    "statistics": {
      "type": "object",
      "required": ["total_hosts", "hosts_up", "hosts_down", "total_ports", "open_ports", "closed_ports", "filtered_ports", "duration"],
      "properties": {
        "total_hosts": {
          "type": "integer",
          "minimum": 0,
          "description": "Total number of hosts scanned"
        },
        "hosts_up": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of hosts found up"
        },
        "hosts_down": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of hosts found down"
        },
        "total_ports": {
          "type": "integer",
          "minimum": 0,
          "description": "Total number of ports scanned"
        },
        "open_ports": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of open ports found"
        },
        "closed_ports": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of closed ports found"
        },
        "filtered_ports": {
          "type": "integer",
          "minimum": 0,
          "description": "Number of filtered ports found"
        },
        "duration": {
          "type": "number",
          "minimum": 0,
          "description": "Scan duration in seconds"
        }
      }
    }
  }
}"#;

/// Export scan results to canonical JSON format
pub async fn export_canonical_json<P: AsRef<Path>>(
    results: &ScanResults,
    output_path: P,
    pretty: bool,
) -> OutputResult<()> {
    let json_value = to_canonical_json(results)?;
    
    let json_string = if pretty {
        serde_json::to_string_pretty(&json_value)
    } else {
        serde_json::to_string(&json_value)
    }
    .map_err(|e| OutputError::Serialization(e.to_string()))?;
    
    tokio::fs::write(output_path, json_string).await?;
    Ok(())
}

/// Convert scan results to canonical JSON format
pub fn to_canonical_json(results: &ScanResults) -> OutputResult<Value> {
    let mut root = Map::new();
    
    // Add schema version
    root.insert("schema_version".to_string(), Value::String(JSON_SCHEMA_VERSION.to_string()));
    
    // Convert metadata
    let mut metadata = Map::new();
    metadata.insert("start_time".to_string(), 
        Value::String(format_timestamp(results.metadata.start_time)));
    
    if let Some(end_time) = results.metadata.end_time {
        metadata.insert("end_time".to_string(), 
            Value::String(format_timestamp(end_time)));
    } else {
        metadata.insert("end_time".to_string(), Value::Null);
    }
    
    metadata.insert("scanner_version".to_string(), 
        Value::String(results.metadata.scanner_version.clone()));
    metadata.insert("command_line".to_string(), 
        Value::String(results.metadata.command_line.clone()));
    metadata.insert("scan_type".to_string(), 
        Value::String(results.metadata.scan_type.clone()));
    metadata.insert("targets".to_string(), 
        Value::Array(results.metadata.targets.iter()
            .map(|t| Value::String(t.clone()))
            .collect()));
    
    root.insert("metadata".to_string(), Value::Object(metadata));
    
    // Convert hosts
    let hosts: Vec<Value> = results.hosts.iter()
        .map(|host| {
            let mut host_obj = Map::new();
            host_obj.insert("address".to_string(), Value::String(host.address.clone()));
            host_obj.insert("state".to_string(), Value::String(format!("{:?}", host.state).to_lowercase()));
            host_obj.insert("hostnames".to_string(), 
                Value::Array(host.hostnames.iter()
                    .map(|h| Value::String(h.clone()))
                    .collect()));
            
            // Convert ports
            let ports: Vec<Value> = host.ports.iter()
                .map(|port| {
                    let mut port_obj = Map::new();
                    port_obj.insert("port".to_string(), Value::Number(port.port.into()));
                    port_obj.insert("protocol".to_string(), 
                        Value::String(format!("{:?}", port.protocol).to_lowercase()));
                    port_obj.insert("state".to_string(), 
                        Value::String(format!("{:?}", port.state).to_lowercase()));
                    
                    if let Some(service) = &port.service {
                        let mut service_obj = Map::new();
                        service_obj.insert("name".to_string(), Value::String(service.name.clone()));
                        service_obj.insert("version".to_string(), 
                            service.version.as_ref().map(|v| Value::String(v.clone())).unwrap_or(Value::Null));
                        service_obj.insert("product".to_string(), 
                            service.product.as_ref().map(|p| Value::String(p.clone())).unwrap_or(Value::Null));
                        service_obj.insert("confidence".to_string(), 
                            Value::Number(serde_json::Number::from_f64(service.confidence).unwrap_or_else(|| serde_json::Number::from_f64(0.0).unwrap())));
                        port_obj.insert("service".to_string(), Value::Object(service_obj));
                    } else {
                        port_obj.insert("service".to_string(), Value::Null);
                    }
                    
                    port_obj.insert("banner".to_string(), 
                        port.banner.as_ref().map(|b| Value::String(b.clone())).unwrap_or(Value::Null));
                    
                    Value::Object(port_obj)
                })
                .collect();
            
            host_obj.insert("ports".to_string(), Value::Array(ports));
            
            // Add OS fingerprint if available
            if let Some(os) = &host.os_fingerprint {
                let mut os_obj = Map::new();
                os_obj.insert("family".to_string(), Value::String(os.family.clone()));
                os_obj.insert("version".to_string(), 
                    os.version.as_ref().map(|v| Value::String(v.clone())).unwrap_or(Value::Null));
                os_obj.insert("confidence".to_string(), 
                    Value::Number(serde_json::Number::from_f64(os.confidence).unwrap_or_else(|| serde_json::Number::from_f64(0.0).unwrap())));
                host_obj.insert("os_fingerprint".to_string(), Value::Object(os_obj));
            } else {
                host_obj.insert("os_fingerprint".to_string(), Value::Null);
            }
            
            Value::Object(host_obj)
        })
        .collect();
    
    root.insert("hosts".to_string(), Value::Array(hosts));
    
    // Convert statistics
    let mut stats = Map::new();
    stats.insert("total_hosts".to_string(), Value::Number(results.statistics.total_hosts.into()));
    stats.insert("hosts_up".to_string(), Value::Number(results.statistics.hosts_up.into()));
    stats.insert("hosts_down".to_string(), Value::Number(results.statistics.hosts_down.into()));
    stats.insert("total_ports".to_string(), Value::Number(results.statistics.total_ports.into()));
    stats.insert("open_ports".to_string(), Value::Number(results.statistics.open_ports.into()));
    stats.insert("closed_ports".to_string(), Value::Number(results.statistics.closed_ports.into()));
    stats.insert("filtered_ports".to_string(), Value::Number(results.statistics.filtered_ports.into()));
    stats.insert("duration".to_string(), 
        Value::Number(serde_json::Number::from_f64(results.statistics.duration.as_secs_f64()).unwrap_or_else(|| serde_json::Number::from_f64(0.0).unwrap())));
    
    root.insert("statistics".to_string(), Value::Object(stats));
    
    Ok(Value::Object(root))
}

/// Format SystemTime as ISO 8601 timestamp
fn format_timestamp(time: std::time::SystemTime) -> String {
    use std::time::UNIX_EPOCH;
    
    let duration = time.duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0));
    
    let secs = duration.as_secs();
    let nanos = duration.subsec_nanos();
    
    // Simple ISO 8601 formatting
    format!("{}T{}Z", 
        chrono::DateTime::from_timestamp(secs as i64, nanos)
            .unwrap_or_default()
            .format("%Y-%m-%dT%H:%M:%S%.3f"),
        "")
}

/// Validate JSON against canonical schema
pub fn validate_canonical_json(json_value: &Value) -> OutputResult<()> {
    // Basic validation - in a real implementation, use jsonschema crate
    if !json_value.is_object() {
        return Err(OutputError::Serialization("Root must be an object".to_string()));
    }
    
    let obj = json_value.as_object().unwrap();
    
    // Check required fields
    let required_fields = ["metadata", "hosts", "statistics"];
    for field in &required_fields {
        if !obj.contains_key(*field) {
            return Err(OutputError::Serialization(
                format!("Missing required field: {}", field)
            ));
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanResults;
    use tempfile::NamedTempFile;
    
    #[tokio::test]
    async fn test_canonical_json_export() {
        let results = ScanResults::default();
        let temp_file = NamedTempFile::new().unwrap();
        
        export_canonical_json(&results, temp_file.path(), true)
            .await
            .unwrap();
        
        let content = tokio::fs::read_to_string(temp_file.path()).await.unwrap();
        assert!(!content.is_empty());
        
        // Verify it's valid JSON
        let json_value: Value = serde_json::from_str(&content).unwrap();
        validate_canonical_json(&json_value).unwrap();
    }
    
    #[test]
    fn test_canonical_json_conversion() {
        let results = ScanResults::default();
        let json_value = to_canonical_json(&results).unwrap();
        
        validate_canonical_json(&json_value).unwrap();
        
        // Check schema version
        assert_eq!(json_value["schema_version"], JSON_SCHEMA_VERSION);
    }
}
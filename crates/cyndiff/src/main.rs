//! cyNetMapper Diff Tool
//!
//! A command-line tool for comparing cyNetMapper scan results
//! and generating detailed difference reports.

use std::path::PathBuf;
use clap::{Arg, Command};
use cynetmapper_outputs::{
    ScanResults, ScanDiff, OutputFormat, OutputManager,
    compare_scan_results, generate_diff_report
};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};

#[tokio::main]
async fn main() -> Result<()> {
    let matches = Command::new("cyndiff")
        .version("1.0.0")
        .author("cyNetMapper Team")
        .about("Compare cyNetMapper scan results and generate diff reports")
        .arg(
            Arg::new("source")
                .help("Source scan results file (JSON format)")
                .required(true)
                .index(1)
        )
        .arg(
            Arg::new("target")
                .help("Target scan results file (JSON format)")
                .required(true)
                .index(2)
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for diff report (default: stdout)")
        )
        .arg(
            Arg::new("format")
                .short('f')
                .long("format")
                .value_name("FORMAT")
                .help("Output format: text, json, html")
                .default_value("text")
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose output")
                .action(clap::ArgAction::SetTrue)
        )
        .arg(
            Arg::new("summary-only")
                .short('s')
                .long("summary-only")
                .help("Show only summary statistics")
                .action(clap::ArgAction::SetTrue)
        )
        .get_matches();

    let source_path = matches.get_one::<String>("source").unwrap();
    let target_path = matches.get_one::<String>("target").unwrap();
    let output_path = matches.get_one::<String>("output");
    let format = matches.get_one::<String>("format").unwrap();
    let verbose = matches.get_flag("verbose");
    let summary_only = matches.get_flag("summary-only");

    if verbose {
        println!("Loading source scan: {}", source_path);
    }
    
    // Load source scan results
    let source_content = tokio::fs::read_to_string(source_path)
        .await
        .with_context(|| format!("Failed to read source file: {}", source_path))?;
    
    let source_results: ScanResults = serde_json::from_str(&source_content)
        .with_context(|| format!("Failed to parse source JSON: {}", source_path))?;

    if verbose {
        println!("Loading target scan: {}", target_path);
    }
    
    // Load target scan results
    let target_content = tokio::fs::read_to_string(target_path)
        .await
        .with_context(|| format!("Failed to read target file: {}", target_path))?;
    
    let target_results: ScanResults = serde_json::from_str(&target_content)
        .with_context(|| format!("Failed to parse target JSON: {}", target_path))?;

    if verbose {
        println!("Comparing scan results...");
    }
    
    // Generate diff
    let diff = compare_scan_results(&source_results, &target_results)
        .with_context(|| "Failed to compare scan results")?;

    // Generate output based on format
    let output_content = match format.as_str() {
        "text" => {
            if summary_only {
                generate_summary_report(&diff)
            } else {
                generate_diff_report(&diff)
            }
        },
        "json" => {
            serde_json::to_string_pretty(&diff)
                .with_context(|| "Failed to serialize diff to JSON")?
        },
        "html" => {
            generate_html_report(&diff, summary_only)?
        },
        _ => {
            anyhow::bail!("Unsupported output format: {}. Use 'text', 'json', or 'html'", format);
        }
    };

    // Output results
    if let Some(output_file) = output_path {
        if verbose {
            println!("Writing output to: {}", output_file);
        }
        tokio::fs::write(output_file, &output_content)
            .await
            .with_context(|| format!("Failed to write output file: {}", output_file))?;
    } else {
        println!("{}", output_content);
    }

    if verbose {
        println!("Diff completed successfully!");
    }

    Ok(())
}

/// Generate a summary-only report
fn generate_summary_report(diff: &ScanDiff) -> String {
    let mut report = String::new();
    
    report.push_str(&format!(
        "cyNetMapper Scan Comparison Summary\n"
    ));
    report.push_str(&format!(
        "Generated: {}\n",
        DateTime::<Utc>::from(diff.metadata.generated_at)
            .format("%Y-%m-%d %H:%M:%S UTC")
    ));
    report.push_str(&format!(
        "Source: {}\n",
        diff.metadata.source_scan
    ));
    report.push_str(&format!(
        "Target: {}\n\n",
        diff.metadata.target_scan
    ));
    
    // Summary statistics
    report.push_str(&format!(
        "Hosts: {} -> {} ({:+})\n",
        diff.summary.source_hosts,
        diff.summary.target_hosts,
        diff.summary.target_hosts as i32 - diff.summary.source_hosts as i32
    ));
    report.push_str(&format!(
        "  Added: {}, Removed: {}, Changed: {}\n\n",
        diff.summary.hosts_added,
        diff.summary.hosts_removed,
        diff.summary.hosts_changed
    ));
    
    report.push_str(&format!(
        "Ports: {} -> {} ({:+})\n",
        diff.summary.source_ports,
        diff.summary.target_ports,
        diff.summary.target_ports as i32 - diff.summary.source_ports as i32
    ));
    report.push_str(&format!(
        "  Added: {}, Removed: {}, Changed: {}\n",
        diff.summary.ports_added,
        diff.summary.ports_removed,
        diff.summary.ports_changed
    ));
    
    report
}

/// Generate an HTML report
fn generate_html_report(diff: &ScanDiff, summary_only: bool) -> Result<String> {
    let mut html = String::new();
    
    // HTML header
    html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>cyNetMapper Scan Comparison</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 20px; background-color: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; margin-top: 30px; }
        .metadata { background: #ecf0f1; padding: 15px; border-radius: 5px; margin-bottom: 20px; }
        .summary { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 30px; }
        .summary-card { background: #3498db; color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .summary-card h3 { margin: 0 0 10px 0; }
        .summary-card .number { font-size: 2em; font-weight: bold; }
        .change-positive { color: #27ae60; }
        .change-negative { color: #e74c3c; }
        .change-neutral { color: #95a5a6; }
        .host-list { margin: 20px 0; }
        .host-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; border-radius: 4px; }
        .port-change { margin: 5px 0; padding: 8px; background: #fff; border-radius: 3px; }
        .added { border-left: 4px solid #27ae60; }
        .removed { border-left: 4px solid #e74c3c; }
        .changed { border-left: 4px solid #f39c12; }
        .timestamp { color: #7f8c8d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
"#);
    
    // Title and metadata
    html.push_str(&format!(
        "<h1>cyNetMapper Scan Comparison Report</h1>\n"
    ));
    
    html.push_str(&format!(
        "<div class=\"metadata\">\n"
    ));
    html.push_str(&format!(
        "<p><strong>Generated:</strong> <span class=\"timestamp\">{}</span></p>\n",
        DateTime::<Utc>::from(diff.metadata.generated_at)
            .format("%Y-%m-%d %H:%M:%S UTC")
    ));
    html.push_str(&format!(
        "<p><strong>Source:</strong> {}</p>\n",
        html_escape(&diff.metadata.source_scan)
    ));
    html.push_str(&format!(
        "<p><strong>Target:</strong> {}</p>\n",
        html_escape(&diff.metadata.target_scan)
    ));
    html.push_str("</div>\n");
    
    // Summary cards
    html.push_str("<div class=\"summary\">\n");
    
    // Hosts summary
    let host_change = diff.summary.target_hosts as i32 - diff.summary.source_hosts as i32;
    let host_change_class = if host_change > 0 { "change-positive" } else if host_change < 0 { "change-negative" } else { "change-neutral" };
    
    html.push_str(&format!(
        "<div class=\"summary-card\">\n<h3>Hosts</h3>\n<div class=\"number\">{} → {}</div>\n<div class=\"{}\">({:+})</div>\n</div>\n",
        diff.summary.source_hosts,
        diff.summary.target_hosts,
        host_change_class,
        host_change
    ));
    
    // Ports summary
    let port_change = diff.summary.target_ports as i32 - diff.summary.source_ports as i32;
    let port_change_class = if port_change > 0 { "change-positive" } else if port_change < 0 { "change-negative" } else { "change-neutral" };
    
    html.push_str(&format!(
        "<div class=\"summary-card\">\n<h3>Ports</h3>\n<div class=\"number\">{} → {}</div>\n<div class=\"{}\">({:+})</div>\n</div>\n",
        diff.summary.source_ports,
        diff.summary.target_ports,
        port_change_class,
        port_change
    ));
    
    html.push_str("</div>\n");
    
    if !summary_only {
        // Detailed changes
        if !diff.hosts_added.is_empty() {
            html.push_str("<h2>Hosts Added</h2>\n<div class=\"host-list\">\n");
            for host in &diff.hosts_added {
                html.push_str(&format!(
                    "<div class=\"host-item added\">\n<strong>{}</strong> ({} ports)\n</div>\n",
                    html_escape(&host.address),
                    host.ports.len()
                ));
            }
            html.push_str("</div>\n");
        }
        
        if !diff.hosts_removed.is_empty() {
            html.push_str("<h2>Hosts Removed</h2>\n<div class=\"host-list\">\n");
            for host in &diff.hosts_removed {
                html.push_str(&format!(
                    "<div class=\"host-item removed\">\n<strong>{}</strong> ({} ports)\n</div>\n",
                    html_escape(&host.address),
                    host.ports.len()
                ));
            }
            html.push_str("</div>\n");
        }
        
        if !diff.hosts_changed.is_empty() {
            html.push_str("<h2>Hosts Changed</h2>\n<div class=\"host-list\">\n");
            for host_diff in &diff.hosts_changed {
                html.push_str(&format!(
                    "<div class=\"host-item changed\">\n<strong>{}</strong>\n",
                    html_escape(&host_diff.address)
                ));
                
                for port_change in &host_diff.port_changes {
                    let change_class = match port_change.change_type {
                        cynetmapper_outputs::PortChangeType::Added => "added",
                        cynetmapper_outputs::PortChangeType::Removed => "removed",
                        _ => "changed",
                    };
                    
                    html.push_str(&format!(
                        "<div class=\"port-change {}\">Port {}/{}: {}</div>\n",
                        change_class,
                        port_change.port,
                        html_escape(&port_change.protocol),
                        match &port_change.change_type {
                            cynetmapper_outputs::PortChangeType::Added => 
                                format!("Added ({})", port_change.new_state.as_deref().unwrap_or("unknown")),
                            cynetmapper_outputs::PortChangeType::Removed => 
                                format!("Removed ({})", port_change.previous_state.as_deref().unwrap_or("unknown")),
                            cynetmapper_outputs::PortChangeType::StateChanged => 
                                format!("{} → {}", 
                                    port_change.previous_state.as_deref().unwrap_or("unknown"),
                                    port_change.new_state.as_deref().unwrap_or("unknown")),
                            cynetmapper_outputs::PortChangeType::ServiceChanged => 
                                port_change.service_changes.as_deref().unwrap_or("Service changed").to_string(),
                        }
                    ));
                }
                
                html.push_str("</div>\n");
            }
            html.push_str("</div>\n");
        }
    }
    
    // HTML footer
    html.push_str("</div>\n</body>\n</html>\n");
    
    Ok(html)
}

/// Escape HTML special characters
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_html_escape() {
        assert_eq!(html_escape("<script>alert('xss')</script>"), "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;");
        assert_eq!(html_escape("AT&T"), "AT&amp;T");
        assert_eq!(html_escape("normal text"), "normal text");
    }
    
    #[test]
    fn test_summary_generation() {
        use cynetmapper_outputs::*;
        
        let diff = ScanDiff {
            metadata: DiffMetadata {
                generated_at: std::time::SystemTime::now(),
                source_scan: "test1".to_string(),
                target_scan: "test2".to_string(),
                diff_version: "1.0.0".to_string(),
            },
            hosts_added: vec![],
            hosts_removed: vec![],
            hosts_changed: vec![],
            summary: DiffSummary {
                source_hosts: 5,
                target_hosts: 7,
                hosts_added: 2,
                hosts_removed: 0,
                hosts_changed: 0,
                source_ports: 10,
                target_ports: 14,
                ports_added: 4,
                ports_removed: 0,
                ports_changed: 0,
            },
        };
        
        let summary = generate_summary_report(&diff);
        assert!(summary.contains("Hosts: 5 -> 7 (+2)"));
        assert!(summary.contains("Ports: 10 -> 14 (+4)"));
    }
}
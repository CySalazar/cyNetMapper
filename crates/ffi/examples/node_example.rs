//! Node.js bindings example for cyNetMapper
//! 
//! This example demonstrates how to create Node.js bindings using Neon.

use neon::prelude::*;
use std::collections::HashMap;

/// NetworkScanner class for Node.js
struct NetworkScanner {
    target: String,
    ports: Vec<u16>,
    results: HashMap<u16, String>,
}

impl NetworkScanner {
    fn new(target: String) -> Self {
        NetworkScanner {
            target,
            ports: Vec::new(),
            results: HashMap::new(),
        }
    }
    
    fn add_port(&mut self, port: u16) {
        self.ports.push(port);
    }
    
    fn scan(&mut self) {
        println!("Scanning target: {}", self.target);
        
        for &port in &self.ports {
            let status = match port {
                22 => "open (SSH)",
                80 => "open (HTTP)",
                443 => "open (HTTPS)",
                8080 => "open (HTTP-Alt)",
                _ => "closed",
            };
            
            self.results.insert(port, status.to_string());
            println!("Port {}: {}", port, status);
        }
    }
}

/// Create a new NetworkScanner instance
fn create_scanner(mut cx: FunctionContext) -> JsResult<JsBox<NetworkScanner>> {
    let target = cx.argument::<JsString>(0)?.value(&mut cx);
    let scanner = NetworkScanner::new(target);
    Ok(cx.boxed(scanner))
}

/// Add a port to the scanner
fn add_port(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let scanner = cx.argument::<JsBox<NetworkScanner>>(0)?;
    let port = cx.argument::<JsNumber>(1)?.value(&mut cx) as u16;
    
    let mut scanner = scanner.borrow_mut();
    scanner.add_port(port);
    
    Ok(cx.undefined())
}

/// Add multiple ports to the scanner
fn add_ports(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let scanner = cx.argument::<JsBox<NetworkScanner>>(0)?;
    let ports_array = cx.argument::<JsArray>(1)?;
    
    let mut scanner = scanner.borrow_mut();
    
    for i in 0..ports_array.len(&mut cx) {
        let port: Handle<JsNumber> = ports_array.get(&mut cx, i)?;
        scanner.add_port(port.value(&mut cx) as u16);
    }
    
    Ok(cx.undefined())
}

/// Perform the scan
fn scan(mut cx: FunctionContext) -> JsResult<JsUndefined> {
    let scanner = cx.argument::<JsBox<NetworkScanner>>(0)?;
    let mut scanner = scanner.borrow_mut();
    scanner.scan();
    Ok(cx.undefined())
}

/// Get scan results
fn get_results(mut cx: FunctionContext) -> JsResult<JsObject> {
    let scanner = cx.argument::<JsBox<NetworkScanner>>(0)?;
    let scanner = scanner.borrow();
    
    let results = cx.empty_object();
    
    for (port, status) in &scanner.results {
        let port_key = cx.string(port.to_string());
        let status_value = cx.string(status);
        results.set(&mut cx, port_key, status_value)?;
    }
    
    Ok(results)
}

/// Quick scan function
fn quick_scan(mut cx: FunctionContext) -> JsResult<JsObject> {
    let target = cx.argument::<JsString>(0)?.value(&mut cx);
    let ports_array = cx.argument::<JsArray>(1)?;
    
    let mut ports = Vec::new();
    for i in 0..ports_array.len(&mut cx) {
        let port: Handle<JsNumber> = ports_array.get(&mut cx, i)?;
        ports.push(port.value(&mut cx) as u16);
    }
    
    println!("Quick scanning {} on ports {:?}", target, ports);
    
    let results = cx.empty_object();
    
    for port in ports {
        let status = match port {
            22 => "open (SSH)",
            80 => "open (HTTP)",
            443 => "open (HTTPS)",
            8080 => "open (HTTP-Alt)",
            _ => "closed",
        };
        
        let port_key = cx.string(port.to_string());
        let status_value = cx.string(status);
        results.set(&mut cx, port_key, status_value)?;
    }
    
    Ok(results)
}

/// Host discovery function
fn discover_hosts(mut cx: FunctionContext) -> JsResult<JsArray> {
    let network = cx.argument::<JsString>(0)?.value(&mut cx);
    
    println!("Discovering hosts in {}", network);
    
    let hosts = cx.empty_array();
    
    // Simulate network discovery
    let base_network = network.trim_end_matches(".0/24");
    let example_hosts = vec![
        format!("{}.1", base_network),
        format!("{}.10", base_network),
        format!("{}.100", base_network),
    ];
    
    for (i, host) in example_hosts.iter().enumerate() {
        let host_value = cx.string(host);
        hosts.set(&mut cx, i as u32, host_value)?;
    }
    
    Ok(hosts)
}

/// Get version information
fn version(mut cx: FunctionContext) -> JsResult<JsString> {
    Ok(cx.string(env!("CARGO_PKG_VERSION")))
}

/// Async scan function (example)
fn async_scan(mut cx: FunctionContext) -> JsResult<JsPromise> {
    let target = cx.argument::<JsString>(0)?.value(&mut cx);
    let ports_array = cx.argument::<JsArray>(1)?;
    
    let mut ports = Vec::new();
    for i in 0..ports_array.len(&mut cx) {
        let port: Handle<JsNumber> = ports_array.get(&mut cx, i)?;
        ports.push(port.value(&mut cx) as u16);
    }
    
    let promise = cx.task(move || {
        // Simulate async scanning
        std::thread::sleep(std::time::Duration::from_millis(100));
        
        let mut results = HashMap::new();
        for port in ports {
            let status = match port {
                22 => "open (SSH)",
                80 => "open (HTTP)",
                443 => "open (HTTPS)",
                8080 => "open (HTTP-Alt)",
                _ => "closed",
            };
            results.insert(port, status.to_string());
        }
        
        Ok(results)
    }).promise(|mut cx, results| {
        let obj = cx.empty_object();
        
        match results {
            Ok(results) => {
                for (port, status) in results {
                    let port_key = cx.string(port.to_string());
                    let status_value = cx.string(status);
                    obj.set(&mut cx, port_key, status_value)?;
                }
            }
            Err(_) => {
                return cx.throw_error("Scan failed");
            }
        }
        
        Ok(obj)
    });
    
    Ok(promise)
}

/// Module registration
#[neon::main]
fn main(mut cx: ModuleContext) -> NeonResult<()> {
    // Scanner functions
    cx.export_function("createScanner", create_scanner)?;
    cx.export_function("addPort", add_port)?;
    cx.export_function("addPorts", add_ports)?;
    cx.export_function("scan", scan)?;
    cx.export_function("getResults", get_results)?;
    
    // Utility functions
    cx.export_function("quickScan", quick_scan)?;
    cx.export_function("discoverHosts", discover_hosts)?;
    cx.export_function("asyncScan", async_scan)?;
    cx.export_function("version", version)?;
    
    // Constants
    let default_ports = cx.empty_array();
    let ports = [22, 80, 443, 8080];
    for (i, &port) in ports.iter().enumerate() {
        let port_value = cx.number(port);
        default_ports.set(&mut cx, i as u32, port_value)?;
    }
    cx.export_value("DEFAULT_PORTS", default_ports)?;
    
    Ok(())
}

// Example usage documentation
fn print_usage_example() {
    println!("Node.js bindings example for cyNetMapper");
    println!("=======================================");
    
    println!("\nExample usage in Node.js:");
    println!("```javascript");
    println!("const cynetmapper = require('./index.node');");
    println!("");
    println!("// Quick scan");
    println!("const results = cynetmapper.quickScan('127.0.0.1', [22, 80, 443]);");
    println!("console.log(results);");
    println!("");
    println!("// Host discovery");
    println!("const hosts = cynetmapper.discoverHosts('192.168.1.0/24');");
    println!("console.log('Discovered hosts:', hosts);");
    println!("");
    println!("// Advanced scanning");
    println!("const scanner = cynetmapper.createScanner('192.168.1.1');");
    println!("cynetmapper.addPorts(scanner, [22, 80, 443, 8080]);");
    println!("cynetmapper.scan(scanner);");
    println!("const scanResults = cynetmapper.getResults(scanner);");
    println!("console.log('Scan results:', scanResults);");
    println!("");
    println!("// Async scanning");
    println!("cynetmapper.asyncScan('192.168.1.1', [22, 80, 443])");
    println!("  .then(results => console.log('Async results:', results))");
    println!("  .catch(err => console.error('Scan error:', err));");
    println!("```");
    
    println!("\n✓ Node.js bindings example completed");
}

// This would be called in a separate example runner
#[cfg(not(feature = "node"))]
fn main() {
    print_usage_example();
}
//! Build script for the cyNetMapper GUI Tauri application
//!
//! This script handles the build-time configuration and setup
//! for the Tauri desktop application.

fn main() {
    // Run Tauri build script
    tauri_build::build();
    
    // Print build information
    println!("cargo:rerun-if-changed=tauri.conf.json");
    println!("cargo:rerun-if-changed=icons/");
    println!("cargo:rerun-if-changed=../dist/");
    
    // Set build timestamp
    println!(
        "cargo:rustc-env=BUILD_TIMESTAMP={}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    );
    
    // Set git commit hash if available
    if let Ok(output) = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if output.status.success() {
            let git_hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
            println!("cargo:rustc-env=GIT_HASH={}", git_hash);
        }
    }
    
    // Set version information
    println!("cargo:rustc-env=CARGO_PKG_VERSION={}", env!("CARGO_PKG_VERSION"));
}
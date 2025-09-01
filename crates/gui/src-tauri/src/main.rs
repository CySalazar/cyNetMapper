//! Main entry point for the cyNetMapper GUI application
//!
//! This is the Tauri application that provides the desktop interface
//! for cyNetMapper network scanning and analysis.

#![cfg_attr(
    all(not(debug_assertions), target_os = "windows"),
    windows_subsystem = "windows"
)]

use std::sync::Arc;

use log::{error, info, warn};
use tauri::Manager;

use cynetmapper_gui::{
    commands::*,
    config::ConfigManager,
    state::GlobalState,
    events::EventEmitter,
    AppState,
    GuiResult,
    GuiError,
};

/// Application state that will be managed by Tauri
struct TauriAppState {
    global_state: Arc<GlobalState>,
    config_manager: Arc<ConfigManager>,
}

/// Initialize application state
fn init_app_state() -> GuiResult<TauriAppState> {
    info!("Initializing application state...");
    
    // Initialize configuration manager
    let config_manager = match ConfigManager::new() {
        Ok(manager) => Arc::new(manager),
        Err(e) => {
            warn!("Failed to initialize config manager: {}", e);
            return Err(GuiError::ConfigError(format!("Config initialization failed: {}", e)));
        }
    };
    info!("Configuration manager initialized");

    // Initialize global state
    let global_state = Arc::new(GlobalState::new());

    Ok(TauriAppState {
        global_state,
        config_manager: config_manager.clone(),
    })
}



/// Setup application logging
fn setup_logging() -> GuiResult<()> {
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();
    
    info!("Logging initialized");
    Ok(())
}

/// Main application entry point
fn main() {
    // Setup logging
    if let Err(e) = setup_logging() {
        eprintln!("Failed to setup logging: {}", e);
        std::process::exit(1);
    }

    // Initialize application state
    let tauri_app_state = match init_app_state() {
        Ok(state) => state,
        Err(e) => {
            error!("Failed to initialize application state: {}", e);
            std::process::exit(1);
        }
    };

    info!("Starting cyNetMapper GUI application");

    // Build and run the Tauri application
    tauri::Builder::default()
        .manage(tauri_app_state.global_state)
        .manage(tauri_app_state.config_manager)
        // .plugin(tauri_plugin_store::Builder::default().build())
        // .plugin(tauri_plugin_window_state::Builder::default().build())
        // .plugin(tauri_plugin_shell::init())
        // .plugin(tauri_plugin_dialog::init())
        // .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            // Scan management commands
            start_scan,
            stop_scan,
            pause_scan,
            resume_scan,
            get_scan_progress,
            get_active_scans,
            get_scan_results,
            export_results,
            
            // Configuration commands
            get_config,
            update_config,
            
            // Chart and visualization commands
            get_chart_data,
            get_network_topology,
            
            // System information commands
            get_system_info,
            validate_scan_config,
        ])
        .setup(|app| {
            // Initialize event emitter with actual window
            let window = app.get_window("main").expect("Failed to get main window");
            let event_emitter = Arc::new(EventEmitter::new(window));
            app.manage(event_emitter);
            
            // Initialize and manage AppState for commands
            let app_state = AppState::new();
            app.manage(app_state);
            
            info!("Application setup completed");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("Error while running Tauri application");
}
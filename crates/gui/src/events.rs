//! Event handling for the cyNetMapper GUI
//!
//! This module manages real-time events and notifications between the backend and frontend.
//! It handles scan progress updates, system notifications, and other real-time communications.

use serde::{Deserialize, Serialize};
use tauri::{Manager, Window};
use tokio::sync::broadcast;
use std::time::Duration;

use crate::{ScanProgress, ScanStatus, GuiError, GuiResult};

/// Event types that can be emitted to the frontend
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum GuiEvent {
    /// Scan progress update
    ScanProgress(ScanProgress),
    /// Scan completed
    ScanCompleted {
        scan_id: String,
        success: bool,
        message: Option<String>,
    },
    /// New host discovered
    HostDiscovered {
        scan_id: String,
        host_address: String,
        hostname: Option<String>,
    },
    /// New open port found
    PortDiscovered {
        scan_id: String,
        host_address: String,
        port: u16,
        service: Option<String>,
    },
    /// Error occurred
    Error {
        scan_id: Option<String>,
        error: String,
        severity: ErrorSeverity,
    },
    /// System notification
    Notification {
        title: String,
        message: String,
        notification_type: NotificationType,
    },
    /// Configuration changed
    ConfigChanged,
    /// Application status update
    StatusUpdate {
        status: String,
        details: Option<String>,
    },
}

/// Error severity levels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

/// Notification types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    Info,
    Success,
    Warning,
    Error,
}

/// Event emitter for sending events to the frontend
#[derive(Debug, Clone)]
pub struct EventEmitter {
    window: Window,
}

impl EventEmitter {
    /// Create a new event emitter
    pub fn new(window: Window) -> Self {
        Self { window }
    }

    /// Emit a GUI event to the frontend
    pub fn emit(&self, event: GuiEvent) -> GuiResult<()> {
        self.window
            .emit("gui-event", &event)
            .map_err(|e| GuiError::ScanError(format!("Failed to emit event: {}", e)))
    }

    /// Emit scan progress update
    pub fn emit_scan_progress(&self, progress: ScanProgress) -> GuiResult<()> {
        self.emit(GuiEvent::ScanProgress(progress))
    }

    /// Emit scan completion
    pub fn emit_scan_completed(
        &self,
        scan_id: String,
        success: bool,
        message: Option<String>,
    ) -> GuiResult<()> {
        self.emit(GuiEvent::ScanCompleted {
            scan_id,
            success,
            message,
        })
    }

    /// Emit host discovery
    pub fn emit_host_discovered(
        &self,
        scan_id: String,
        host_address: String,
        hostname: Option<String>,
    ) -> GuiResult<()> {
        self.emit(GuiEvent::HostDiscovered {
            scan_id,
            host_address,
            hostname,
        })
    }

    /// Emit port discovery
    pub fn emit_port_discovered(
        &self,
        scan_id: String,
        host_address: String,
        port: u16,
        service: Option<String>,
    ) -> GuiResult<()> {
        self.emit(GuiEvent::PortDiscovered {
            scan_id,
            host_address,
            port,
            service,
        })
    }

    /// Emit error
    pub fn emit_error(
        &self,
        scan_id: Option<String>,
        error: String,
        severity: ErrorSeverity,
    ) -> GuiResult<()> {
        self.emit(GuiEvent::Error {
            scan_id,
            error,
            severity,
        })
    }

    /// Emit notification
    pub fn emit_notification(
        &self,
        title: String,
        message: String,
        notification_type: NotificationType,
    ) -> GuiResult<()> {
        self.emit(GuiEvent::Notification {
            title,
            message,
            notification_type,
        })
    }

    /// Emit status update
    pub fn emit_status_update(
        &self,
        status: String,
        details: Option<String>,
    ) -> GuiResult<()> {
        self.emit(GuiEvent::StatusUpdate { status, details })
    }
}

/// Progress tracker for managing scan progress updates
#[derive(Debug)]
pub struct ProgressTracker {
    emitter: EventEmitter,
    scan_id: String,
    start_time: std::time::Instant,
    last_update: std::time::Instant,
    update_interval: Duration,
}

impl ProgressTracker {
    /// Create a new progress tracker
    pub fn new(
        emitter: EventEmitter,
        scan_id: String,
        update_interval: Duration,
    ) -> Self {
        let now = std::time::Instant::now();
        Self {
            emitter,
            scan_id,
            start_time: now,
            last_update: now,
            update_interval,
        }
    }

    /// Update progress if enough time has passed
    pub fn update_progress(&mut self, progress: ScanProgress) -> GuiResult<()> {
        let now = std::time::Instant::now();
        if now.duration_since(self.last_update) >= self.update_interval {
            self.emitter.emit_scan_progress(progress)?;
            self.last_update = now;
        }
        Ok(())
    }

    /// Force update progress regardless of interval
    pub fn force_update_progress(&mut self, progress: ScanProgress) -> GuiResult<()> {
        self.emitter.emit_scan_progress(progress)?;
        self.last_update = std::time::Instant::now();
        Ok(())
    }

    /// Get elapsed time since start
    pub fn elapsed_time(&self) -> Duration {
        std::time::Instant::now().duration_since(self.start_time)
    }
}

/// Event listener for handling events from the core scanning engine
#[derive(Debug)]
pub struct EventListener {
    receiver: broadcast::Receiver<GuiEvent>,
    emitter: EventEmitter,
}

impl EventListener {
    /// Create a new event listener
    pub fn new(
        receiver: broadcast::Receiver<GuiEvent>,
        emitter: EventEmitter,
    ) -> Self {
        Self { receiver, emitter }
    }

    /// Start listening for events and forwarding them to the frontend
    pub async fn start_listening(&mut self) -> GuiResult<()> {
        loop {
            match self.receiver.recv().await {
                Ok(event) => {
                    if let Err(e) = self.emitter.emit(event) {
                        eprintln!("Failed to emit event: {}", e);
                    }
                }
                Err(broadcast::error::RecvError::Closed) => {
                    break;
                }
                Err(broadcast::error::RecvError::Lagged(skipped)) => {
                    eprintln!("Event listener lagged, skipped {} events", skipped);
                    continue;
                }
            }
        }
        Ok(())
    }
}

/// System notification manager
#[derive(Debug)]
pub struct NotificationManager {
    emitter: EventEmitter,
    enabled: bool,
}

impl NotificationManager {
    /// Create a new notification manager
    pub fn new(emitter: EventEmitter, enabled: bool) -> Self {
        Self { emitter, enabled }
    }

    /// Send an info notification
    pub fn info(&self, title: &str, message: &str) -> GuiResult<()> {
        if self.enabled {
            self.emitter.emit_notification(
                title.to_string(),
                message.to_string(),
                NotificationType::Info,
            )
        } else {
            Ok(())
        }
    }

    /// Send a success notification
    pub fn success(&self, title: &str, message: &str) -> GuiResult<()> {
        if self.enabled {
            self.emitter.emit_notification(
                title.to_string(),
                message.to_string(),
                NotificationType::Success,
            )
        } else {
            Ok(())
        }
    }

    /// Send a warning notification
    pub fn warning(&self, title: &str, message: &str) -> GuiResult<()> {
        if self.enabled {
            self.emitter.emit_notification(
                title.to_string(),
                message.to_string(),
                NotificationType::Warning,
            )
        } else {
            Ok(())
        }
    }

    /// Send an error notification
    pub fn error(&self, title: &str, message: &str) -> GuiResult<()> {
        if self.enabled {
            self.emitter.emit_notification(
                title.to_string(),
                message.to_string(),
                NotificationType::Error,
            )
        } else {
            Ok(())
        }
    }

    /// Enable or disable notifications
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

/// Real-time statistics tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RealtimeStats {
    pub scan_id: String,
    pub hosts_discovered: usize,
    pub ports_scanned: usize,
    pub open_ports: usize,
    pub closed_ports: usize,
    pub filtered_ports: usize,
    pub scan_rate: f64, // ports per second
    pub elapsed_time: Duration,
    pub estimated_remaining: Option<Duration>,
}

impl RealtimeStats {
    /// Create new realtime stats
    pub fn new(scan_id: String) -> Self {
        Self {
            scan_id,
            hosts_discovered: 0,
            ports_scanned: 0,
            open_ports: 0,
            closed_ports: 0,
            filtered_ports: 0,
            scan_rate: 0.0,
            elapsed_time: Duration::from_secs(0),
            estimated_remaining: None,
        }
    }

    /// Update statistics
    pub fn update(
        &mut self,
        hosts_discovered: usize,
        ports_scanned: usize,
        open_ports: usize,
        closed_ports: usize,
        filtered_ports: usize,
        elapsed_time: Duration,
    ) {
        self.hosts_discovered = hosts_discovered;
        self.ports_scanned = ports_scanned;
        self.open_ports = open_ports;
        self.closed_ports = closed_ports;
        self.filtered_ports = filtered_ports;
        self.elapsed_time = elapsed_time;
        
        // Calculate scan rate
        if elapsed_time.as_secs() > 0 {
            self.scan_rate = ports_scanned as f64 / elapsed_time.as_secs_f64();
        }
    }

    /// Estimate remaining time
    pub fn estimate_remaining(&mut self, total_ports: usize) {
        if self.scan_rate > 0.0 && self.ports_scanned < total_ports {
            let remaining_ports = total_ports - self.ports_scanned;
            let remaining_seconds = remaining_ports as f64 / self.scan_rate;
            self.estimated_remaining = Some(Duration::from_secs_f64(remaining_seconds));
        } else {
            self.estimated_remaining = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_realtime_stats_creation() {
        let stats = RealtimeStats::new("test-scan".to_string());
        assert_eq!(stats.scan_id, "test-scan");
        assert_eq!(stats.hosts_discovered, 0);
        assert_eq!(stats.scan_rate, 0.0);
    }

    #[test]
    fn test_realtime_stats_update() {
        let mut stats = RealtimeStats::new("test-scan".to_string());
        stats.update(5, 100, 10, 80, 10, Duration::from_secs(10));
        
        assert_eq!(stats.hosts_discovered, 5);
        assert_eq!(stats.ports_scanned, 100);
        assert_eq!(stats.open_ports, 10);
        assert_eq!(stats.scan_rate, 10.0); // 100 ports / 10 seconds
    }

    #[test]
    fn test_estimate_remaining() {
        let mut stats = RealtimeStats::new("test-scan".to_string());
        stats.update(5, 100, 10, 80, 10, Duration::from_secs(10));
        stats.estimate_remaining(200);
        
        assert!(stats.estimated_remaining.is_some());
        // Should estimate 10 seconds remaining (100 remaining ports / 10 ports per second)
        assert_eq!(stats.estimated_remaining.unwrap().as_secs(), 10);
    }
}
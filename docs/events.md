# Event System Documentation

## Overview

cyNetMapper implements a comprehensive real-time event system that enables live monitoring and updates during network scanning operations. This system provides structured, timestamped events that can be consumed by both the GUI and external integrations.

## Event Architecture

### Core Components

1. **Event Emitter** (`crates/core/src/events.rs`)
   - Central event dispatching system
   - Thread-safe event broadcasting
   - Structured logging integration

2. **GUI Event Handler** (`crates/gui/src/events.rs`)
   - Tauri event bridge
   - Frontend state synchronization
   - Real-time UI updates

3. **Event Types** (`crates/core/src/types.rs`)
   - Strongly-typed event definitions
   - Serializable event payloads
   - Comprehensive event metadata

## Event Types

### ScanStarted

Emitted when a new scan operation begins.

```rust
ScanStarted {
    scan_id: Uuid,
    targets: Vec<Target>,
    ports: PortRange,
    timestamp: DateTime<Utc>,
    options: ScanOptions,
}
```

**Usage:**
- Initialize progress tracking
- Reset scan state in GUI
- Log scan initiation

### HostDiscovered

Fired when a responsive host is discovered during scanning.

```rust
HostDiscovered {
    scan_id: Uuid,
    host: IpAddr,
    timestamp: DateTime<Utc>,
    response_time: Duration,
    ttl: Option<u8>,
}
```

**Usage:**
- Update host count in real-time
- Display discovered hosts immediately
- Track scan progress

### PortDiscovered

Triggered when an open port is found on a target host.

```rust
PortDiscovered {
    scan_id: Uuid,
    host: IpAddr,
    port: u16,
    protocol: Protocol,
    state: PortState,
    service: Option<ServiceInfo>,
    timestamp: DateTime<Utc>,
}
```

**Usage:**
- Real-time port status updates
- Service detection results
- Security assessment data

### ScanProgress

Regular progress updates with scanning metrics.

```rust
ScanProgress {
    scan_id: Uuid,
    hosts_scanned: usize,
    total_hosts: usize,
    ports_scanned: usize,
    total_ports: usize,
    elapsed_time: Duration,
    estimated_remaining: Option<Duration>,
    timestamp: DateTime<Utc>,
}
```

**Usage:**
- Progress bar updates
- ETA calculations
- Performance monitoring

### ScanCompleted

Final notification when scan operation finishes.

```rust
ScanCompleted {
    scan_id: Uuid,
    results: ScanResults,
    duration: Duration,
    timestamp: DateTime<Utc>,
    success: bool,
    error: Option<String>,
}
```

**Usage:**
- Finalize scan results
- Update scan history
- Generate reports

### Error

Error events with detailed diagnostic information.

```rust
Error {
    scan_id: Option<Uuid>,
    error_type: ErrorType,
    message: String,
    context: HashMap<String, String>,
    timestamp: DateTime<Utc>,
}
```

**Usage:**
- Error handling and recovery
- User notifications
- Debugging and diagnostics

## Event Flow

### Typical Scan Sequence

```
1. ScanStarted
   ├── Target validation
   └── Resource allocation

2. Host Discovery Phase
   ├── HostDiscovered (for each responsive host)
   └── ScanProgress (periodic updates)

3. Port Scanning Phase
   ├── PortDiscovered (for each open port)
   ├── ScanProgress (periodic updates)
   └── Service detection

4. Completion
   └── ScanCompleted (final results)
```

### Error Handling

```
Any Phase
├── Error (non-fatal)
│   └── Continue scanning
└── Error (fatal)
    └── ScanCompleted (with error)
```

## Implementation Guide

### Backend Event Emission

```rust
use cynetmapper_core::events::{EventEmitter, GuiEvent};

// Create event emitter
let emitter = EventEmitter::new();

// Emit events during scanning
emitter.emit(GuiEvent::ScanStarted {
    scan_id,
    targets: targets.clone(),
    ports: ports.clone(),
    timestamp: Utc::now(),
    options: options.clone(),
}).await;

// Emit host discovery
emitter.emit(GuiEvent::HostDiscovered {
    scan_id,
    host: discovered_host,
    timestamp: Utc::now(),
    response_time,
    ttl: Some(64),
}).await;
```

### GUI Event Handling

```typescript
// React component with event subscription
import { listen } from '@tauri-apps/api/event';
import { useScanStore } from '../store/scanStore';

const ScanDashboard = () => {
  const { updateScanProgress, addDiscoveredHost } = useScanStore();

  useEffect(() => {
    // Listen for scan progress events
    const unlistenProgress = listen('scan_progress', (event) => {
      updateScanProgress(event.payload);
    });

    // Listen for host discovery events
    const unlistenHost = listen('host_discovered', (event) => {
      addDiscoveredHost(event.payload);
    });

    return () => {
      unlistenProgress.then(f => f());
      unlistenHost.then(f => f());
    };
  }, []);

  return (
    <div>
      {/* Real-time scan dashboard */}
    </div>
  );
};
```

### Zustand Store Integration

```typescript
// Store with event handling
import { create } from 'zustand';

interface ScanState {
  scanResults: ScanResults[];
  isScanning: boolean;
  progress: ScanProgress | null;
  discoveredHosts: HostInfo[];
  
  // Event handlers
  handleScanStarted: (event: ScanStartedEvent) => void;
  handleHostDiscovered: (event: HostDiscoveredEvent) => void;
  handleScanProgress: (event: ScanProgressEvent) => void;
  handleScanCompleted: (event: ScanCompletedEvent) => void;
}

export const useScanStore = create<ScanState>((set, get) => ({
  scanResults: [],
  isScanning: false,
  progress: null,
  discoveredHosts: [],

  handleScanStarted: (event) => set({
    isScanning: true,
    progress: null,
    discoveredHosts: [],
  }),

  handleHostDiscovered: (event) => set((state) => ({
    discoveredHosts: [...state.discoveredHosts, {
      ip: event.host,
      responseTime: event.response_time,
      timestamp: event.timestamp,
    }],
  })),

  handleScanProgress: (event) => set({
    progress: event,
  }),

  handleScanCompleted: (event) => set({
    isScanning: false,
    scanResults: [...get().scanResults, event.results],
  }),
}));
```

## Debugging Events

### Structured Logging

All events are logged with structured data:

```rust
use tracing::{info, warn, error};

// Event emission with logging
info!(
    scan_id = %scan_id,
    event_type = "host_discovered",
    host = %host,
    response_time_ms = response_time.as_millis(),
    "Host discovered during scan"
);
```

### Log Analysis

```bash
# Filter events by scan ID
grep "scan_id=550e8400" logs/cynetmapper.log

# Monitor real-time events
tail -f logs/cynetmapper.log | grep "event_type"

# Event timing analysis
grep "event_type=scan_progress" logs/cynetmapper.log | \
  jq '.timestamp, .hosts_scanned, .total_hosts'
```

## Performance Considerations

### Event Throttling

- Progress events are throttled to prevent UI flooding
- Batch similar events when possible
- Use debouncing for rapid successive events

### Memory Management

- Events are not persisted by default
- Implement event cleanup for long-running scans
- Consider event archival for audit trails

### Network Efficiency

- Events use efficient serialization (bincode/JSON)
- Minimize event payload size
- Compress large event data when necessary

## Testing Events

### Integration Tests

The project includes comprehensive event testing:

```bash
# Run event-specific tests
cargo test test_event_emission
cargo test test_gui_event_handling
cargo test test_event_ordering

# Test event performance
cargo test test_concurrent_event_emission --release
```

### Manual Testing

```bash
# Enable debug logging
RUST_LOG=debug cargo run --bin cynetmapper-gui

# Monitor events in real-time
RUST_LOG=cynetmapper_core::events=trace cargo run
```

## Best Practices

1. **Event Design**
   - Keep events immutable and serializable
   - Include sufficient context for debugging
   - Use consistent naming conventions

2. **Error Handling**
   - Always handle event emission failures gracefully
   - Provide fallback mechanisms for critical events
   - Log event processing errors

3. **Performance**
   - Avoid blocking operations in event handlers
   - Use async event processing where possible
   - Monitor event queue sizes

4. **Testing**
   - Test event emission in isolation
   - Verify event ordering and timing
   - Test error scenarios and recovery

## Troubleshooting

### Common Issues

1. **Events Not Received**
   - Check event listener registration
   - Verify event name matching
   - Confirm Tauri event bridge setup

2. **Performance Issues**
   - Monitor event emission frequency
   - Check for event handler bottlenecks
   - Verify memory usage patterns

3. **Event Ordering**
   - Ensure proper async/await usage
   - Check for race conditions
   - Verify event queue processing

### Diagnostic Commands

```bash
# Check event system health
cargo test test_event_system_health

# Benchmark event performance
cargo bench event_emission

# Analyze event logs
grep -E "(event_type|scan_id)" logs/*.log | \
  sort -k3 | head -100
```

## Future Enhancements

- Event persistence and replay
- Event filtering and subscription management
- Webhook integration for external systems
- Event analytics and metrics
- Custom event types for plugins
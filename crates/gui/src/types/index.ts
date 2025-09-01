// Main type definitions for the cyNetMapper GUI

export * from './events';

// Scan configuration types
export interface ScanConfig {
  targets: string[];
  scan_type: ScanType;
  ports?: string;
  timing: TimingTemplate;
  discovery_method: DiscoveryMethod;
  max_concurrent: number;
  timeout_ms: number;
  enable_service_detection: boolean;
  enable_os_detection: boolean;
  enable_version_detection: boolean;
  output_format: OutputFormat[];
}

export type ScanType = 'TcpConnect' | 'TcpSyn' | 'UdpScan' | 'Stealth' | 'Aggressive';

export type TimingTemplate = 'Paranoid' | 'Sneaky' | 'Polite' | 'Normal' | 'Aggressive' | 'Insane';

export type DiscoveryMethod = 'Ping' | 'TcpSyn' | 'TcpAck' | 'UdpPing' | 'ArpPing' | 'None';

export type OutputFormat = 'Json' | 'Xml' | 'Csv' | 'Text';

// Scan results types
export interface ScanResults {
  scan_id: string;
  config: ScanConfig;
  start_time: string;
  end_time?: string;
  status: ScanStatus;
  hosts: HostInfo[];
  statistics: ScanStatistics;
}

export type ScanStatus = 'Running' | 'Completed' | 'Paused' | 'Stopped' | 'Error';

export interface HostInfo {
  ip: string;
  hostname?: string;
  status: HostStatus;
  response_time?: number;
  ports: PortInfo[];
  os_fingerprint?: OsFingerprint;
  last_seen: string;
}

export type HostStatus = 'Up' | 'Down' | 'Unknown';

export interface PortInfo {
  port: number;
  protocol: string;
  state: PortState;
  service?: ServiceInfo;
  banner?: string;
  response_time?: number;
}

export type PortState = 'Open' | 'Closed' | 'Filtered' | 'Unfiltered' | 'OpenFiltered' | 'ClosedFiltered';

export interface ServiceInfo {
  name: string;
  version?: string;
  product?: string;
  extra_info?: string;
  confidence: number;
}

export interface OsFingerprint {
  os_family?: string;
  os_generation?: string;
  device_type?: string;
  confidence: number;
  details: string;
}

export interface ScanStatistics {
  total_hosts: number;
  hosts_up: number;
  hosts_down: number;
  total_ports: number;
  open_ports: number;
  closed_ports: number;
  filtered_ports: number;
  scan_duration: number;
  packets_sent: number;
  packets_received: number;
}

// Application state types
export interface AppConfig {
  theme: 'light' | 'dark' | 'system';
  auto_save: boolean;
  max_scan_history: number;
  default_scan_config: Partial<ScanConfig>;
  ui_preferences: UiPreferences;
  log_level?: string;
  auto_save_results?: boolean;
  default_export_format?: string;
}

export interface UiPreferences {
  sidebar_collapsed: boolean;
  show_advanced_options: boolean;
  chart_animations: boolean;
  real_time_updates: boolean;
  notification_level: 'all' | 'warnings' | 'errors' | 'none';
  soundEnabled?: boolean;
}

// Chart and visualization types
export interface ChartData {
  labels: string[];
  datasets: ChartDataset[];
}

export interface ChartDataset {
  label: string;
  data: number[];
  background_color: string;
  border_color: string;
}

// Network topology types
export interface NetworkTopology {
  nodes: NetworkNode[];
  edges: NetworkEdge[];
}

export interface NetworkNode {
  id: string;
  label: string;
  ip: string;
  status: HostStatus;
  properties: Record<string, any>;
}

export interface NetworkEdge {
  from: string;
  to: string;
  label?: string;
  properties: Record<string, any>;
}

// UI component types
export interface TableColumn<T> {
  key: keyof T;
  label: string;
  sortable?: boolean;
  width?: string;
  render?: (value: any, row: T) => any;
}

export interface FilterOption {
  label: string;
  value: string;
  count?: number;
}

// Error types
export interface AppError {
  code: string;
  message: string;
  details?: string;
  timestamp: string;
}
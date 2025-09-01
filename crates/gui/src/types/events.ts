// Event types for real-time communication between backend and frontend

export interface GuiEvent {
  id: string;
  timestamp: string;
  event_type: GuiEventType;
  data: any;
}

export type GuiEventType =
  | 'ScanStarted'
  | 'ScanProgress'
  | 'ScanCompleted'
  | 'ScanPaused'
  | 'ScanResumed'
  | 'ScanStopped'
  | 'HostDiscovered'
  | 'PortDiscovered'
  | 'ServiceDetected'
  | 'OsDetected'
  | 'Error'
  | 'Warning'
  | 'Info';

export interface ScanProgressEvent {
  scan_id: string;
  progress: number;
  current_target?: string;
  hosts_discovered: number;
  ports_scanned: number;
  services_detected: number;
  estimated_remaining?: number;
}

export interface HostDiscoveredEvent {
  scan_id: string;
  host: string;
  response_time?: number;
  method: string;
}

export interface PortDiscoveredEvent {
  scan_id: string;
  host: string;
  port: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
}

export interface ErrorEvent {
  scan_id?: string;
  error: string;
  details?: string;
}

export interface NotificationEvent {
  title: string;
  message: string;
  level: 'info' | 'warning' | 'error' | 'success';
}
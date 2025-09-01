import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import toast from 'react-hot-toast';
import {
  AppConfig,
  ScanConfig,
  ScanResults,
  AppError,
  GuiEvent,
} from '../types';

interface AppState {
  // Configuration
  config: AppConfig;
  
  // Current scan state
  currentScan: ScanResults | null;
  scanConfig: ScanConfig;
  scanProgress: number;
  scanStatus: 'idle' | 'running' | 'paused' | 'completed' | 'error';
  
  // Scan history
  scanHistory: ScanResults[];
  
  // Events and errors
  events: GuiEvent[];
  errors: AppError[];
  notifications: any[];
  
  // UI state
  ui: {
    activeView: string;
    sidebarCollapsed: boolean;
    showAdvancedOptions: boolean;
    selectedHost: string | null;
    selectedScan: string | null;
    theme: string;
    autoRefreshInterval: number;
    showNotifications: boolean;
    soundEnabled: boolean;
  };
  
  // Actions
  setConfig: (config: AppConfig) => void;
  updateConfig: (updates: Partial<AppConfig>) => void;
  setScanConfig: (config: ScanConfig) => void;
  startScan: (config?: ScanConfig) => void;
  stopScan: () => void;
  pauseScan: () => void;
  resumeScan: () => void;
  addEvent: (event: GuiEvent) => void;
  updateScanProgress: (progress: number) => void;
  addScanResult: (results: ScanResults) => void;
  updateScanResult: (results: ScanResults) => void;
  addError: (error: AppError) => void;
  clearErrors: () => void;
  setActiveView: (view: string) => void;
  toggleSidebar: () => void;
  setSelectedHost: (host: string | null) => void;
  setSelectedScan: (scanId: string | null) => void;
  toggleAdvancedOptions: () => void;
  updateUi: (updates: Partial<AppState['ui']>) => void;
  addNotification: (notification: any) => void;
  clearNotifications: () => void;
  clearScanHistory: () => void;
  setCurrentScan: (scan: ScanResults | null) => void;
  exportData: () => any;
  
  // Helper getters
  getCurrentScanResults: () => ScanResults | null;
  getIsScanning: () => boolean;
}

const defaultConfig: AppConfig = {
  theme: 'system',
  auto_save: true,
  max_scan_history: 100,
  default_scan_config: {
    scan_type: 'TcpConnect',
    timing: 'Normal',
    discovery_method: 'Ping',
    max_concurrent: 100,
    timeout_ms: 5000,
    enable_service_detection: true,
    enable_os_detection: false,
    enable_version_detection: false,
    output_format: ['Json'],
  },
  ui_preferences: {
    sidebar_collapsed: false,
    show_advanced_options: false,
    chart_animations: true,
    real_time_updates: true,
    notification_level: 'warnings',
    soundEnabled: false,
  },
  log_level: 'info',
  auto_save_results: true,
  default_export_format: 'json',
};

const defaultScanConfig: ScanConfig = {
  targets: [],
  scan_type: 'TcpConnect',
  timing: 'Normal',
  discovery_method: 'Ping',
  max_concurrent: 100,
  timeout_ms: 5000,
  enable_service_detection: true,
  enable_os_detection: false,
  enable_version_detection: false,
  output_format: ['Json'],
};

export const useAppStore = create<AppState>()(persist(
  (set, get) => ({
    // Initial state
    config: defaultConfig,
    currentScan: null,
    scanConfig: defaultScanConfig,
    scanProgress: 0,
    scanStatus: 'idle',
    scanHistory: [],
    events: [],
    errors: [],
    notifications: [],
    ui: {
      activeView: 'dashboard',
      sidebarCollapsed: false,
      showAdvancedOptions: false,
      selectedHost: null,
      selectedScan: null,
      theme: 'system',
      autoRefreshInterval: 5000,
      showNotifications: true,
      soundEnabled: false,
    },
    
    // Helper getters
    getCurrentScanResults: () => {
      const state = get();
      return state.scanHistory.length > 0 ? state.scanHistory[state.scanHistory.length - 1] : null;
    },
    
    getIsScanning: () => {
      const state = get();
      return state.scanStatus === 'running';
    },
    
    // Actions
    setConfig: (config: AppConfig) => set({ config }),
    
    updateConfig: (updates: Partial<AppConfig>) => set((state) => ({
      config: { ...state.config, ...updates }
    })),
    
    setScanConfig: (config: ScanConfig) => set({ scanConfig: config }),
    
    startScan: (config?: ScanConfig) => {
      if (config) {
        set({ scanConfig: config, scanStatus: 'running' });
      }
      toast.success('Scan started');
      // The actual Tauri command invocation is handled in the component
    },
    
    stopScan: () => {
      set({ currentScan: null });
      toast('Scan stopped');
    },
    
    pauseScan: () => {
      set({ scanStatus: 'paused' });
      toast('Scan paused');
    },
    
    resumeScan: () => {
      set({ scanStatus: 'running' });
      toast('Scan resumed');
    },
    
    addEvent: (event: GuiEvent) => {
    set((state) => ({ events: [...state.events, event] }));
    
    // Handle specific event types
    const state = get();
    if (event.event_type === 'HostDiscovered' && event.data) {
      // Update current scan with discovered host
      if (state.currentScan) {
        const updatedScan = {
          ...state.currentScan,
          hosts: [...(state.currentScan.hosts || []), event.data]
        };
        set({ currentScan: updatedScan });
      }
    } else if (event.event_type === 'ScanCompleted' && event.data) {
      // Mark scan as completed and update final results
      set({ 
        scanStatus: 'completed',
        currentScan: event.data.results || state.currentScan
      });
    } else if (event.event_type === 'Error') {
      // Add error to error list
      const error: AppError = {
        code: event.data?.code || 'SCAN_ERROR',
        message: event.data?.error || event.data?.message || 'Unknown error',
        details: event.data?.details,
        timestamp: new Date().toISOString()
      };
      set((state) => ({
        errors: [...state.errors, error]
      }));
    }
  },
    
    updateScanProgress: (progress: number) => {
      set({ scanProgress: progress });
    },
    
    addScanResult: (results: ScanResults) => set((state) => ({
      scanHistory: [...state.scanHistory, results],
      currentScan: results
    })),
    
    updateScanResult: (results: ScanResults) => set((state) => ({
      currentScan: results,
      scanHistory: state.scanHistory.map(scan => 
        scan.scan_id === results.scan_id ? results : scan
      )
    })),
    
    addError: (error: AppError) => set((state) => ({
      errors: [...state.errors, error]
    })),
    
    clearErrors: () => set({ errors: [] }),
    
    addNotification: (notification: any) => set((state) => ({
      notifications: [...state.notifications, notification]
    })),
    
    clearNotifications: () => set({ notifications: [] }),
    
    setActiveView: (view: string) => set((state) => ({
      ui: { ...state.ui, activeView: view }
    })),
    
    toggleSidebar: () => set((state) => ({
      ui: { ...state.ui, sidebarCollapsed: !state.ui.sidebarCollapsed }
    })),
    
    setSelectedHost: (host: string | null) => set((state) => ({
      ui: { ...state.ui, selectedHost: host }
    })),
    
    setSelectedScan: (scanId: string | null) => set((state) => ({
      ui: { ...state.ui, selectedScan: scanId }
    })),
    
    toggleAdvancedOptions: () => set((state) => ({
      ui: { ...state.ui, showAdvancedOptions: !state.ui.showAdvancedOptions }
    })),
    
    updateUi: (updates: Partial<AppState['ui']>) => set((state) => ({
      ui: { ...state.ui, ...updates }
    })),

    clearScanHistory: () => set({ scanHistory: [] }),

    setCurrentScan: (scan: ScanResults | null) => set({ currentScan: scan }),

    exportData: () => {
      const state = get();
      return {
        config: state.config,
        scanHistory: state.scanHistory,
        ui: {
          sidebarCollapsed: state.ui.sidebarCollapsed,
          showAdvancedOptions: state.ui.showAdvancedOptions,
        }
      };
    },
  }),
  {
    name: 'cynetmapper-storage',
    partialize: (state) => ({
      config: state.config,
      scanHistory: state.scanHistory,
      ui: {
        sidebarCollapsed: state.ui.sidebarCollapsed,
        showAdvancedOptions: state.ui.showAdvancedOptions,
      }
    }),
  }
));
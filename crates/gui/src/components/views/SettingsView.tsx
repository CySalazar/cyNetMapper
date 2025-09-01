import { useState } from 'react';
import { useAppStore } from '../../stores/appStore';
import {
  Cog6ToothIcon,
  DocumentArrowDownIcon,
  DocumentArrowUpIcon,
  TrashIcon,
  CheckIcon,
  XMarkIcon,
} from '@heroicons/react/24/outline';
import { AppConfig } from '../../types';

interface SettingsFormData {
  // Scan defaults
  default_scan_type: string;
  default_timing: string;
  default_discovery_method: string;
  default_max_concurrent: number;
  default_timeout_ms: number;
  default_enable_service_detection: boolean;
  default_enable_os_detection: boolean;
  default_enable_version_detection: boolean;
  
  // UI preferences
  theme: string;
  auto_refresh_interval: number;
  show_notifications: boolean;
  sound_enabled: boolean;
  
  // Advanced
  log_level: string;
  max_scan_history: number;
  auto_save_results: boolean;
  export_format: string;
}

export function SettingsView() {
  const { config, updateConfig, ui, updateUi } = useAppStore();
  
  const [formData, setFormData] = useState<SettingsFormData>({
    // Scan defaults
    default_scan_type: config?.default_scan_config?.scan_type || 'TcpConnect',
    default_timing: config?.default_scan_config?.timing || 'Normal',
    default_discovery_method: config?.default_scan_config?.discovery_method || 'Ping',
    default_max_concurrent: config?.default_scan_config?.max_concurrent || 100,
    default_timeout_ms: config?.default_scan_config?.timeout_ms || 3000,
    default_enable_service_detection: config?.default_scan_config?.enable_service_detection || true,
    default_enable_os_detection: config?.default_scan_config?.enable_os_detection || false,
    default_enable_version_detection: config?.default_scan_config?.enable_version_detection || true,
    
    // UI preferences
    theme: ui?.theme || 'system',
    auto_refresh_interval: ui?.autoRefreshInterval || 5000,
    show_notifications: ui?.showNotifications !== false,
    sound_enabled: ui?.soundEnabled !== false,
    
    // Advanced
    log_level: config?.log_level || 'info',
    max_scan_history: config?.max_scan_history || 100,
    auto_save_results: config?.auto_save_results !== false,
    export_format: config?.default_export_format || 'json',
  });
  
  const [activeTab, setActiveTab] = useState('general');
  const [hasChanges, setHasChanges] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  
  const handleInputChange = (field: keyof SettingsFormData, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setHasChanges(true);
  };
  
  const handleSave = async () => {
    setIsSaving(true);
    
    try {
      // Update app config
      const newConfig: Partial<AppConfig> = {
        default_scan_config: {
          targets: [],
          scan_type: formData.default_scan_type as any,
          timing: formData.default_timing as any,
          discovery_method: formData.default_discovery_method as any,
          max_concurrent: formData.default_max_concurrent,
          timeout_ms: formData.default_timeout_ms,
          enable_service_detection: formData.default_enable_service_detection,
          enable_os_detection: formData.default_enable_os_detection,
          enable_version_detection: formData.default_enable_version_detection,
          output_format: [formData.export_format as any],
        },
        log_level: formData.log_level as any,
        max_scan_history: formData.max_scan_history,
        auto_save_results: formData.auto_save_results,
        default_export_format: formData.export_format as any,
      };
      
      updateConfig(newConfig);
      
      // Update UI preferences
      updateUi({
        theme: formData.theme as any,
        autoRefreshInterval: formData.auto_refresh_interval,
        showNotifications: formData.show_notifications,
        soundEnabled: formData.sound_enabled,
      });
      
      setHasChanges(false);
      
      // Here we would save to Tauri store
      // await invoke('save_config', { config: newConfig });
      
    } catch (error) {
      console.error('Failed to save settings:', error);
    } finally {
      setIsSaving(false);
    }
  };
  
  const handleReset = () => {
    setFormData({
      default_scan_type: 'TcpConnect',
      default_timing: 'Normal',
      default_discovery_method: 'Ping',
      default_max_concurrent: 100,
      default_timeout_ms: 3000,
      default_enable_service_detection: true,
      default_enable_os_detection: false,
      default_enable_version_detection: true,
      theme: 'system',
      auto_refresh_interval: 5000,
      show_notifications: true,
      sound_enabled: true,
      log_level: 'info',
      max_scan_history: 100,
      auto_save_results: true,
      export_format: 'json',
    });
    setHasChanges(true);
  };
  
  const exportConfig = () => {
    const configData = {
      config,
      ui,
      exported_at: new Date().toISOString(),
    };
    
    const dataStr = JSON.stringify(configData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `cynetmapper-config-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };
  
  const importConfig = () => {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = (e: any) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (e: any) => {
          try {
            const importedData = JSON.parse(e.target.result);
            if (importedData.config) {
              updateConfig(importedData.config);
            }
            if (importedData.ui) {
              updateUi(importedData.ui);
            }
            // Refresh form data
            window.location.reload();
          } catch (error) {
            console.error('Failed to import config:', error);
            alert('Invalid configuration file');
          }
        };
        reader.readAsText(file);
      }
    };
    input.click();
  };
  
  const tabs = [
    { id: 'general', name: 'General', icon: Cog6ToothIcon },
    { id: 'scanning', name: 'Scanning Defaults', icon: Cog6ToothIcon },
    { id: 'advanced', name: 'Advanced', icon: Cog6ToothIcon },
  ];
  
  return (
    <div className="p-6 max-w-4xl mx-auto">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Settings
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              Configure application preferences and defaults
            </p>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={importConfig}
              className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              <DocumentArrowUpIcon className="h-4 w-4 mr-2" />
              Import
            </button>
            
            <button
              onClick={exportConfig}
              className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              <DocumentArrowDownIcon className="h-4 w-4 mr-2" />
              Export
            </button>
          </div>
        </div>
      </div>
      
      {/* Tabs */}
      <div className="border-b border-gray-200 dark:border-gray-700 mb-6">
        <nav className="-mb-px flex space-x-8">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center py-2 px-1 border-b-2 font-medium text-sm transition-colors ${
                  activeTab === tab.id
                    ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300 dark:text-gray-400 dark:hover:text-gray-300'
                }`}
              >
                <Icon className="h-4 w-4 mr-2" />
                {tab.name}
              </button>
            );
          })}
        </nav>
      </div>
      
      {/* Tab Content */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        {/* General Tab */}
        {activeTab === 'general' && (
          <div className="p-6 space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Appearance
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Theme
                  </label>
                  <select
                    value={formData.theme}
                    onChange={(e) => handleInputChange('theme', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="system">System</option>
                    <option value="light">Light</option>
                    <option value="dark">Dark</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Auto Refresh Interval (ms)
                  </label>
                  <input
                    type="number"
                    min="1000"
                    max="60000"
                    step="1000"
                    value={formData.auto_refresh_interval}
                    onChange={(e) => handleInputChange('auto_refresh_interval', parseInt(e.target.value) || 5000)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  />
                </div>
              </div>
            </div>
            
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Notifications
              </h3>
              
              <div className="space-y-4">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.show_notifications}
                    onChange={(e) => handleInputChange('show_notifications', e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Show desktop notifications
                  </span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.sound_enabled}
                    onChange={(e) => handleInputChange('sound_enabled', e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable notification sounds
                  </span>
                </label>
              </div>
            </div>
          </div>
        )}
        
        {/* Scanning Defaults Tab */}
        {activeTab === 'scanning' && (
          <div className="p-6 space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Default Scan Configuration
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Scan Type
                  </label>
                  <select
                    value={formData.default_scan_type}
                    onChange={(e) => handleInputChange('default_scan_type', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="TcpConnect">TCP Connect</option>
                    <option value="TcpSyn">TCP SYN</option>
                    <option value="UdpScan">UDP Scan</option>
                    <option value="TcpAck">TCP ACK</option>
                    <option value="TcpFin">TCP FIN</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Timing Template
                  </label>
                  <select
                    value={formData.default_timing}
                    onChange={(e) => handleInputChange('default_timing', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="Paranoid">Paranoid (T0)</option>
                    <option value="Sneaky">Sneaky (T1)</option>
                    <option value="Polite">Polite (T2)</option>
                    <option value="Normal">Normal (T3)</option>
                    <option value="Aggressive">Aggressive (T4)</option>
                    <option value="Insane">Insane (T5)</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Discovery Method
                  </label>
                  <select
                    value={formData.default_discovery_method}
                    onChange={(e) => handleInputChange('default_discovery_method', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="Ping">ICMP Ping</option>
                    <option value="TcpSyn">TCP SYN</option>
                    <option value="TcpAck">TCP ACK</option>
                    <option value="ArpScan">ARP Scan</option>
                    <option value="None">No Discovery</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Max Concurrent Connections
                  </label>
                  <input
                    type="number"
                    min="1"
                    max="1000"
                    value={formData.default_max_concurrent}
                    onChange={(e) => handleInputChange('default_max_concurrent', parseInt(e.target.value) || 100)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Timeout (ms)
                  </label>
                  <input
                    type="number"
                    min="100"
                    max="60000"
                    value={formData.default_timeout_ms}
                    onChange={(e) => handleInputChange('default_timeout_ms', parseInt(e.target.value) || 3000)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  />
                </div>
              </div>
            </div>
            
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Detection Options
              </h3>
              
              <div className="space-y-4">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.default_enable_service_detection}
                    onChange={(e) => handleInputChange('default_enable_service_detection', e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable service detection by default
                  </span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.default_enable_os_detection}
                    onChange={(e) => handleInputChange('default_enable_os_detection', e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable OS detection by default
                  </span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.default_enable_version_detection}
                    onChange={(e) => handleInputChange('default_enable_version_detection', e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable version detection by default
                  </span>
                </label>
              </div>
            </div>
          </div>
        )}
        
        {/* Advanced Tab */}
        {activeTab === 'advanced' && (
          <div className="p-6 space-y-6">
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Logging & Storage
              </h3>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Log Level
                  </label>
                  <select
                    value={formData.log_level}
                    onChange={(e) => handleInputChange('log_level', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="error">Error</option>
                    <option value="warn">Warning</option>
                    <option value="info">Info</option>
                    <option value="debug">Debug</option>
                    <option value="trace">Trace</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Max Scan History
                  </label>
                  <input
                    type="number"
                    min="10"
                    max="1000"
                    value={formData.max_scan_history}
                    onChange={(e) => handleInputChange('max_scan_history', parseInt(e.target.value) || 100)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Default Export Format
                  </label>
                  <select
                    value={formData.export_format}
                    onChange={(e) => handleInputChange('export_format', e.target.value)}
                    className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                  >
                    <option value="json">JSON</option>
                    <option value="xml">XML (Nmap)</option>
                    <option value="csv">CSV</option>
                    <option value="txt">Text</option>
                  </select>
                </div>
              </div>
            </div>
            
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Data Management
              </h3>
              
              <div className="space-y-4">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.auto_save_results}
                    onChange={(e) => handleInputChange('auto_save_results', e.target.checked)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Automatically save scan results
                  </span>
                </label>
              </div>
            </div>
            
            <div>
              <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
                Reset Options
              </h3>
              
              <div className="space-y-4">
                <button
                  onClick={handleReset}
                  className="inline-flex items-center px-4 py-2 border border-red-300 dark:border-red-600 text-sm font-medium rounded-md text-red-700 dark:text-red-300 bg-white dark:bg-gray-800 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                >
                  <TrashIcon className="h-4 w-4 mr-2" />
                  Reset to Defaults
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
      
      {/* Save Actions */}
      {hasChanges && (
        <div className="mt-6 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center">
              <div className="text-sm text-yellow-800 dark:text-yellow-200">
                You have unsaved changes
              </div>
            </div>
            
            <div className="flex items-center space-x-3">
              <button
                onClick={() => window.location.reload()}
                className="inline-flex items-center px-3 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
              >
                <XMarkIcon className="h-4 w-4 mr-1" />
                Discard
              </button>
              
              <button
                onClick={handleSave}
                disabled={isSaving}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {isSaving ? (
                  <>
                    <div className="animate-spin -ml-1 mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                    Saving...
                  </>
                ) : (
                  <>
                    <CheckIcon className="h-4 w-4 mr-2" />
                    Save Changes
                  </>
                )}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
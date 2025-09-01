import { useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useAppStore } from '../../stores/appStore';
import {
  PlayIcon,
  Cog6ToothIcon,
  InformationCircleIcon,
  PlusIcon,
  TrashIcon,
} from '@heroicons/react/24/outline';
import { ScanConfig } from '../../types';

interface ScanFormData {
  targets: string[];
  scan_type: string;
  timing: string;
  discovery_method: string;
  max_concurrent: number;
  timeout_ms: number;
  enable_service_detection: boolean;
  enable_os_detection: boolean;
  enable_version_detection: boolean;
  output_format: string[];
  custom_ports?: string;
  exclude_hosts?: string;
}

export function ScanView() {
  const { config, startScan, ui, toggleAdvancedOptions } = useAppStore();
  
  const [formData, setFormData] = useState<ScanFormData>({
    targets: [''],
    scan_type: config?.default_scan_config?.scan_type || 'TcpConnect',
    timing: config?.default_scan_config?.timing || 'Normal',
    discovery_method: config?.default_scan_config?.discovery_method || 'Ping',
    max_concurrent: config?.default_scan_config?.max_concurrent || 100,
    timeout_ms: config?.default_scan_config?.timeout_ms || 3000,
    enable_service_detection: config?.default_scan_config?.enable_service_detection || true,
    enable_os_detection: config?.default_scan_config?.enable_os_detection || false,
    enable_version_detection: config?.default_scan_config?.enable_version_detection || true,
    output_format: config?.default_scan_config?.output_format || ['Json'],
    custom_ports: '',
    exclude_hosts: '',
  });
  
  const [isLoading, setIsLoading] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  
  const validateForm = (): boolean => {
    const newErrors: Record<string, string> = {};
    
    // Validate targets
    const validTargets = formData.targets.filter(target => target.trim() !== '');
    if (validTargets.length === 0) {
      newErrors.targets = 'At least one target is required';
    }
    
    // Validate timing values
    if (formData.max_concurrent < 1 || formData.max_concurrent > 1000) {
      newErrors.max_concurrent = 'Concurrent connections must be between 1 and 1000';
    }
    
    if (formData.timeout_ms < 100 || formData.timeout_ms > 60000) {
      newErrors.timeout_ms = 'Timeout must be between 100ms and 60000ms';
    }
    
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };
  
  const handleSubmit = async (e: any) => {
    e.preventDefault();
    
    if (!validateForm()) {
      return;
    }
    
    setIsLoading(true);
    
    try {
      const validTargets = formData.targets.filter(target => target.trim() !== '');
      
      const scanConfig: ScanConfig = {
        targets: validTargets,
        scan_type: formData.scan_type as any,
        timing: formData.timing as any,
        discovery_method: formData.discovery_method as any,
        max_concurrent: formData.max_concurrent,
        timeout_ms: formData.timeout_ms,
        enable_service_detection: formData.enable_service_detection,
        enable_os_detection: formData.enable_os_detection,
        enable_version_detection: formData.enable_version_detection,
        output_format: formData.output_format as any[],
        ports: formData.custom_ports || undefined,
      };
      
      startScan(scanConfig);
      
      // Call the Tauri command to start the scan
      await invoke('start_scan', { config: scanConfig });
      
    } catch (error) {
      console.error('Failed to start scan:', error);
    } finally {
      setIsLoading(false);
    }
  };
  
  const addTarget = () => {
    setFormData(prev => ({
      ...prev,
      targets: [...prev.targets, '']
    }));
  };
  
  const removeTarget = (index: number) => {
    setFormData(prev => ({
      ...prev,
      targets: prev.targets.filter((_, i) => i !== index)
    }));
  };
  
  const updateTarget = (index: number, value: string) => {
    setFormData(prev => ({
      ...prev,
      targets: prev.targets.map((target, i) => i === index ? value : target)
    }));
  };
  
  return (
    <div className="p-6 max-w-4xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
          New Network Scan
        </h1>
        <p className="text-gray-600 dark:text-gray-400">
          Configure and launch a new network scanning operation
        </p>
      </div>
      
      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Targets Section */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Scan Targets
          </h2>
          
          <div className="space-y-3">
            {formData.targets.map((target, index) => (
              <div key={index} className="flex items-center space-x-3">
                <input
                  type="text"
                  value={target}
                  onChange={(e) => updateTarget(index, e.target.value)}
                  placeholder="IP address, hostname, or CIDR range (e.g., 192.168.1.0/24)"
                  className="flex-1 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                />
                {formData.targets.length > 1 && (
                  <button
                    type="button"
                    onClick={() => removeTarget(index)}
                    className="p-2 text-red-600 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300"
                  >
                    <TrashIcon className="h-5 w-5" />
                  </button>
                )}
              </div>
            ))}
            
            <button
              type="button"
              onClick={addTarget}
              className="flex items-center px-3 py-2 text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300"
            >
              <PlusIcon className="h-4 w-4 mr-1" />
              Add Target
            </button>
            
            {errors.targets && (
              <p className="text-sm text-red-600 dark:text-red-400">
                {errors.targets}
              </p>
            )}
          </div>
        </div>
        
        {/* Scan Configuration */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Scan Configuration
          </h2>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Scan Type
              </label>
              <select
                value={formData.scan_type}
                onChange={(e) => setFormData(prev => ({ ...prev, scan_type: e.target.value }))}
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
                value={formData.timing}
                onChange={(e) => setFormData(prev => ({ ...prev, timing: e.target.value }))}
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
                value={formData.discovery_method}
                onChange={(e) => setFormData(prev => ({ ...prev, discovery_method: e.target.value }))}
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
                Custom Ports
              </label>
              <input
                type="text"
                value={formData.custom_ports}
                onChange={(e) => setFormData(prev => ({ ...prev, custom_ports: e.target.value }))}
                placeholder="e.g., 22,80,443,8080-8090"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>
        </div>
        
        {/* Advanced Options */}
        {ui.showAdvancedOptions && (
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Advanced Options
            </h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Max Concurrent Connections
                </label>
                <input
                  type="number"
                  min="1"
                  max="1000"
                  value={formData.max_concurrent}
                  onChange={(e) => setFormData(prev => ({ ...prev, max_concurrent: parseInt(e.target.value) || 100 }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.max_concurrent && (
                  <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                    {errors.max_concurrent}
                  </p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Timeout (ms)
                </label>
                <input
                  type="number"
                  min="100"
                  max="60000"
                  value={formData.timeout_ms}
                  onChange={(e) => setFormData(prev => ({ ...prev, timeout_ms: parseInt(e.target.value) || 3000 }))}
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                />
                {errors.timeout_ms && (
                  <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                    {errors.timeout_ms}
                  </p>
                )}
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Exclude Hosts
                </label>
                <input
                  type="text"
                  value={formData.exclude_hosts}
                  onChange={(e) => setFormData(prev => ({ ...prev, exclude_hosts: e.target.value }))}
                  placeholder="e.g., 192.168.1.1,192.168.1.254"
                  className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
                />
              </div>
            </div>
            
            {/* Detection Options */}
            <div className="mt-6">
              <h3 className="text-md font-medium text-gray-900 dark:text-white mb-3">
                Detection Options
              </h3>
              <div className="space-y-3">
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.enable_service_detection}
                    onChange={(e) => setFormData(prev => ({ ...prev, enable_service_detection: e.target.checked }))}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable Service Detection
                  </span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.enable_os_detection}
                    onChange={(e) => setFormData(prev => ({ ...prev, enable_os_detection: e.target.checked }))}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable OS Detection
                  </span>
                </label>
                
                <label className="flex items-center">
                  <input
                    type="checkbox"
                    checked={formData.enable_version_detection}
                    onChange={(e) => setFormData(prev => ({ ...prev, enable_version_detection: e.target.checked }))}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                  />
                  <span className="ml-2 text-sm text-gray-700 dark:text-gray-300">
                    Enable Version Detection
                  </span>
                </label>
              </div>
            </div>
          </div>
        )}
        
        {/* Actions */}
        <div className="flex items-center justify-between">
          <button
            type="button"
            onClick={toggleAdvancedOptions}
            className="flex items-center px-4 py-2 text-sm text-gray-600 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-300"
          >
            <Cog6ToothIcon className="h-4 w-4 mr-2" />
            {ui.showAdvancedOptions ? 'Hide' : 'Show'} Advanced Options
          </button>
          
          <div className="flex items-center space-x-3">
            <button
              type="button"
              className="px-4 py-2 border border-gray-300 dark:border-gray-600 text-gray-700 dark:text-gray-300 rounded-md hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              Save as Template
            </button>
            
            <button
              type="submit"
              disabled={isLoading}
              className="inline-flex items-center px-6 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isLoading ? (
                <>
                  <div className="animate-spin -ml-1 mr-2 h-4 w-4 border-2 border-white border-t-transparent rounded-full" />
                  Starting...
                </>
              ) : (
                <>
                  <PlayIcon className="h-4 w-4 mr-2" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </div>
      </form>
      
      {/* Help Section */}
      <div className="mt-8 bg-blue-50 dark:bg-blue-900/20 rounded-lg p-4">
        <div className="flex items-start">
          <InformationCircleIcon className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5 mr-3 flex-shrink-0" />
          <div>
            <h3 className="text-sm font-medium text-blue-900 dark:text-blue-200 mb-1">
              Scan Configuration Tips
            </h3>
            <ul className="text-sm text-blue-800 dark:text-blue-300 space-y-1">
              <li>• Use CIDR notation for network ranges (e.g., 192.168.1.0/24)</li>
              <li>• TCP Connect scans are more reliable but slower than SYN scans</li>
              <li>• Lower timing templates are stealthier but take longer</li>
              <li>• Enable service detection for detailed port information</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
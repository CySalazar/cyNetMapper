import { useState, useMemo } from 'react';
import { useAppStore } from '../../stores/appStore';
import {
  MagnifyingGlassIcon,
  FunnelIcon,
  ArrowDownTrayIcon,
  EyeIcon,
  ChevronDownIcon,
  ChevronRightIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon,
  ExclamationTriangleIcon,
} from '@heroicons/react/24/outline';
import { ScanResults, HostInfo, PortInfo } from '../../types';

interface FilterOptions {
  status: string;
  service: string;
  port: string;
  host: string;
}

export function ResultsView() {
  const { scanResults, scanHistory } = useAppStore();
  
  const [selectedScan, setSelectedScan] = useState<string>('');
  const [searchQuery, setSearchQuery] = useState('');
  const [filters, setFilters] = useState<FilterOptions>({
    status: 'all',
    service: 'all',
    port: '',
    host: '',
  });
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'table' | 'tree'>('table');
  
  // Get current scan results
  const currentResults = useMemo(() => {
    if (selectedScan && scanHistory) {
      return scanHistory.find(scan => scan.id === selectedScan)?.results;
    }
    return scanResults;
  }, [selectedScan, scanHistory, scanResults]);
  
  // Filter and search results
  const filteredHosts = useMemo(() => {
    if (!currentResults?.hosts) return [];
    
    return currentResults.hosts.filter(host => {
      // Search filter
      if (searchQuery) {
        const query = searchQuery.toLowerCase();
        const matchesHost = host.ip.toLowerCase().includes(query) ||
                           (host.hostname && host.hostname.toLowerCase().includes(query));
        const matchesPort = host.ports?.some(port => 
          port.port.toString().includes(query) ||
          (port.service && port.service.name.toLowerCase().includes(query))
        );
        if (!matchesHost && !matchesPort) return false;
      }
      
      // Host filter
      if (filters.host && !host.ip.includes(filters.host)) {
        return false;
      }
      
      // Status filter
      if (filters.status !== 'all') {
        const hasMatchingPorts = host.ports?.some(port => {
          if (filters.status === 'open') return port.state === 'Open';
          if (filters.status === 'closed') return port.state === 'Closed';
          if (filters.status === 'filtered') return port.state === 'Filtered';
          return true;
        });
        if (!hasMatchingPorts) return false;
      }
      
      // Service filter
      if (filters.service !== 'all') {
        const hasMatchingService = host.ports?.some(port => 
          port.service?.name === filters.service
        );
        if (!hasMatchingService) return false;
      }
      
      // Port filter
      if (filters.port) {
        const hasMatchingPort = host.ports?.some(port => 
          port.port.toString().includes(filters.port)
        );
        if (!hasMatchingPort) return false;
      }
      
      return true;
    });
  }, [currentResults, searchQuery, filters]);
  
  // Get unique services for filter dropdown
  const availableServices = useMemo(() => {
    if (!currentResults?.hosts) return [];
    
    const services = new Set<string>();
    currentResults.hosts.forEach(host => {
      host.ports?.forEach(port => {
        if (port.service?.name) {
          services.add(port.service.name);
        }
      });
    });
    
    return Array.from(services).sort();
  }, [currentResults]);
  
  const toggleHostExpansion = (hostIp: string) => {
    const newExpanded = new Set(expandedHosts);
    if (newExpanded.has(hostIp)) {
      newExpanded.delete(hostIp);
    } else {
      newExpanded.add(hostIp);
    }
    setExpandedHosts(newExpanded);
  };
  
  const getPortStatusIcon = (state: string) => {
    switch (state) {
      case 'Open':
        return <ShieldCheckIcon className="h-4 w-4 text-green-500" />;
      case 'Closed':
        return <ShieldExclamationIcon className="h-4 w-4 text-red-500" />;
      case 'Filtered':
        return <ExclamationTriangleIcon className="h-4 w-4 text-yellow-500" />;
      default:
        return <ShieldExclamationIcon className="h-4 w-4 text-gray-500" />;
    }
  };
  
  const exportResults = () => {
    if (!currentResults) return;
    
    const dataStr = JSON.stringify(currentResults, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `scan-results-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };
  
  if (!currentResults) {
    return (
      <div className="p-6">
        <div className="text-center py-12">
          <MagnifyingGlassIcon className="mx-auto h-12 w-12 text-gray-400" />
          <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
            No scan results
          </h3>
          <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
            Run a scan to see results here.
          </p>
        </div>
      </div>
    );
  }
  
  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Scan Results
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              {currentResults.hosts?.length || 0} hosts discovered
            </p>
          </div>
          
          <div className="flex items-center space-x-3">
            <button
              onClick={exportResults}
              className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              <ArrowDownTrayIcon className="h-4 w-4 mr-2" />
              Export
            </button>
          </div>
        </div>
      </div>
      
      {/* Filters and Search */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow mb-6 p-4">
        <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between space-y-4 lg:space-y-0 lg:space-x-4">
          {/* Search */}
          <div className="flex-1 max-w-md">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search hosts, ports, or services..."
                className="w-full pl-10 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>
          
          {/* Filters */}
          <div className="flex items-center space-x-3">
            <FunnelIcon className="h-4 w-4 text-gray-400" />
            
            <select
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Ports</option>
              <option value="open">Open Ports</option>
              <option value="closed">Closed Ports</option>
              <option value="filtered">Filtered Ports</option>
            </select>
            
            <select
              value={filters.service}
              onChange={(e) => setFilters(prev => ({ ...prev, service: e.target.value }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Services</option>
              {availableServices.map(service => (
                <option key={service} value={service}>{service}</option>
              ))}
            </select>
            
            <input
              type="text"
              value={filters.port}
              onChange={(e) => setFilters(prev => ({ ...prev, port: e.target.value }))}
              placeholder="Port number"
              className="w-24 px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            />
          </div>
        </div>
      </div>
      
      {/* Results */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        {filteredHosts.length === 0 ? (
          <div className="text-center py-12">
            <MagnifyingGlassIcon className="mx-auto h-12 w-12 text-gray-400" />
            <h3 className="mt-2 text-sm font-medium text-gray-900 dark:text-white">
              No results found
            </h3>
            <p className="mt-1 text-sm text-gray-500 dark:text-gray-400">
              Try adjusting your search or filters.
            </p>
          </div>
        ) : (
          <div className="divide-y divide-gray-200 dark:divide-gray-700">
            {filteredHosts.map((host) => (
              <div key={host.ip} className="p-4">
                {/* Host Header */}
                <div 
                  className="flex items-center justify-between cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700 -m-2 p-2 rounded"
                  onClick={() => toggleHostExpansion(host.ip)}
                >
                  <div className="flex items-center space-x-3">
                    {expandedHosts.has(host.ip) ? (
                      <ChevronDownIcon className="h-4 w-4 text-gray-400" />
                    ) : (
                      <ChevronRightIcon className="h-4 w-4 text-gray-400" />
                    )}
                    
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-gray-900 dark:text-white">
                          {host.ip}
                        </span>
                        {host.hostname && (
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            ({host.hostname})
                          </span>
                        )}
                      </div>
                      
                      <div className="flex items-center space-x-4 mt-1">
                        <span className="text-sm text-gray-500 dark:text-gray-400">
                          {host.ports?.filter(p => p.state === 'Open').length || 0} open ports
                        </span>
                        
                        {host.os_fingerprint && (
                          <span className="text-sm text-gray-500 dark:text-gray-400">
                            OS: {host.os_fingerprint.os_family}
                          </span>
                        )}
                        
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${
                          host.status === 'Up' 
                            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200'
                            : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
                        }`}>
                          {host.status}
                        </span>
                      </div>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-2">
                    <button className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300">
                      <EyeIcon className="h-4 w-4" />
                    </button>
                  </div>
                </div>
                
                {/* Port Details */}
                {expandedHosts.has(host.ip) && host.ports && (
                  <div className="mt-4 ml-7">
                    <div className="overflow-hidden shadow ring-1 ring-black ring-opacity-5 md:rounded-lg">
                      <table className="min-w-full divide-y divide-gray-300 dark:divide-gray-600">
                        <thead className="bg-gray-50 dark:bg-gray-700">
                          <tr>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                              Port
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                              State
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                              Service
                            </th>
                            <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-gray-300 uppercase tracking-wider">
                              Version
                            </th>
                          </tr>
                        </thead>
                        <tbody className="bg-white dark:bg-gray-800 divide-y divide-gray-200 dark:divide-gray-700">
                          {host.ports.map((port) => (
                            <tr key={port.port} className="hover:bg-gray-50 dark:hover:bg-gray-700">
                              <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900 dark:text-white">
                                {port.port}/{port.protocol}
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                <div className="flex items-center space-x-2">
                                  {getPortStatusIcon(port.state)}
                                  <span>{port.state}</span>
                                </div>
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                {port.service?.name || '-'}
                              </td>
                              <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-gray-400">
                                {port.service?.version || '-'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
      
      {/* Statistics */}
      {currentResults.statistics && (
        <div className="mt-6 bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-4">
            Scan Statistics
          </h3>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="text-center">
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {currentResults.statistics.total_hosts}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Total Hosts
              </div>
            </div>
            
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {currentResults.statistics.hosts_up}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Hosts Up
              </div>
            </div>
            
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-600">
                {currentResults.statistics.total_ports}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Total Ports
              </div>
            </div>
            
            <div className="text-center">
              <div className="text-2xl font-bold text-green-600">
                {currentResults.statistics.open_ports}
              </div>
              <div className="text-sm text-gray-500 dark:text-gray-400">
                Open Ports
              </div>
            </div>
          </div>
          
          <div className="mt-4 text-sm text-gray-500 dark:text-gray-400">
            Scan duration: {currentResults.statistics.scan_duration_ms}ms
          </div>
        </div>
      )}
    </div>
  );
}
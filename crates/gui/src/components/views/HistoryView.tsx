import { useState, useMemo } from 'react';
import { useAppStore } from '../../stores/appStore';
import {
  ClockIcon,
  MagnifyingGlassIcon,
  TrashIcon,
  EyeIcon,
  DocumentArrowDownIcon,
  FunnelIcon,
  CheckCircleIcon,
  XCircleIcon,
  ExclamationTriangleIcon,
  PlayIcon,
} from '@heroicons/react/24/outline';
import { ScanResults, ScanStatus } from '../../types';

interface FilterOptions {
  status: ScanStatus | 'all';
  dateRange: 'all' | 'today' | 'week' | 'month';
  searchTerm: string;
}

export function HistoryView() {
  const { scanHistory, clearScanHistory, setCurrentScan } = useAppStore();
  
  const [filters, setFilters] = useState<FilterOptions>({
    status: 'all',
    dateRange: 'all',
    searchTerm: '',
  });
  
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [sortBy, setSortBy] = useState<'date' | 'duration' | 'hosts' | 'status'>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  
  // Filter and sort scan history
  const filteredScans = useMemo(() => {
    let filtered = [...scanHistory];
    
    // Filter by status
    if (filters.status !== 'all') {
      const statusMap = {
        'completed': 'Completed',
        'failed': 'Error', 
        'cancelled': 'Stopped',
        'running': 'Running'
      };
      const mappedStatus = statusMap[filters.status as keyof typeof statusMap] || filters.status;
      filtered = filtered.filter(scan => scan.status === mappedStatus);
    }
    
    // Filter by date range
    if (filters.dateRange !== 'all') {
      const now = new Date();
      const cutoff = new Date();
      
      switch (filters.dateRange) {
        case 'today':
          cutoff.setHours(0, 0, 0, 0);
          break;
        case 'week':
          cutoff.setDate(now.getDate() - 7);
          break;
        case 'month':
          cutoff.setMonth(now.getMonth() - 1);
          break;
      }
      
      filtered = filtered.filter(scan => 
        new Date(scan.start_time) >= cutoff
      );
    }
    
    // Filter by search term
    if (filters.searchTerm) {
      const term = filters.searchTerm.toLowerCase();
      filtered = filtered.filter(scan => 
        scan.config.targets.some(target => target.toLowerCase().includes(term)) ||
        scan.hosts.some(host => 
          host.ip.toLowerCase().includes(term) ||
          (host.hostname && host.hostname.toLowerCase().includes(term))
        )
      );
    }
    
    // Sort
    filtered.sort((a, b) => {
      let aVal: any, bVal: any;
      
      switch (sortBy) {
        case 'date':
          aVal = new Date(a.start_time).getTime();
          bVal = new Date(b.start_time).getTime();
          break;
        case 'duration':
          aVal = a.end_time ? new Date(a.end_time).getTime() - new Date(a.start_time).getTime() : 0;
          bVal = b.end_time ? new Date(b.end_time).getTime() - new Date(b.start_time).getTime() : 0;
          break;
        case 'hosts':
          aVal = a.hosts.length;
          bVal = b.hosts.length;
          break;
        case 'status':
          aVal = a.status;
          bVal = b.status;
          break;
        default:
          aVal = a.start_time;
          bVal = b.start_time;
      }
      
      if (sortOrder === 'asc') {
        return aVal < bVal ? -1 : aVal > bVal ? 1 : 0;
      } else {
        return aVal > bVal ? -1 : aVal < bVal ? 1 : 0;
      }
    });
    
    return filtered;
  }, [scanHistory, filters, sortBy, sortOrder]);
  
  const handleSelectScan = (scanId: string) => {
    const newSelected = new Set(selectedScans);
    if (newSelected.has(scanId)) {
      newSelected.delete(scanId);
    } else {
      newSelected.add(scanId);
    }
    setSelectedScans(newSelected);
  };
  
  const handleSelectAll = () => {
    if (selectedScans.size === filteredScans.length) {
      setSelectedScans(new Set());
    } else {
      setSelectedScans(new Set(filteredScans.map(scan => scan.scan_id)));
    }
  };
  
  const handleDeleteSelected = () => {
    if (window.confirm(`Delete ${selectedScans.size} selected scans?`)) {
      // In a real app, this would call a store action to delete specific scans
      // For now, we'll just clear the selection
      setSelectedScans(new Set());
    }
  };
  
  const handleViewScan = (scan: ScanResults) => {
    setCurrentScan(scan);
    // Navigate to results view
    // This would typically be handled by a router
  };
  
  const handleExportScan = (scan: ScanResults) => {
    const dataStr = JSON.stringify(scan, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    
    const link = document.createElement('a');
    link.href = url;
    link.download = `scan-${scan.scan_id}-${new Date(scan.start_time).toISOString().split('T')[0]}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };
  
  const getStatusIcon = (status: ScanStatus) => {
    switch (status) {
      case 'Completed':
        return <CheckCircleIcon className="h-5 w-5 text-green-500" />;
      case 'Error':
        return <XCircleIcon className="h-5 w-5 text-red-500" />;
      case 'Stopped':
        return <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500" />;
      case 'Running':
        return <PlayIcon className="h-5 w-5 text-blue-500" />;
      default:
        return <ClockIcon className="h-5 w-5 text-gray-500" />;
    }
  };
  
  const getStatusColor = (status: ScanStatus) => {
    switch (status) {
      case 'Completed':
        return 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400';
      case 'Error':
        return 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400';
      case 'Stopped':
        return 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400';
      case 'Running':
        return 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400';
      default:
        return 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400';
    }
  };
  
  const formatDuration = (startTime: string, endTime?: string) => {
    const start = new Date(startTime);
    const end = endTime ? new Date(endTime) : new Date();
    const duration = end.getTime() - start.getTime();
    
    const seconds = Math.floor(duration / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    
    if (hours > 0) {
      return `${hours}h ${minutes % 60}m`;
    } else if (minutes > 0) {
      return `${minutes}m ${seconds % 60}s`;
    } else {
      return `${seconds}s`;
    }
  };
  
  return (
    <div className="p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
              Scan History
            </h1>
            <p className="text-gray-600 dark:text-gray-400">
              View and manage your previous network scans
            </p>
          </div>
          
          <div className="flex items-center space-x-3">
            {selectedScans.size > 0 && (
              <button
                onClick={handleDeleteSelected}
                className="inline-flex items-center px-4 py-2 border border-red-300 dark:border-red-600 text-sm font-medium rounded-md text-red-700 dark:text-red-300 bg-white dark:bg-gray-800 hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
              >
                <TrashIcon className="h-4 w-4 mr-2" />
                Delete ({selectedScans.size})
              </button>
            )}
            
            <button
              onClick={() => clearScanHistory()}
              className="inline-flex items-center px-4 py-2 border border-gray-300 dark:border-gray-600 text-sm font-medium rounded-md text-gray-700 dark:text-gray-300 bg-white dark:bg-gray-800 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors"
            >
              <TrashIcon className="h-4 w-4 mr-2" />
              Clear All
            </button>
          </div>
        </div>
      </div>
      
      {/* Filters */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow mb-6 p-4">
        <div className="flex flex-wrap items-center gap-4">
          {/* Search */}
          <div className="flex-1 min-w-64">
            <div className="relative">
              <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <input
                type="text"
                placeholder="Search by target or hostname..."
                value={filters.searchTerm}
                onChange={(e) => setFilters(prev => ({ ...prev, searchTerm: e.target.value }))}
                className="w-full pl-10 pr-4 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
              />
            </div>
          </div>
          
          {/* Status Filter */}
          <div className="flex items-center space-x-2">
            <FunnelIcon className="h-4 w-4 text-gray-400" />
            <select
              value={filters.status}
              onChange={(e) => setFilters(prev => ({ ...prev, status: e.target.value as any }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Status</option>
              <option value="completed">Completed</option>
              <option value="failed">Failed</option>
              <option value="cancelled">Cancelled</option>
              <option value="running">Running</option>
            </select>
          </div>
          
          {/* Date Range Filter */}
          <div>
            <select
              value={filters.dateRange}
              onChange={(e) => setFilters(prev => ({ ...prev, dateRange: e.target.value as any }))}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="all">All Time</option>
              <option value="today">Today</option>
              <option value="week">Last Week</option>
              <option value="month">Last Month</option>
            </select>
          </div>
          
          {/* Sort */}
          <div className="flex items-center space-x-2">
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500"
            >
              <option value="date">Date</option>
              <option value="duration">Duration</option>
              <option value="hosts">Hosts Found</option>
              <option value="status">Status</option>
            </select>
            
            <button
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              className="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-md bg-white dark:bg-gray-700 text-gray-900 dark:text-white hover:bg-gray-50 dark:hover:bg-gray-600 transition-colors"
            >
              {sortOrder === 'asc' ? '↑' : '↓'}
            </button>
          </div>
        </div>
      </div>
      
      {/* Results */}
      {filteredScans.length === 0 ? (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-8 text-center">
          <ClockIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
          <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
            No scan history found
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            {filters.searchTerm || filters.status !== 'all' || filters.dateRange !== 'all'
              ? 'Try adjusting your filters to see more results.'
              : 'Start your first network scan to see results here.'}
          </p>
        </div>
      ) : (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow overflow-hidden">
          {/* Table Header */}
          <div className="bg-gray-50 dark:bg-gray-700 px-6 py-3 border-b border-gray-200 dark:border-gray-600">
            <div className="flex items-center">
              <input
                type="checkbox"
                checked={selectedScans.size === filteredScans.length && filteredScans.length > 0}
                onChange={handleSelectAll}
                className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded mr-4"
              />
              <div className="text-sm font-medium text-gray-700 dark:text-gray-300">
                {filteredScans.length} scan{filteredScans.length !== 1 ? 's' : ''}
                {selectedScans.size > 0 && ` (${selectedScans.size} selected)`}
              </div>
            </div>
          </div>
          
          {/* Table Body */}
          <div className="divide-y divide-gray-200 dark:divide-gray-600">
            {filteredScans.map((scan) => (
              <div key={scan.scan_id} className="px-6 py-4 hover:bg-gray-50 dark:hover:bg-gray-700 transition-colors">
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    checked={selectedScans.has(scan.scan_id)}
                    onChange={() => handleSelectScan(scan.scan_id)}
                    className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded mr-4"
                  />
                  
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        {getStatusIcon(scan.status)}
                        
                        <div>
                          <div className="text-sm font-medium text-gray-900 dark:text-white">
                            {scan.config.targets.join(', ')}
                          </div>
                          <div className="text-sm text-gray-500 dark:text-gray-400">
                            {new Date(scan.start_time).toLocaleString()}
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-center space-x-4">
                        <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(scan.status)}`}>
                          {scan.status}
                        </span>
                        
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {scan.hosts.length} host{scan.hosts.length !== 1 ? 's' : ''}
                        </div>
                        
                        <div className="text-sm text-gray-500 dark:text-gray-400">
                          {formatDuration(scan.start_time, scan.end_time)}
                        </div>
                        
                        <div className="flex items-center space-x-2">
                          <button
                            onClick={() => handleViewScan(scan)}
                            className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                            title="View Details"
                          >
                            <EyeIcon className="h-4 w-4" />
                          </button>
                          
                          <button
                            onClick={() => handleExportScan(scan)}
                            className="p-1 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
                            title="Export"
                          >
                            <DocumentArrowDownIcon className="h-4 w-4" />
                          </button>
                        </div>
                      </div>
                    </div>
                    
                    {/* Additional scan details */}
                    <div className="mt-2 flex items-center space-x-4 text-xs text-gray-500 dark:text-gray-400">
                      <span>Type: {scan.config.scan_type}</span>
                      <span>Timing: {scan.config.timing}</span>
                      {scan.config.enable_service_detection && <span>Service Detection</span>}
                      {scan.config.enable_os_detection && <span>OS Detection</span>}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
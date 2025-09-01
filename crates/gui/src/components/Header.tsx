import { useState } from 'react';
import { useAppStore } from '../stores/appStore';
import {
  Bars3Icon,
  BellIcon,
  Cog6ToothIcon,
  MagnifyingGlassIcon,
  PlayIcon,
  StopIcon,
  PauseIcon,
} from '@heroicons/react/24/outline';

interface HeaderProps {
  className?: string;
}

export function Header({ className = '' }: HeaderProps) {
  const {
    getIsScanning,
    scanStatus,
    scanProgress,
    toggleSidebar,
    errors,
  } = useAppStore();
  
  const [searchQuery, setSearchQuery] = useState('');
  const [showNotifications, setShowNotifications] = useState(false);
  
  const handleStartScan = async () => {
    // This will be implemented when we add Tauri commands
    console.log('Start scan clicked');
  };
  
  const handleStopScan = async () => {
    // This will be implemented when we add Tauri commands
    console.log('Stop scan clicked');
  };
  
  const handlePauseScan = async () => {
    // This will be implemented when we add Tauri commands
    console.log('Pause scan clicked');
  };
  
  const getScanStatusColor = () => {
    if (getIsScanning()) {
      return scanStatus === 'paused' ? 'text-yellow-500' : 'text-green-500';
    }
    return 'text-gray-500';
  };
  
  const getScanStatusText = () => {
    if (getIsScanning()) {
      return scanStatus === 'paused' ? 'Paused' : 'Running';
    }
    return 'Idle';
  };
  
  return (
    <header className={`bg-white dark:bg-gray-800 border-b border-gray-200 dark:border-gray-700 ${className}`}>
      <div className="flex items-center justify-between h-16 px-4">
        {/* Left section */}
        <div className="flex items-center space-x-4">
          <button
            onClick={toggleSidebar}
            className="p-2 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:bg-gray-700 transition-colors"
            aria-label="Toggle sidebar"
          >
            <Bars3Icon className="h-5 w-5" />
          </button>
          
          <div className="flex items-center space-x-2">
            <h1 className="text-xl font-semibold text-gray-900 dark:text-white">
              cyNetMapper
            </h1>
            <span className="text-sm text-gray-500 dark:text-gray-400">
              v1.0.0
            </span>
          </div>
        </div>
        
        {/* Center section - Search */}
        <div className="flex-1 max-w-md mx-8">
          <div className="relative">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <MagnifyingGlassIcon className="h-5 w-5 text-gray-400" />
            </div>
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white dark:bg-gray-700 dark:border-gray-600 placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
              placeholder="Search hosts, ports, services..."
            />
          </div>
        </div>
        
        {/* Right section */}
        <div className="flex items-center space-x-4">
          {/* Scan controls */}
          <div className="flex items-center space-x-2">
            {!getIsScanning() ? (
              <button
                onClick={handleStartScan}
                className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors"
              >
                <PlayIcon className="h-4 w-4 mr-1" />
                Start Scan
              </button>
            ) : (
              <div className="flex items-center space-x-2">
                {scanStatus !== 'paused' ? (
                  <button
                    onClick={handlePauseScan}
                    className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-yellow-600 hover:bg-yellow-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-yellow-500 transition-colors"
                  >
                    <PauseIcon className="h-4 w-4 mr-1" />
                    Pause
                  </button>
                ) : (
                  <button
                    onClick={handleStartScan}
                    className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-green-600 hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-green-500 transition-colors"
                  >
                    <PlayIcon className="h-4 w-4 mr-1" />
                    Resume
                  </button>
                )}
                <button
                  onClick={handleStopScan}
                  className="inline-flex items-center px-3 py-2 border border-transparent text-sm leading-4 font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 transition-colors"
                >
                  <StopIcon className="h-4 w-4 mr-1" />
                  Stop
                </button>
              </div>
            )}
          </div>
          
          {/* Scan status */}
          <div className="flex items-center space-x-2">
            <div className={`w-2 h-2 rounded-full ${getScanStatusColor()}`} />
            <span className="text-sm text-gray-600 dark:text-gray-300">
              {getScanStatusText()}
            </span>
            {getIsScanning() && (
              <span className="text-sm text-gray-500 dark:text-gray-400">
                ({Math.round(scanProgress)}%)
              </span>
            )}
          </div>
          
          {/* Notifications */}
          <div className="relative">
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="p-2 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:bg-gray-700 transition-colors relative"
              aria-label="Notifications"
            >
              <BellIcon className="h-5 w-5" />
              {errors.length > 0 && (
                <span className="absolute -top-1 -right-1 h-4 w-4 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                  {errors.length > 9 ? '9+' : errors.length}
                </span>
              )}
            </button>
            
            {showNotifications && (
              <div className="absolute right-0 mt-2 w-80 bg-white dark:bg-gray-800 rounded-md shadow-lg ring-1 ring-black ring-opacity-5 z-50">
                <div className="p-4">
                  <h3 className="text-sm font-medium text-gray-900 dark:text-white mb-2">
                    Notifications
                  </h3>
                  {errors.length === 0 ? (
                    <p className="text-sm text-gray-500 dark:text-gray-400">
                      No notifications
                    </p>
                  ) : (
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {errors.slice(0, 5).map((error, index) => (
                        <div key={index} className="p-2 bg-red-50 dark:bg-red-900/20 rounded border-l-4 border-red-400">
                          <p className="text-sm font-medium text-red-800 dark:text-red-200">
                            {error.message}
                          </p>
                          {error.details && (
                            <p className="text-xs text-red-600 dark:text-red-300 mt-1">
                              {error.details}
                            </p>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
          
          {/* Settings */}
          <button
            className="p-2 rounded-md text-gray-500 hover:text-gray-700 hover:bg-gray-100 dark:text-gray-400 dark:hover:text-gray-200 dark:hover:bg-gray-700 transition-colors"
            aria-label="Settings"
          >
            <Cog6ToothIcon className="h-5 w-5" />
          </button>
        </div>
      </div>
      
      {/* Progress bar */}
      {getIsScanning() && (
        <div className="h-1 bg-gray-200 dark:bg-gray-700">
          <div
            className="h-full bg-primary-500 transition-all duration-300 ease-out"
            style={{ width: `${scanProgress}%` }}
          />
        </div>
      )}
    </header>
  );
}
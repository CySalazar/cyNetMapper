import { useAppStore } from '../stores/appStore';
import {
  HomeIcon,
  MagnifyingGlassIcon,
  ChartBarIcon,
  DocumentTextIcon,
  Cog6ToothIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  ServerIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline';

interface SidebarProps {
  className?: string;
}

interface NavItem {
  id: string;
  label: string;
  icon: any;
  badge?: number;
}

export function Sidebar({ className = '' }: SidebarProps) {
  const {
    ui,
    setActiveView,
    getCurrentScanResults,
    getIsScanning,
    scanProgress,
    scanStatus,
    scanHistory,
    errors,
  } = useAppStore();
  
  const currentScanResults = getCurrentScanResults();
  const isScanning = getIsScanning();
  
  const navItems: NavItem[] = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: HomeIcon,
    },
    {
      id: 'scan',
      label: 'New Scan',
      icon: MagnifyingGlassIcon,
    },
    {
      id: 'results',
      label: 'Results',
      icon: ChartBarIcon,
      badge: currentScanResults ? 1 : 0,
    },
    {
      id: 'hosts',
      label: 'Hosts',
      icon: ServerIcon,
      badge: currentScanResults?.hosts?.length || 0,
    },
    {
      id: 'topology',
      label: 'Network Map',
      icon: GlobeAltIcon,
    },
    {
      id: 'history',
      label: 'History',
      icon: ClockIcon,
      badge: scanHistory.length,
    },
    {
      id: 'logs',
      label: 'Logs',
      icon: DocumentTextIcon,
    },
    {
      id: 'errors',
      label: 'Errors',
      icon: ExclamationTriangleIcon,
      badge: errors.length,
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Cog6ToothIcon,
    },
  ];
  
  const handleNavClick = (viewId: string) => {
    setActiveView(viewId);
  };
  
  if (ui.sidebarCollapsed) {
    return (
      <aside className={`w-16 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 ${className}`}>
        <nav className="h-full flex flex-col py-4">
          <div className="flex-1 space-y-2 px-2">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = ui.activeView === item.id;
              
              return (
                <button
                  key={item.id}
                  onClick={() => handleNavClick(item.id)}
                  className={`
                    w-full p-3 rounded-lg transition-colors relative group
                    ${
                      isActive
                        ? 'bg-primary-100 dark:bg-primary-900 text-primary-700 dark:text-primary-300'
                        : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-gray-200'
                    }
                  `}
                  title={item.label}
                >
                  <Icon className="h-6 w-6 mx-auto" />
                  {item.badge !== undefined && item.badge > 0 && (
                    <span className="absolute -top-1 -right-1 h-5 w-5 bg-red-500 text-white text-xs rounded-full flex items-center justify-center">
                      {item.badge > 99 ? '99+' : item.badge}
                    </span>
                  )}
                  
                  {/* Tooltip */}
                  <div className="absolute left-full ml-2 px-2 py-1 bg-gray-900 dark:bg-gray-700 text-white text-sm rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50">
                    {item.label}
                  </div>
                </button>
              );
            })}
          </div>
        </nav>
      </aside>
    );
  }
  
  return (
    <aside className={`w-64 bg-white dark:bg-gray-800 border-r border-gray-200 dark:border-gray-700 ${className}`}>
      <nav className="h-full flex flex-col py-4">
        <div className="px-4 mb-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
            Navigation
          </h2>
        </div>
        
        <div className="flex-1 space-y-1 px-3">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = ui.activeView === item.id;
            
            return (
              <button
                key={item.id}
                onClick={() => handleNavClick(item.id)}
                className={`
                  w-full flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors
                  ${
                    isActive
                      ? 'bg-primary-100 dark:bg-primary-900 text-primary-700 dark:text-primary-300'
                      : 'text-gray-600 dark:text-gray-400 hover:bg-gray-100 dark:hover:bg-gray-700 hover:text-gray-900 dark:hover:text-gray-200'
                  }
                `}
              >
                <Icon className="h-5 w-5 mr-3 flex-shrink-0" />
                <span className="flex-1 text-left">{item.label}</span>
                {item.badge !== undefined && item.badge > 0 && (
                  <span className="ml-2 px-2 py-1 bg-red-500 text-white text-xs rounded-full">
                    {item.badge > 99 ? '99+' : item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>
        
        {/* Current scan status */}
        {isScanning && (
          <div className="px-3 py-4 border-t border-gray-200 dark:border-gray-700">
            <div className="bg-blue-50 dark:bg-blue-900/20 rounded-lg p-3">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium text-blue-900 dark:text-blue-200">
                  Current Scan
                </span>
                <span className="text-xs text-blue-700 dark:text-blue-300">
                  {Math.round(scanProgress)}%
                </span>
              </div>
              <div className="w-full bg-blue-200 dark:bg-blue-800 rounded-full h-2">
                <div
                  className="bg-blue-600 dark:bg-blue-400 h-2 rounded-full transition-all duration-300"
                  style={{ width: `${scanProgress}%` }}
                />
              </div>
              <div className="mt-2 text-xs text-blue-700 dark:text-blue-300">
                Network scan
                {scanStatus === 'paused' && (
                  <span className="ml-1 text-yellow-600 dark:text-yellow-400">
                    (Paused)
                  </span>
                )}
              </div>
            </div>
          </div>
        )}
        
        {/* Quick stats */}
        <div className="px-3 py-4 border-t border-gray-200 dark:border-gray-700">
          <h3 className="text-xs font-semibold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-3">
            Quick Stats
          </h3>
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Total Scans</span>
              <span className="font-medium text-gray-900 dark:text-white">
                {scanHistory.length}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Active Hosts</span>
              <span className="font-medium text-gray-900 dark:text-white">
                {currentScanResults?.hosts?.length || 0}
              </span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-gray-600 dark:text-gray-400">Open Ports</span>
              <span className="font-medium text-gray-900 dark:text-white">
                {currentScanResults?.hosts?.reduce((total: number, host: any) => 
                  total + (host.ports?.filter((port: any) => port.state === 'Open').length || 0), 0
                ) || 0}
              </span>
            </div>
          </div>
        </div>
      </nav>
    </aside>
  );
}
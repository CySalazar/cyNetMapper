import { useAppStore } from '../../stores/appStore';
import {
  ChartBarIcon,
  ServerIcon,
  ClockIcon,
  ExclamationTriangleIcon,
  PlayIcon,
  EyeIcon,
} from '@heroicons/react/24/outline';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: any;
  color: string;
  trend?: {
    value: number;
    isPositive: boolean;
  };
}

function StatCard({ title, value, icon: Icon, color, trend }: StatCardProps) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
      <div className="flex items-center">
        <div className={`flex-shrink-0 p-3 rounded-lg ${color}`}>
          <Icon className="h-6 w-6 text-white" />
        </div>
        <div className="ml-4 flex-1">
          <p className="text-sm font-medium text-gray-600 dark:text-gray-400">
            {title}
          </p>
          <p className="text-2xl font-semibold text-gray-900 dark:text-white">
            {value}
          </p>
          {trend && (
            <p className={`text-sm ${
              trend.isPositive ? 'text-green-600' : 'text-red-600'
            }`}>
              {trend.isPositive ? '+' : ''}{trend.value}%
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

interface RecentScanProps {
  scan: any;
  onView: (scanId: string) => void;
}

function RecentScanItem({ scan, onView }: RecentScanProps) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Completed':
        return 'text-green-600 bg-green-100 dark:bg-green-900/20';
      case 'Failed':
        return 'text-red-600 bg-red-100 dark:bg-red-900/20';
      case 'Running':
        return 'text-blue-600 bg-blue-100 dark:bg-blue-900/20';
      default:
        return 'text-gray-600 bg-gray-100 dark:bg-gray-900/20';
    }
  };

  return (
    <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-700 last:border-b-0">
      <div className="flex-1">
        <div className="flex items-center space-x-3">
          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
            getStatusColor(scan.status)
          }`}>
            {scan.status}
          </span>
          <span className="text-sm font-medium text-gray-900 dark:text-white">
            {scan.target || 'Unknown Target'}
          </span>
        </div>
        <div className="mt-1 text-sm text-gray-500 dark:text-gray-400">
          {scan.scan_type} • {scan.hosts?.length || 0} hosts • {new Date(scan.timestamp).toLocaleString()}
        </div>
      </div>
      <button
        onClick={() => onView(scan.scan_id)}
        className="ml-4 p-2 text-gray-400 hover:text-gray-600 dark:hover:text-gray-300 transition-colors"
        title="View scan details"
      >
        <EyeIcon className="h-5 w-5" />
      </button>
    </div>
  );
}

export function Dashboard() {
  const {
    getCurrentScanResults,
    getIsScanning,
    scanProgress,
    scanStatus,
    scanHistory,
    errors,
    setActiveView,
    setSelectedScan,
  } = useAppStore();

  const currentScanResults = getCurrentScanResults();
  const totalHosts = currentScanResults?.hosts?.length || 0;
  const openPorts = currentScanResults?.hosts?.reduce((total: number, host: any) => 
    total + (host.ports?.filter((port: any) => port.state === 'Open').length || 0), 0
  ) || 0;
  const totalScans = scanHistory.length;
  const activeErrors = errors.length;

  const handleViewScan = (scanId: string) => {
    setSelectedScan(scanId);
    setActiveView('results');
  };

  const handleStartNewScan = () => {
    setActiveView('scan');
  };

  const recentScans = scanHistory.slice(0, 5);

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Dashboard
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Overview of your network scanning activities
          </p>
        </div>
        <button
          onClick={handleStartNewScan}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 transition-colors"
        >
          <PlayIcon className="h-4 w-4 mr-2" />
          New Scan
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          title="Active Hosts"
          value={totalHosts}
          icon={ServerIcon}
          color="bg-blue-500"
        />
        <StatCard
          title="Open Ports"
          value={openPorts}
          icon={ChartBarIcon}
          color="bg-green-500"
        />
        <StatCard
          title="Total Scans"
          value={totalScans}
          icon={ClockIcon}
          color="bg-purple-500"
        />
        <StatCard
          title="Errors"
          value={activeErrors}
          icon={ExclamationTriangleIcon}
          color="bg-red-500"
        />
      </div>

      {/* Current Scan Status */}
      {getIsScanning() && (
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Current Scan
          </h2>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  Network Scan
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  Scanning network targets
                </p>
              </div>
              <div className="text-right">
                <p className="text-sm font-medium text-gray-900 dark:text-white">
                  {Math.round(scanProgress)}% Complete
                </p>
                <p className="text-sm text-gray-500 dark:text-gray-400">
                  {scanStatus === 'paused' ? 'Paused' : 'Running'}
                </p>
              </div>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-primary-600 h-2 rounded-full transition-all duration-300"
                style={{ width: `${scanProgress}%` }}
              />
            </div>
          </div>
        </div>
      )}

      {/* Recent Scans */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
              Recent Scans
            </h2>
            <button
              onClick={() => setActiveView('history')}
              className="text-sm text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 transition-colors"
            >
              View All
            </button>
          </div>
        </div>
        <div className="divide-y divide-gray-200 dark:divide-gray-700">
          {recentScans.length === 0 ? (
            <div className="p-6 text-center">
              <p className="text-gray-500 dark:text-gray-400">
                No scans yet. Start your first scan to see results here.
              </p>
              <button
                onClick={handleStartNewScan}
                className="mt-2 text-primary-600 hover:text-primary-700 dark:text-primary-400 dark:hover:text-primary-300 transition-colors"
              >
                Start New Scan
              </button>
            </div>
          ) : (
            recentScans.map((scan) => (
              <RecentScanItem
                key={scan.scan_id}
                scan={scan}
                onView={handleViewScan}
              />
            ))
          )}
        </div>
      </div>

      {/* Quick Actions */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <button
          onClick={() => setActiveView('scan')}
          className="p-6 bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-md transition-shadow text-left"
        >
          <PlayIcon className="h-8 w-8 text-primary-600 mb-3" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
            Start New Scan
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Configure and launch a new network scan
          </p>
        </button>

        <button
          onClick={() => setActiveView('results')}
          className="p-6 bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-md transition-shadow text-left"
        >
          <ChartBarIcon className="h-8 w-8 text-green-600 mb-3" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
            View Results
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Analyze current scan results and data
          </p>
        </button>

        <button
          onClick={() => setActiveView('topology')}
          className="p-6 bg-white dark:bg-gray-800 rounded-lg shadow hover:shadow-md transition-shadow text-left"
        >
          <ServerIcon className="h-8 w-8 text-purple-600 mb-3" />
          <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
            Network Map
          </h3>
          <p className="text-gray-600 dark:text-gray-400">
            Visualize network topology and connections
          </p>
        </button>
      </div>
    </div>
  );
}
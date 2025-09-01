import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { Toaster } from 'react-hot-toast';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { MainContent } from './components/MainContent';
import { useAppStore } from './stores/appStore';
import { GuiEvent } from './types/events';

export function App() {
  const [isLoading, setIsLoading] = useState(true);
  const { setConfig, addEvent, updateScanProgress } = useAppStore();

  useEffect(() => {
    // Initialize the application
    const initApp = async () => {
      try {
        // Check if running in Tauri environment
        if (typeof window !== 'undefined' && window.__TAURI__) {
          // Load application configuration
          const config = await invoke('get_app_config') as any;
          setConfig(config);

          // Set up event listeners for real-time updates
          const unlistenProgress = await listen('scan-progress', (event) => {
            const progressData = event.payload as any;
            // Extract progress percentage from ScanProgress object
            if (progressData && typeof progressData.progress_percentage === 'number') {
              updateScanProgress(progressData.progress_percentage);
            }
          });

          const unlistenEvents = await listen('scan-event', (event) => {
            const eventData = event.payload as GuiEvent;
            addEvent(eventData);
          });

          // Listen for host-discovered events specifically
          const unlistenHostDiscovered = await listen('host-discovered', (event) => {
            const hostData = event.payload as any;
            const hostEvent: GuiEvent = {
              id: Date.now().toString(),
              timestamp: new Date().toISOString(),
              event_type: 'HostDiscovered',
              data: hostData
            };
            addEvent(hostEvent);
          });

          // Store cleanup functions
          return () => {
            unlistenProgress();
            unlistenEvents();
            unlistenHostDiscovered();
          };
        } else {
          // Running in browser - set default config and mock data
          console.log('Running in browser mode - Tauri APIs not available');
          setConfig({
            theme: 'light' as const,
            auto_save: true,
            max_scan_history: 100,
            default_scan_config: {
              targets: [],
              scan_type: 'TcpConnect' as const,
              timing: 'Normal' as const,
              discovery_method: 'Ping' as const,
              max_concurrent: 100,
              timeout_ms: 30000,
              enable_service_detection: true,
              enable_os_detection: true,
              enable_version_detection: false,
              output_format: ['Json' as const]
            },
            ui_preferences: {
              sidebar_collapsed: false,
              show_advanced_options: false,
              chart_animations: true,
              real_time_updates: true,
              notification_level: 'all' as const
            }
          });
        }
      } catch (error) {
        console.error('Failed to initialize app:', error);
      } finally {
        setIsLoading(false);
      }
    };

    initApp();
  }, [setConfig, addEvent, updateScanProgress]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen bg-gray-50 dark:bg-gray-900">
        <div className="text-center">
          <div className="spinner w-8 h-8 mx-auto mb-4"></div>
          <h2 className="text-lg font-semibold text-gray-900 dark:text-gray-100">
            Loading cyNetMapper...
          </h2>
          <p className="text-sm text-gray-600 dark:text-gray-400 mt-2">
            Initializing network scanner
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-screen bg-gray-50 dark:bg-gray-900">
      {/* Sidebar */}
      <Sidebar />
      
      {/* Main content area */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <Header />
        
        {/* Main content */}
        <MainContent />
      </div>
      
      {/* Toast notifications */}
      <Toaster
        position="top-right"
        toastOptions={{
          duration: 4000,
          className: 'dark:bg-gray-800 dark:text-gray-100',
          style: {
            background: 'var(--toast-bg)',
            color: 'var(--toast-color)',
          },
        }}
      />
    </div>
  );
}
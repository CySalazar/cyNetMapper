import { useAppStore } from '../stores/appStore';
import { 
  Dashboard,
  ScanView,
  ResultsView,
  NetworkMapView,
  HistoryView,
  SettingsView
} from './views';

interface MainContentProps {
  className?: string;
}

export function MainContent({ className = '' }: MainContentProps) {
  const { ui } = useAppStore();
  
  const renderView = () => {
    switch (ui.activeView) {
      case 'dashboard':
        return <Dashboard />;
      case 'scan':
        return <ScanView />;
      case 'results':
        return <ResultsView />;
      case 'network-map':
        return <NetworkMapView />;
      case 'history':
        return <HistoryView />;
      case 'settings':
        return <SettingsView />;
      default:
        return <Dashboard />;
    }
  };
  
  return (
    <main className={`flex-1 overflow-hidden ${className}`}>
      <div className="h-full overflow-y-auto">
        {renderView()}
      </div>
    </main>
  );
}
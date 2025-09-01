# cyNetMapper - Analisi Completa del Progetto

## Panoramica Generale

cyNetMapper è un network scanner avanzato scritto in Rust con un'interfaccia GUI moderna basata su Tauri e React. Il progetto implementa un'architettura modulare con workspace Cargo che separa le funzionalità in crate specializzate.

## Architettura del Sistema

### Struttura del Workspace

```
cyNetMapper/
├── crates/
│   ├── core/          # Logica principale di scansione
│   ├── cli/           # Interfaccia a riga di comando
│   ├── gui/           # Applicazione GUI (Tauri + React)
│   ├── probes/        # Moduli di probing di rete
│   ├── osfp/          # OS fingerprinting
│   ├── parsers/       # Parser per vari formati
│   ├── outputs/       # Gestione output e export
│   ├── ffi/           # Foreign Function Interface
│   └── cyndiff/       # Utility di comparazione
├── docker/            # Ambiente di test containerizzato
└── target/            # Artefatti di build
```

### Principi Architetturali

1. **Modularità**: Separazione delle responsabilità in crate distinte
2. **Performance**: Utilizzo di async/await e parallelismo con Rayon
3. **Sicurezza**: Gestione sicura della memoria con Rust
4. **Interoperabilità**: FFI per integrazione con altri linguaggi
5. **Cross-platform**: Supporto per Windows, macOS e Linux

## Backend (Rust)

### Core Engine (`crates/core/`)

**Strutture Dati Principali:**

```rust
// Configurazione di scansione
pub struct ScanConfig {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub scan_type: ScanType,
    pub timeout: Duration,
    pub max_concurrent: usize,
    pub os_detection: bool,
    pub service_detection: bool,
    pub aggressive_timing: bool,
}

// Risultati di scansione
pub struct ScanResults {
    pub hosts: Vec<HostInfo>,
    pub statistics: ScanStatistics,
    pub metadata: ScanMetadata,
}

// Informazioni host
pub struct HostInfo {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub status: HostStatus,
    pub ports: Vec<PortInfo>,
    pub os_fingerprint: Option<OsFingerprint>,
    pub response_time: Duration,
}

// Informazioni porta
pub struct PortInfo {
    pub port: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
}
```

### GUI Backend (`crates/gui/src-tauri/`)

**Comandi Tauri Disponibili:**

1. **Gestione Scansioni:**
   - `start_scan(config: ScanConfig)` - Avvia una nuova scansione
   - `stop_scan(scan_id: String)` - Ferma una scansione attiva
   - `pause_scan(scan_id: String)` - Mette in pausa una scansione
   - `resume_scan(scan_id: String)` - Riprende una scansione in pausa

2. **Monitoraggio:**
   - `get_scan_progress(scan_id: String)` - Ottiene il progresso
   - `get_active_scans()` - Lista delle scansioni attive
   - `get_scan_results(scan_id: String)` - Risultati di una scansione

3. **Configurazione:**
   - `get_config()` - Ottiene la configurazione corrente
   - `update_config(config: AppConfig)` - Aggiorna la configurazione
   - `validate_scan_config(config: ScanConfig)` - Valida una configurazione

4. **Utilità:**
   - `export_results(format: String, path: String)` - Esporta risultati
   - `get_chart_data(scan_id: String)` - Dati per grafici
   - `get_network_topology(scan_id: String)` - Topologia di rete
   - `get_system_info()` - Informazioni di sistema

**Gestione dello Stato:**

```rust
pub struct AppState {
    pub active_scans: Arc<Mutex<HashMap<String, ScanHandle>>>,
    pub config: Arc<RwLock<AppConfig>>,
    pub scan_results: Arc<Mutex<HashMap<String, ScanResults>>>,
}
```

### CLI (`crates/cli/`)

**Interfaccia a Riga di Comando:**

```rust
pub struct Cli {
    pub targets: Vec<String>,
    pub ports: Option<String>,
    pub output_format: OutputFormat,
    pub output_file: Option<PathBuf>,
    pub verbose: bool,
    pub quiet: bool,
    pub max_concurrent: Option<usize>,
    pub timeout: Option<u64>,
}
```

## Frontend (React + TypeScript)

### Struttura dei Componenti

```
src/
├── components/
│   ├── Dashboard.tsx      # Dashboard principale
│   ├── ScanView.tsx       # Vista di scansione
│   ├── ResultsView.tsx    # Visualizzazione risultati
│   ├── SettingsView.tsx   # Configurazioni
│   ├── NetworkMapView.tsx # Mappa di rete
│   ├── HistoryView.tsx    # Cronologia scansioni
│   ├── Header.tsx         # Header dell'applicazione
│   ├── Sidebar.tsx        # Barra laterale
│   └── MainContent.tsx    # Contenuto principale
├── types/
│   ├── index.ts          # Tipi principali
│   └── events.ts         # Tipi per eventi
├── stores/
│   └── appStore.ts       # Gestione stato globale
└── utils/
    └── commands.ts       # Wrapper per comandi Tauri
```

### Tipi TypeScript Principali

```typescript
// Configurazione di scansione
interface ScanConfig {
  targets: string[];
  ports: number[];
  scanType: ScanType;
  timeout: number;
  maxConcurrent: number;
  osDetection: boolean;
  serviceDetection: boolean;
  aggressiveTiming: boolean;
}

// Risultati di scansione
interface ScanResults {
  id: string;
  hosts: HostInfo[];
  statistics: ScanStatistics;
  startTime: string;
  endTime?: string;
  status: ScanStatus;
}

// Configurazione dell'applicazione
interface AppConfig {
  scanDefaults: ScanConfig;
  uiPreferences: UiPreferences;
  networkSettings: NetworkSettings;
  exportSettings: ExportSettings;
}
```

### Gestione dello Stato (Zustand)

```typescript
interface AppStore {
  // Stato
  scans: ScanResults[];
  activeScans: string[];
  config: AppConfig;
  
  // Azioni
  startScan: (config: ScanConfig) => Promise<string>;
  stopScan: (scanId: string) => Promise<void>;
  updateConfig: (config: Partial<AppConfig>) => Promise<void>;
  loadScanResults: () => Promise<void>;
}
```

### Sistema di Eventi in Tempo Reale

```typescript
// Tipi di eventi
enum GuiEventType {
  ScanStarted = 'scan_started',
  ScanProgress = 'scan_progress',
  ScanCompleted = 'scan_completed',
  HostDiscovered = 'host_discovered',
  PortDiscovered = 'port_discovered',
  Error = 'error',
  Notification = 'notification'
}

// Evento di progresso
interface ScanProgressEvent {
  scanId: string;
  hostsScanned: number;
  totalHosts: number;
  portsScanned: number;
  totalPorts: number;
  percentage: number;
  estimatedTimeRemaining?: number;
}
```

## Dipendenze e Tecnologie

### Backend (Rust)

**Core Dependencies:**
- `tokio` - Runtime asincrono
- `serde` - Serializzazione/deserializzazione
- `clap` - Parsing argomenti CLI
- `anyhow` - Gestione errori
- `tracing` - Logging strutturato
- `uuid` - Generazione identificatori
- `chrono` - Gestione date/tempo

**Networking:**
- `socket2` - Socket di basso livello
- `pnet` - Manipolazione pacchetti di rete
- `trust-dns-resolver` - Risoluzione DNS

**Performance:**
- `rayon` - Parallelismo data
- `dashmap` - HashMap concorrente
- `parking_lot` - Primitive di sincronizzazione

**Tauri:**
- `tauri` - Framework per app desktop
- `tauri-plugin-*` - Plugin per funzionalità aggiuntive

### Frontend (TypeScript/React)

**Core:**
- `react` - Libreria UI
- `typescript` - Tipizzazione statica
- `vite` - Build tool e dev server

**State Management:**
- `zustand` - Gestione stato globale

**UI/Styling:**
- `tailwindcss` - Framework CSS utility-first
- `@headlessui/react` - Componenti UI accessibili
- `lucide-react` - Icone

**Visualizzazione Dati:**
- `recharts` - Grafici e visualizzazioni
- `react-flow` - Diagrammi di rete

## Configurazioni di Sistema

### Tauri Configuration (`tauri.conf.json`)

```json
{
  "productName": "cynetmapper-gui-tauri",
  "version": "0.1.0",
  "identifier": "com.cynetmapper.gui",
  "build": {
    "beforeBuildCommand": "npm run build",
    "beforeDevCommand": "npm run dev",
    "devPath": "http://localhost:1420",
    "distDir": "../dist"
  },
  "tauri": {
    "allowlist": {
      "all": false,
      "shell": {
        "all": false,
        "open": true
      },
      "dialog": {
        "all": false,
        "open": true,
        "save": true
      },
      "fs": {
        "all": false,
        "readFile": true,
        "writeFile": true,
        "readDir": true,
        "createDir": true
      }
    }
  }
}
```

### Build Configuration

**Cargo.toml (Workspace):**
```toml
[workspace]
members = [
    "crates/core",
    "crates/cli",
    "crates/gui",
    "crates/probes",
    "crates/osfp",
    "crates/parsers",
    "crates/outputs",
    "crates/ffi",
    "crates/cyndiff"
]

[workspace.dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
```

**Vite Configuration:**
```typescript
export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"]
    }
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  }
});
```

## Persistenza dei Dati

### Formato di Output

**JSON Canonico:**
```json
{
  "scan_metadata": {
    "id": "uuid",
    "start_time": "2024-01-01T00:00:00Z",
    "end_time": "2024-01-01T00:05:00Z",
    "scanner_version": "0.1.0",
    "command_line": "cynetmapper -t 192.168.1.0/24"
  },
  "hosts": [
    {
      "ip": "192.168.1.1",
      "hostname": "router.local",
      "status": "up",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": {
            "name": "http",
            "version": "nginx/1.18.0"
          }
        }
      ]
    }
  ]
}
```

### Compatibilità Nmap XML

Il sistema supporta l'export in formato Nmap XML per compatibilità con tool esistenti.

## Sicurezza

### Pratiche di Sicurezza Implementate

1. **Gestione Privilegi:**
   - Richiesta privilegi minimi necessari
   - Separazione tra operazioni privilegiate e non

2. **Validazione Input:**
   - Sanitizzazione target di scansione
   - Validazione range di porte
   - Controllo parametri di configurazione

3. **Gestione Errori:**
   - Logging sicuro senza esposizione di informazioni sensibili
   - Gestione graceful di errori di rete

4. **Tauri Security:**
   - Allowlist restrittiva per API
   - CSP (Content Security Policy) configurata
   - Comunicazione sicura frontend-backend

## Performance e Ottimizzazioni

### Strategie di Performance

1. **Concorrenza:**
   - Scansioni parallele con limite configurabile
   - Pool di thread per operazioni I/O

2. **Caching:**
   - Cache DNS per ridurre lookup
   - Cache risultati per evitare rescansioni

3. **Memory Management:**
   - Streaming dei risultati per grandi scansioni
   - Garbage collection efficiente in frontend

4. **Network Optimization:**
   - Timeout adattivi
   - Rate limiting per evitare sovraccarico

### Metriche di Performance

```rust
pub struct ScanStatistics {
    pub total_hosts: usize,
    pub hosts_up: usize,
    pub total_ports: usize,
    pub open_ports: usize,
    pub scan_duration: Duration,
    pub packets_sent: u64,
    pub packets_received: u64,
}
```

## Testing e Quality Assurance

### Ambiente di Test

**Docker Lab Environment:**
```yaml
# docker-compose.lab.yml
services:
  web-server:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
  
  ssh-server:
    image: linuxserver/openssh-server
    ports:
      - "22:2222"
  
  database:
    image: postgres:13
    ports:
      - "5432:5432"
```

### Tipi di Test

1. **Unit Tests:** Test delle singole funzioni e moduli
2. **Integration Tests:** Test dell'integrazione tra componenti
3. **Performance Tests:** Benchmark delle operazioni critiche
4. **Security Tests:** Verifica delle pratiche di sicurezza

## Deployment

### Build Process

1. **Development:**
   ```bash
   # Backend development
   cargo run --bin cynetmapper
   
   # GUI development
   cd crates/gui
   npm run tauri dev
   ```

2. **Production Build:**
   ```bash
   # CLI release
   cargo build --release --bin cynetmapper
   
   # GUI release
   cd crates/gui
   npm run tauri build
   ```

### Distribuzione

- **CLI:** Binario singolo per ogni piattaforma
- **GUI:** Installer nativi (DMG, MSI, AppImage)
- **Docker:** Container per deployment server

## Gap Analysis e Aree di Miglioramento

### Funzionalità Mancanti

1. **Database Integration:**
   - Persistenza risultati in database relazionale
   - Storico scansioni con ricerca avanzata
   - Correlazione dati temporali

2. **Advanced Reporting:**
   - Report PDF/HTML personalizzabili
   - Dashboard analytics avanzate
   - Trend analysis e alerting

3. **Collaboration Features:**
   - Condivisione scansioni tra utenti
   - Commenti e annotazioni
   - Workflow di approvazione

4. **API REST/GraphQL:**
   - API pubblica per integrazioni
   - Webhook per notifiche
   - Rate limiting e autenticazione

5. **Mobile Support:**
   - App mobile companion
   - Notifiche push
   - Visualizzazione risultati mobile-friendly

6. **Machine Learning:**
   - Anomaly detection
   - Predictive analysis
   - Automated threat classification

7. **Vulnerability Integration:**
   - Database CVE integration
   - Automated vulnerability assessment
   - Risk scoring

### Miglioramenti Tecnici

1. **Performance:**
   - Ottimizzazione algoritmi di scansione
   - Caching più aggressivo
   - Parallelizzazione avanzata

2. **User Experience:**
   - Wizard di configurazione guidata
   - Template di scansione predefiniti
   - Keyboard shortcuts

3. **Monitoring:**
   - Metriche applicazione in tempo reale
   - Health checks
   - Distributed tracing

4. **Security:**
   - Audit logging completo
   - Encryption at rest
   - RBAC (Role-Based Access Control)

## Conclusioni

cyNetMapper rappresenta un network scanner moderno e ben architettato che combina le performance di Rust con un'interfaccia utente moderna. L'architettura modulare facilita la manutenzione e l'estensione, mentre l'uso di tecnologie moderne garantisce scalabilità e sicurezza.

Le aree di miglioramento identificate offrono opportunità per evolvere il prodotto verso una soluzione enterprise-grade con funzionalità avanzate di collaboration, analytics e integrazione.

---

*Documento generato il: $(date)*
*Versione progetto analizzata: 0.1.0*
*Analisi basata su: Codebase completo, documentazione architetturale, configurazioni di sistema*
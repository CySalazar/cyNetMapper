# cyNetMapper

<div align="center">

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![Tauri](https://img.shields.io/badge/tauri-%2324C8DB.svg?style=for-the-badge&logo=tauri&logoColor=%23FFFFFF)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/username/cyNetMapper/workflows/CI/badge.svg)](https://github.com/username/cyNetMapper/actions)
[![Release](https://img.shields.io/github/v/release/username/cyNetMapper)](https://github.com/username/cyNetMapper/releases)

**Un network scanner avanzato e moderno scritto in Rust con interfaccia GUI cross-platform**

[Funzionalità](#-funzionalità) •
[Installazione](#-installazione) •
[Utilizzo](#-utilizzo) •
[Documentazione](#-documentazione) •
[Contributi](#-contributi)

</div>

## 🚀 Panoramica

cyNetMapper è un network scanner ad alte prestazioni che combina la velocità e la sicurezza di Rust con un'interfaccia utente moderna e intuitiva. Progettato per professionisti della sicurezza, amministratori di rete e ricercatori, offre capacità di scansione avanzate con visualizzazioni in tempo reale.

### ✨ Caratteristiche Principali

- **🔥 Performance Elevate**: Engine di scansione asincrono scritto in Rust
- **🖥️ GUI Moderna**: Interfaccia cross-platform con Tauri e React
- **⚡ Scansioni in Tempo Reale**: Monitoraggio live del progresso e dei risultati
- **🎯 Rilevamento Avanzato**: OS fingerprinting e service detection
- **📊 Visualizzazioni**: Grafici interattivi e mappe di rete
- **🔧 CLI Potente**: Interfaccia a riga di comando per automazione
- **📁 Export Multipli**: Supporto per JSON, XML (Nmap), CSV
- **🐳 Docker Ready**: Ambiente di test containerizzato incluso

## 🛠️ Funzionalità

### Core Engine
- Scansioni TCP/UDP parallele ad alta velocità
- Rilevamento automatico di servizi e versioni
- OS fingerprinting avanzato
- Timeout adattivi e rate limiting intelligente
- Gestione robusta degli errori

### Interfaccia GUI
- Dashboard in tempo reale con metriche live
- Configurazione guidata delle scansioni
- Visualizzazione interattiva dei risultati
- Grafici e mappe di rete dinamiche
- Gestione della cronologia delle scansioni
- Esportazione e reportistica avanzata

### CLI
- Sintassi intuitiva e flessibile
- Supporto per target multipli e range di porte
- Output personalizzabile
- Integrazione con pipeline CI/CD
- Scripting e automazione

## 📦 Installazione

### Prerequisiti

- **Rust** 1.70+ (per compilazione da sorgenti)
- **Node.js** 18+ (per sviluppo GUI)
- **Git** (per clonare il repository)

### Opzione 1: Download Binari Precompilati

```bash
# Scarica l'ultima release da GitHub
wget https://github.com/username/cyNetMapper/releases/latest/download/cynetmapper-linux-x64.tar.gz
tar -xzf cynetmapper-linux-x64.tar.gz
sudo mv cynetmapper /usr/local/bin/
```

### Opzione 2: Compilazione da Sorgenti

```bash
# Clona il repository
git clone https://github.com/username/cyNetMapper.git
cd cyNetMapper

# Compila la CLI
cargo build --release --bin cynetmapper

# Compila la GUI
cd crates/gui
npm install
npm run tauri build
```

### Opzione 3: Docker

```bash
# Esegui con Docker
docker run -it --rm cynetmapper/cynetmapper:latest --help

# Oppure usa docker-compose per l'ambiente di test
cd docker
docker-compose -f docker-compose.lab.yml up -d
```

## 🎯 Utilizzo

### CLI - Esempi Rapidi

```bash
# Scansione base di un host
cynetmapper 192.168.1.1

# Scansione di una subnet con porte specifiche
cynetmapper 192.168.1.0/24 -p 22,80,443,8080

# Scansione completa con OS detection
cynetmapper 10.0.0.0/8 -p 1-1000 --os-detection --service-detection

# Export in formato JSON
cynetmapper example.com -o json --output-file results.json

# Scansione veloce con timing aggressivo
cynetmapper 192.168.1.0/24 --aggressive-timing --max-concurrent 100
```

### GUI - Avvio Rapido

```bash
# Avvia l'interfaccia grafica
cynetmapper-gui

# Oppure in modalità sviluppo
cd crates/gui
npm run tauri dev
```

### Configurazione Avanzata

```bash
# Crea file di configurazione personalizzato
cynetmapper --generate-config > ~/.cynetmapper.toml

# Usa configurazione personalizzata
cynetmapper --config ~/.cynetmapper.toml 192.168.1.0/24
```

## 🏗️ Architettura

cyNetMapper utilizza un'architettura modulare basata su workspace Cargo:

```
cyNetMapper/
├── crates/
│   ├── core/          # Engine di scansione principale
│   ├── cli/           # Interfaccia a riga di comando
│   ├── gui/           # Applicazione GUI (Tauri + React)
│   ├── probes/        # Moduli di probing di rete
│   ├── osfp/          # OS fingerprinting
│   ├── parsers/       # Parser per vari formati
│   ├── outputs/       # Gestione output e export
│   ├── ffi/           # Foreign Function Interface
│   └── cyndiff/       # Utility di comparazione
├── docker/            # Ambiente di test containerizzato
└── docs/              # Documentazione
```

### Tecnologie Utilizzate

**Backend (Rust)**
- `tokio` - Runtime asincrono
- `serde` - Serializzazione
- `clap` - Parsing CLI
- `socket2` - Networking low-level
- `rayon` - Parallelismo

**Frontend (TypeScript/React)**
- `React 18` - Framework UI
- `TypeScript` - Tipizzazione statica
- `Zustand` - State management
- `Tailwind CSS` - Styling
- `Recharts` - Visualizzazioni

**Desktop (Tauri)**
- Cross-platform desktop app
- Comunicazione sicura frontend-backend
- Bundle nativi per ogni OS

## 📚 Documentazione

- **[Guida Utente](docs/user-guide.md)** - Tutorial completo e esempi
- **[Documentazione API](docs/api.md)** - Riferimento API completo
- **[Architettura](ARCHITECTURE.md)** - Design e principi architetturali
- **[Analisi Completa](COMPREHENSIVE_PROJECT_ANALYSIS.md)** - Analisi dettagliata del progetto
- **[Esempi](examples/)** - Script e configurazioni di esempio

## 🧪 Testing

```bash
# Esegui tutti i test
cargo test --workspace

# Test con coverage
cargo tarpaulin --out Html

# Benchmark
cargo bench

# Test dell'ambiente Docker
cd docker
./test-lab.sh
```

## 🤝 Contributi

I contributi sono benvenuti! Per contribuire:

1. **Fork** il repository
2. **Crea** un branch per la tua feature (`git checkout -b feature/amazing-feature`)
3. **Commit** le tue modifiche (`git commit -m 'Add amazing feature'`)
4. **Push** al branch (`git push origin feature/amazing-feature`)
5. **Apri** una Pull Request

### Linee Guida per i Contributi

- Segui le convenzioni di codice Rust standard (`cargo fmt`, `cargo clippy`)
- Aggiungi test per le nuove funzionalità
- Aggiorna la documentazione quando necessario
- Mantieni i commit atomici e descrittivi

### Segnalazione Bug

Per segnalare bug, utilizza il [sistema di issue di GitHub](https://github.com/username/cyNetMapper/issues) includendo:

- Descrizione dettagliata del problema
- Passi per riprodurre il bug
- Versione di cyNetMapper e sistema operativo
- Log di errore (se disponibili)

## 📋 Roadmap

- [ ] **v0.2.0** - Integrazione database per persistenza risultati
- [ ] **v0.3.0** - API REST per integrazioni esterne
- [ ] **v0.4.0** - Plugin system e estensibilità
- [ ] **v0.5.0** - Machine learning per anomaly detection
- [ ] **v1.0.0** - Release stabile con tutte le funzionalità core

Vedi la [roadmap completa](https://github.com/username/cyNetMapper/projects) per dettagli.

## 📄 Licenza

Questo progetto è rilasciato sotto licenza MIT. Vedi il file [LICENSE](LICENSE) per i dettagli.

```
MIT License

Copyright (c) 2024 cyNetMapper Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## 🙏 Riconoscimenti

- Ispirato da [Nmap](https://nmap.org/) per le tecniche di scansione
- [Tauri](https://tauri.app/) per il framework desktop
- [Rust](https://www.rust-lang.org/) community per l'ecosistema eccezionale
- Tutti i [contributori](https://github.com/username/cyNetMapper/contributors) che rendono questo progetto possibile

## 📞 Supporto

- **Documentazione**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/username/cyNetMapper/issues)
- **Discussioni**: [GitHub Discussions](https://github.com/username/cyNetMapper/discussions)
- **Email**: support@cynetmapper.dev

---

<div align="center">

**[⬆ Torna all'inizio](#cynetmapper)**

Realizzato con ❤️ dalla community cyNetMapper

</div>
# cyNetMapper

<div align="center">

![Rust](https://img.shields.io/badge/rust-%23000000.svg?style=for-the-badge&logo=rust&logoColor=white)
![TypeScript](https://img.shields.io/badge/typescript-%23007ACC.svg?style=for-the-badge&logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/react-%2320232a.svg?style=for-the-badge&logo=react&logoColor=%2361DAFB)
![Tauri](https://img.shields.io/badge/tauri-%2324C8DB.svg?style=for-the-badge&logo=tauri&logoColor=%23FFFFFF)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![CI](https://github.com/username/cyNetMapper/workflows/CI/badge.svg)](https://github.com/username/cyNetMapper/actions)
[![Release](https://img.shields.io/github/v/release/username/cyNetMapper)](https://github.com/username/cyNetMapper/releases)

**An advanced and modern network scanner written in Rust with cross-platform GUI interface**

[Features](#-features) •
[Installation](#-installation) •
[Usage](#-usage) •
[Documentation](#-documentation) •
[Contributing](#-contributing)

</div>

## 🚀 Overview

cyNetMapper is a high-performance network scanner that combines the speed and security of Rust with a modern and intuitive user interface. Designed for security professionals, network administrators, and researchers, it offers advanced scanning capabilities with real-time visualizations.

### ✨ Key Features

- **🔥 High Performance**: Asynchronous scanning engine written in Rust
- **🖥️ Modern GUI**: Cross-platform interface with Tauri and React
- **⚡ Real-time Scanning**: Live monitoring of progress and results
- **🎯 Advanced Detection**: OS fingerprinting and service detection
- **📊 Visualizations**: Interactive charts and network maps
- **🔧 Powerful CLI**: Command-line interface for automation
- **📁 Multiple Exports**: Support for JSON, XML (Nmap), CSV
- **🐳 Docker Ready**: Containerized testing environment included

## 🛠️ Features

### Core Engine
- High-speed parallel TCP/UDP scanning
- Automatic service and version detection
- Advanced OS fingerprinting
- Adaptive timeouts and intelligent rate limiting
- Robust error handling

### GUI Interface
- Real-time dashboard with live metrics
- Guided scan configuration
- Interactive results visualization
- Dynamic charts and network maps
- Scan history management
- Advanced export and reporting

### CLI
- Intuitive and flexible syntax
- Support for multiple targets and port ranges
- Customizable output
- CI/CD pipeline integration
- Scripting and automation

## 📦 Installation

### Prerequisites

- **Rust** 1.70+ (for building from source)
- **Node.js** 18+ (for GUI development)
- **Git** (for cloning the repository)

### Option 1: Download Precompiled Binaries

```bash
# Download the latest release from GitHub
wget https://github.com/username/cyNetMapper/releases/latest/download/cynetmapper-linux-x64.tar.gz
tar -xzf cynetmapper-linux-x64.tar.gz
sudo mv cynetmapper /usr/local/bin/
```

### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/username/cyNetMapper.git
cd cyNetMapper

# Build the CLI
cargo build --release --bin cynetmapper

# Build the GUI
cd crates/gui
npm install
npm run tauri build
```

### Option 3: Docker

```bash
# Run with Docker
docker run -it --rm cynetmapper/cynetmapper:latest --help

# Or use docker-compose for testing environment
cd docker
docker-compose -f docker-compose.lab.yml up -d
```

## 🎯 Usage

### CLI - Quick Examples

```bash
# Basic host scan
cynetmapper 192.168.1.1

# Subnet scan with specific ports
cynetmapper 192.168.1.0/24 -p 22,80,443,8080

# Full scan with OS detection
cynetmapper 10.0.0.0/8 -p 1-1000 --os-detection --service-detection

# Export to JSON format
cynetmapper example.com -o json --output-file results.json

# Fast scan with aggressive timing
cynetmapper 192.168.1.0/24 --aggressive-timing --max-concurrent 100
```

### GUI - Quick Start

```bash
# Launch the graphical interface
cynetmapper-gui

# Or in development mode
cd crates/gui
npm run tauri dev
```

### Advanced Configuration

```bash
# Create custom configuration file
cynetmapper --generate-config > ~/.cynetmapper.toml

# Use custom configuration
cynetmapper --config ~/.cynetmapper.toml 192.168.1.0/24
```

## 🏗️ Architecture

cyNetMapper uses a modular architecture based on Cargo workspaces:

```
cyNetMapper/
├── crates/
│   ├── core/          # Main scanning engine
│   ├── cli/           # Command-line interface
│   ├── gui/           # GUI application (Tauri + React)
│   ├── probes/        # Network probing modules
│   ├── osfp/          # OS fingerprinting
│   ├── parsers/       # Parsers for various formats
│   ├── outputs/       # Output handling and export
│   ├── ffi/           # Foreign Function Interface
│   └── cyndiff/       # Comparison utilities
├── docker/            # Containerized testing environment
└── docs/              # Documentation
```

### Technologies Used

**Backend (Rust)**
- `tokio` - Asynchronous runtime
- `serde` - Serialization
- `clap` - CLI parsing
- `socket2` - Low-level networking
- `rayon` - Parallelism

**Frontend (TypeScript/React)**
- `React 18` - UI framework
- `TypeScript` - Static typing
- `Zustand` - State management
- `Tailwind CSS` - Styling
- `Recharts` - Visualizations

**Desktop (Tauri)**
- Cross-platform desktop app
- Secure frontend-backend communication
- Native bundles for each OS

## 📚 Documentation

- **[User Guide](docs/user-guide.md)** - Complete tutorial and examples
- **[API Documentation](docs/api.md)** - Complete API reference
- **[Architecture](ARCHITECTURE.md)** - Design and architectural principles
- **[Comprehensive Analysis](COMPREHENSIVE_PROJECT_ANALYSIS.md)** - Detailed project analysis
- **[Examples](examples/)** - Sample scripts and configurations

## 🧪 Testing

```bash
# Run all tests
cargo test --workspace

# Test with coverage
cargo tarpaulin --out Html

# Benchmarks
cargo bench

# Test Docker environment
cd docker
./test-lab.sh
```

## 🤝 Contributing

Contributions are welcome! To contribute:

1. **Fork** the repository
2. **Create** a branch for your feature (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Guidelines

- Follow standard Rust code conventions (`cargo fmt`, `cargo clippy`)
- Add tests for new features
- Update documentation when necessary
- Keep commits atomic and descriptive

### Bug Reports

To report bugs, use the [GitHub issue system](https://github.com/username/cyNetMapper/issues) including:

- Detailed description of the problem
- Steps to reproduce the bug
- cyNetMapper version and operating system
- Error logs (if available)

## 📋 Roadmap

- [ ] **v0.2.0** - Database integration for result persistence
- [ ] **v0.3.0** - REST API for external integrations
- [ ] **v0.4.0** - Plugin system and extensibility
- [ ] **v0.5.0** - Machine learning for anomaly detection
- [ ] **v1.0.0** - Stable release with all core features

See the [complete roadmap](https://github.com/username/cyNetMapper/projects) for details.

## 📄 License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.

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

## 🙏 Acknowledgments

- Inspired by [Nmap](https://nmap.org/) for scanning techniques
- [Tauri](https://tauri.app/) for the desktop framework
- [Rust](https://www.rust-lang.org/) community for the exceptional ecosystem
- All [contributors](https://github.com/username/cyNetMapper/contributors) who make this project possible

## 📞 Support

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/username/cyNetMapper/issues)
- **Discussions**: [GitHub Discussions](https://github.com/username/cyNetMapper/discussions)
- **Email**: support@cynetmapper.dev

---

<div align="center">

**[⬆ Back to top](#cynetmapper)**

Made with ❤️ by the cyNetMapper community

</div>
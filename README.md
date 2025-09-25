# Autonomous OSINT Suite

A comprehensive, autonomous Open Source Intelligence (OSINT) gathering suite with enterprise-grade security, anonymity, and operational security features. Now enhanced with **RapidAPI integrations**, **free tools**, **pre-seeded databases**, and a **modern web interface**.

## 🚀 Quick Start

### One-Command Setup (Recommended)

```bash
# Clone and setup everything automatically
git clone <repository-url>
cd osint-suite

# Run the universal installer (includes health checks and setup wizard)
./install_universal.sh

# Launch with the intelligent quick start menu
./start_osint_suite.sh
```

Then visit **<http://localhost:3000>** for the web interface!

### Alternative Launch Methods

```bash
# Quick health check before starting
./monitor_system.sh

# Run setup wizard only (for existing installations)
./install_universal.sh --wizard

# Run health checks only
./install_universal.sh --health-check

# Start monitoring daemon
./monitor_system.sh --daemon
```

## 📖 Full Documentation

For complete installation instructions, usage guides, and API documentation, see:

- **[📚 Comprehensive README](README_COMPLETE.md)** - Full setup guide and documentation
- **[🚀 Quick Start Guide](STARTUP_GUIDE.md)** - One-command launch instructions
- **[🔧 Direct Execution Guide](DIRECT_EXECUTION_GUIDE.md)** - Command-line usage
- **[🌐 Web Platform Guide](ENHANCED_PLATFORM_GUIDE.md)** - Web interface features

## ✨ Key Features

### 🔒 **Security & Anonymity**
- Tor integration with circuit hygiene
- DNS over HTTPS via Tor
- Query obfuscation and anti-fingerprinting
- OPSEC policy enforcement

### 🕵️ **Intelligence Gathering**
- **15+ RapidAPI Services** - Free-tier access to premium intelligence APIs
- **Government Databases** - CISA, FBI, OFAC, NOAA, USGS, and more (no API keys required)
- **Free Local Tools** - File analysis, URL inspection, pattern extraction
- **Enhanced Google Dorking** - Multi-engine search with comprehensive patterns
- **Bellingcat Toolkit** - Investigative journalism tools

### 🌐 **Modern Web Interface**
- React/Vite frontend with real-time updates
- AI-powered analysis and investigation management
- Interactive data visualization and mapping
- Export capabilities (JSON, CSV, PDF, Excel)

### 🔧 **Enterprise Features**
- FastAPI backend with WebSocket support
- Redis caching and Elasticsearch indexing
- Immutable audit trails and result encryption
- Role-based access control (RBAC)

## �️ **Deployment & Monitoring**

### **Universal Installer**
- **Environment Detection**: Automatic OS, architecture, and dependency detection
- **Health Checks**: Comprehensive validation of all components before startup
- **Setup Wizard**: Guided configuration for API keys, security settings, and preferences
- **Error Recovery**: Automatic troubleshooting and rollback capabilities

### **Intelligent Launcher**
- **Quick Start Menu**: Interactive menu for different launch modes
- **Health Validation**: Pre-launch health checks with issue detection
- **Multiple Interfaces**: Web, CLI, direct command, and quick investigation modes
- **Documentation Access**: Built-in help and documentation viewer

### **System Monitoring**
- **Continuous Health Monitoring**: Background daemon for system health tracking
- **Alert System**: Automatic alerts for disk space, memory, and component failures
- **Resource Tracking**: CPU, memory, network, and storage monitoring
- **Log Management**: Automatic log rotation and size monitoring

## �📦 What's Included

- **30+ OSINT Modules** across 15+ categories
- **Web Application** with modern React interface
- **REST API** with automatic documentation
- **CLI Tools** for all major functions
- **Security Framework** with Tor integration
- **Investigation Management** and case tracking

## 🛠️ Quick Module Examples

```python
# Enhanced modules (new!)
from modules import get_module

# RapidAPI integration
rapidapi = get_module('rapidapi_osint')
results = rapidapi.comprehensive_person_search(email="target@example.com")

# Government databases (free)
db = get_module('preseeded_databases')
vulns = db.search_cisa_vulnerabilities("CVE-2023")

# Local analysis tools
tools = get_module('free_tools')
metadata = tools.extract_file_metadata("document.pdf")

# Advanced dorking
dorking = get_module('search_engine_dorking')
results = dorking.comprehensive_dorking_search("example.com")
```

## 🔗 Links

- **Web Interface**: <http://localhost:3001> (after setup)
- **API Documentation**: <http://localhost:8001/docs> (after setup)
- **GitHub Repository**: [Link to repository]

---

**Ready to get started?** Run `./start_simple.sh` and visit <http://localhost:3001>!

## 🛠️ Troubleshooting

### Health Checks & Diagnostics

**Run comprehensive health checks:**
```bash
# Full health check with detailed component validation
./install_universal.sh --health-check

# Quick health check
./monitor_system.sh

# Generate health report
./monitor_system.sh --report

# View recent alerts
./monitor_system.sh --alerts
```

**Common Issues & Solutions:**

- **Python environment issues**: Run `./install_universal.sh` to reinstall
- **Missing dependencies**: The installer will detect and fix automatically
- **Configuration problems**: Run `./install_universal.sh --wizard` to reconfigure
- **Network issues**: Check `./monitor_system.sh` for connectivity status

### System Monitoring

**Start background monitoring:**
```bash
# Monitor system health continuously
./monitor_system.sh --daemon

# Check logs for issues
tail -f logs/monitoring.log
tail -f logs/alerts.log
```

### Dev Container Recovery Mode

If you see "This codespace is currently running in recovery mode due to a configuration error":

1. **Run the rebuild script** (safest option):
   ```bash
   ./rebuild_container.sh
   ```

2. **Or manually rebuild** using VS Code Command Palette:
   - `Ctrl+Shift+P` → "Dev Containers: Rebuild Container"

3. **Wait for rebuild** - this takes ~2-3 minutes for the minimal setup

**What the rebuild does:**
- ✅ Installs Python 3.12 with core packages only
- ✅ Sets up Git and essential tools
- ✅ Installs VS Code extensions
- ✅ Makes scripts executable
- ✅ **Node.js and full ML packages install automatically on first run**

### First Run Setup

After container rebuild, run:
```bash
./install_universal.sh
```

This will automatically:
- Detect your environment and install dependencies
- Run comprehensive health checks
- Launch the setup wizard for configuration
- Validate all components before completion

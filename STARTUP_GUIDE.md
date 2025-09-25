# OSINT Suite - One-Command Startup Guide

## 🚀 Quick Start - One Command Launch

Run the complete OSINT Suite with all components in **one simple command**:

```bash
./start_simple.sh
```

This script will:
- ✅ **Set up Python virtual environment** (.venv)
- ✅ **Install all dependencies** (Python packages + npm modules)
- ✅ **Configure keyring password** automatically to `TOC8925!`
- ✅ **Start API backend** (FastAPI server with OSINT modules)
- ✅ **Launch web interface** (React/Vite frontend)
- ✅ **Handle all configuration** automatically
- ✅ **Monitor services** and restart if needed

## 🌐 Access Points

Once started, access the OSINT Suite at:

- **Web Interface**: http://localhost:3001 (or next available port)
- **API Backend**: http://localhost:8001
- **API Documentation**: http://localhost:8001/docs

## 🛠️ What's Included

### Backend Services
- **FastAPI Server** - REST API for all OSINT modules
- **AI Analysis Engine** - Local LLM and cloud AI integration
- **Investigation Manager** - Case management and workflow
- **Cross-Reference Engine** - Data correlation and analysis

### Web Interface
- **Modern React Dashboard** - Intuitive investigation interface
- **OSINT Module Grid** - Access to all 12+ intelligence modules
- **AI Analysis Tabs** - Integrated AI-powered analysis
- **Data Visualization** - Charts, graphs, and geographic mapping
- **Export System** - Multiple format support (JSON, CSV, PDF, Excel)

### OSINT Modules
- **Domain Reconnaissance** - DNS, WHOIS, subdomain enumeration
- **Email Intelligence** - Email analysis and pattern detection
- **Company Intelligence** - Corporate intel gathering
- **Cryptocurrency Analysis** - Blockchain investigation
- **Flight Intelligence** - Aviation tracking and analysis
- **IP Intelligence** - Network and geolocation analysis
- **Media Forensics** - Image and video analysis
- **Network Intelligence** - Infrastructure mapping
- **Conspiracy Analysis** - Evidence-based validation
- **Bellingcat Toolkit** - Open source investigation tools
- **Cross-Reference Engine** - Multi-source data correlation
- **Audit Trail** - Complete activity logging

## 🔧 Alternative Startup Options

### Comprehensive Startup (with Tor, full services)
```bash
./start_osint_suite.sh
```

### Manual Component Startup
```bash
# Backend only
source .venv/bin/activate
python api/api_server.py

# Frontend only
cd web
npm run dev
```

## 🔐 Security Features

- **Keyring Password**: Automatically set to `TOC8925!`
- **Tor Integration**: Optional anonymity layer
- **Result Encryption**: Secure data storage
- **OPSEC Compliance**: Privacy-first design
- **Audit Logging**: Complete activity tracking

## 📋 System Requirements

- **Python 3.8+** with pip
- **Node.js 16+** with npm
- **Linux/macOS** (Windows via WSL)
- **4GB RAM** minimum (8GB recommended)
- **2GB disk space** for dependencies

## 🚨 Troubleshooting

### Port Conflicts
If ports are in use, the script automatically finds next available ports:
- Web: 3001, 3002, 3003...
- API: 8001, 8002, 8003...

### Permission Issues
```bash
chmod +x start_simple.sh
chmod +x start_osint_suite.sh
```

### Dependency Issues
The startup script automatically installs missing dependencies, but if issues persist:
```bash
# Clean rebuild
rm -rf .venv web/node_modules
./start_simple.sh
```

### Keyring Issues
The script automatically configures keyring to avoid password prompts using:
- Environment variable: `PYTHON_KEYRING_BACKEND=keyring.backends.null.Keyring`
- Config file: `~/.config/python_keyring/keyringrc.cfg`
- Fallback: Plaintext keyring with password `TOC8925!`

## 🛑 Stopping Services

Press `Ctrl+C` in the terminal running the startup script to gracefully stop all services.

## 🎯 Key Features Verified

✅ **LLM Integration**: Local and cloud AI analysis
✅ **Web Interface**: Complete React dashboard
✅ **API Backend**: FastAPI with all OSINT modules
✅ **Investigation Management**: Full workflow support
✅ **Data Visualization**: Charts, maps, and graphs
✅ **Export Functionality**: Multiple format support
✅ **Security Features**: Encryption and anonymity
✅ **One-Command Startup**: Complete automation

---

**Your OSINT Suite is ready with full LLM and analysis capabilities integrated into the web interface!** 🎉
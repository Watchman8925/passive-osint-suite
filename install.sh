#!/bin/bash
# Passive OSINT Suite Installation Script
# For Kali Linux and Debian-based systems

echo "🔧 Installing Passive OSINT Suite..."
echo "=================================="

# Update system
echo "📦 Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python dependencies
echo "🐍 Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv python3-dev

# Install system dependencies
echo "🛠️  Installing system dependencies..."
sudo apt install -y     build-essential     libssl-dev     libffi-dev     libxml2-dev     libxslt1-dev     zlib1g-dev     libgmp-dev     libmpfr-dev     libmpc-dev     git     curl     wget     whois     dnsutils     nmap

# Install Tor for anonymity
echo "🧅 Installing Tor for anonymous operations..."
sudo apt install -y tor torsocks

# Create virtual environment
echo "🌐 Creating virtual environment..."
python3 -m venv osint_env
source osint_env/bin/activate

# Install Python packages
echo "📚 Installing Python packages..."
pip install --upgrade pip setuptools wheel

# Install requirements
pip install -r requirements.txt

# Additional OSINT tools installation
echo "🔍 Installing additional OSINT tools..."

# Install theHarvester
if ! command -v theHarvester &> /dev/null; then
    echo "Installing theHarvester..."
    git clone https://github.com/laramies/theHarvester.git
    cd theHarvester
    pip install -r requirements/base.txt
    cd ..
fi

# Install Sublist3r
if ! command -v sublist3r &> /dev/null; then
    echo "Installing Sublist3r..."
    git clone https://github.com/aboul3la/Sublist3r.git
    cd Sublist3r
    pip install -r requirements.txt
    cd ..
fi

# Install Amass (if not already available)
if ! command -v amass &> /dev/null; then
    echo "Installing Amass..."
    go install -v github.com/OWASP/Amass/v3/...@master 2>/dev/null || echo "Amass installation requires Go"
fi

# Set up directories
echo "📁 Setting up directories..."
mkdir -p logs
mkdir -p output
chmod 755 osint_suite.py

# Create launcher script
echo "🚀 Creating launcher script..."
cat > launch_osint_suite.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source osint_env/bin/activate
python3 osint_suite.py "$@"
EOF

chmod +x launch_osint_suite.sh

# Create desktop entry (if running in GUI environment)
if [ -n "$DISPLAY" ]; then
    echo "🖥️  Creating desktop entry..."
    cat > ~/.local/share/applications/osint-suite.desktop << EOF
[Desktop Entry]
Name=Passive OSINT Suite
Comment=Comprehensive passive reconnaissance and intelligence gathering
Exec=$(pwd)/launch_osint_suite.sh
Icon=utilities-system-monitor
Terminal=true
Type=Application
Categories=Security;Network;
EOF
fi

# Set up API key template
echo "🔑 Setting up API configuration..."
cp config/config.ini config/config.ini.template

echo ""
echo "✅ Installation completed!"
echo ""
echo "📋 Next steps:"
echo "1. Edit config/config.ini with your API keys"
echo "2. Run: ./launch_osint_suite.sh"
echo "3. Or run directly: python3 osint_suite.py"
echo ""
echo "📚 Usage examples:"
echo "  Interactive mode: ./launch_osint_suite.sh"
echo "  Domain analysis: ./launch_osint_suite.sh --domain example.com"
echo "  Email analysis:  ./launch_osint_suite.sh --email test@example.com"
echo "  IP analysis:     ./launch_osint_suite.sh --ip 8.8.8.8"
echo "  Company analysis: ./launch_osint_suite.sh --company 'Example Corp'"
echo ""
echo "🔧 Important:"
echo "- Configure your API keys in config/config.ini"
echo "- Review logs in the logs/ directory"
echo "- Results are saved in the output/ directory"
echo ""
echo "Happy hunting! 🕵️"

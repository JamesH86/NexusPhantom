#!/bin/bash

# NEXUS PHANTOM - Comprehensive Cybersecurity Toolkit Installation
# Installs all required tools for elite cybersecurity operations

set -e

echo "🔥 NEXUS PHANTOM - Elite Cybersecurity Toolkit Installation"
echo "============================================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    print_error "This script is designed for macOS only"
    exit 1
fi

# Check if Homebrew is installed
if ! command -v brew &> /dev/null; then
    print_status "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    print_success "Homebrew already installed"
fi

# Update Homebrew
print_status "Updating Homebrew..."
brew update

# MARK: - Core Development Tools
print_status "Installing core development tools..."
brew install git python3 node npm go rust

# MARK: - Reconnaissance Tools
print_status "Installing reconnaissance tools..."
brew install nmap masscan
brew install subfinder amass assetfinder findomain
brew install gobuster ffuf feroxbuster
brew install dnsrecon dnsutils
brew install whatweb
brew install httpx httprobe

# Install additional recon tools via Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/OWASP/Amass/v3/...@master
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/httprobe@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# MARK: - Vulnerability Assessment Tools
print_status "Installing vulnerability assessment tools..."
brew install nuclei nikto
brew install openvas-scanner
brew install testssl

# Install Nuclei templates
print_status "Installing Nuclei templates..."
nuclei -update-templates

# MARK: - Web Application Security Tools
print_status "Installing web application security tools..."
brew install sqlmap
brew install wpscan
brew install dirb
brew install zaproxy

# Install Burp Suite Community Edition (if not already installed)
if [ ! -d "/Applications/Burp Suite Community Edition.app" ]; then
    print_status "Installing Burp Suite Community Edition..."
    brew install --cask burp-suite
else
    print_success "Burp Suite already installed"
fi

# MARK: - Exploitation Frameworks
print_status "Installing exploitation frameworks..."

# Install Metasploit Framework
if ! command -v msfconsole &> /dev/null; then
    print_status "Installing Metasploit Framework..."
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
    chmod 755 msfinstall
    ./msfinstall
    rm msfinstall
else
    print_success "Metasploit already installed"
fi

# Install Cobalt Strike (if available)
print_warning "Cobalt Strike requires commercial license - skipping automatic installation"

# Install Empire
brew install powershell
git clone https://github.com/EmpireProject/Empire.git /opt/Empire || true

# MARK: - Network Security Tools
print_status "Installing network security tools..."
brew install wireshark
brew install tcpdump
brew install bettercap
brew install ettercap
brew install netcat
brew install socat

# MARK: - Wireless Security Tools
print_status "Installing wireless security tools..."
brew install aircrack-ng
brew install kismet
brew install reaver
brew install hashcat-utils

# MARK: - Password Cracking Tools
print_status "Installing password cracking tools..."
brew install john
brew install hashcat
brew install hydra
brew install crunch

# Download common wordlists
print_status "Setting up wordlists..."
sudo mkdir -p /usr/share/wordlists
cd /tmp
if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
    wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt
    sudo mv rockyou.txt /usr/share/wordlists/
fi

# MARK: - Digital Forensics Tools
print_status "Installing digital forensics tools..."
brew install volatility
brew install binwalk
brew install foremost
brew install ddrescue
brew install sleuthkit

# Install Autopsy (GUI forensics tool)
brew install --cask autopsy

# MARK: - Malware Analysis Tools
print_status "Installing malware analysis tools..."
brew install radare2
brew install yara
brew install clamav
brew install upx

# Install Ghidra (NSA tool)
if ! command -v ghidra &> /dev/null; then
    print_status "Installing Ghidra (NSA Reverse Engineering Suite)..."
    brew install ghidra
else
    print_success "Ghidra already installed"
fi

# Install IDA Free (if available)
print_status "Checking for IDA Pro..."
if [ ! -d "/Applications/IDA Freeware.app" ]; then
    print_warning "IDA Pro not found - download manually from Hex-Rays"
fi

# MARK: - OSINT Tools
print_status "Installing OSINT tools..."
brew install recon-ng
brew install spiderfoot
brew install theharvester

# Install Sherlock for social media OSINT
pip3 install sherlock-project

# Install Shodan CLI
pip3 install shodan

# Install Maltego (if available)
print_status "Checking for Maltego..."
if [ ! -d "/Applications/Maltego.app" ]; then
    print_warning "Maltego not found - download manually from Maltego website"
fi

# MARK: - NSA Public Tools
print_status "Installing NSA public tools..."

# Ghidra is already installed above
print_success "Ghidra (NSA) already configured"

# Install Armitage (Metasploit GUI)
if [ ! -d "/opt/armitage" ]; then
    print_status "Installing Armitage (Metasploit GUI)..."
    git clone https://github.com/rsmudge/armitage.git /opt/armitage
    cd /opt/armitage
    # Build Armitage
    chmod +x package.sh
    ./package.sh || true
    cd -
else
    print_success "Armitage already installed"
fi

# Install Apache Spot (NSA)
if [ ! -d "/opt/apache-spot" ]; then
    print_status "Installing Apache Spot (NSA Network Analysis)..."
    git clone https://github.com/apache/spot.git /opt/apache-spot || true
fi

# Install SIRIUS (NSA) - Video surveillance analysis
if [ ! -d "/opt/sirius" ]; then
    print_status "Installing SIRIUS (NSA Video Analysis)..."
    git clone https://github.com/NationalSecurityAgency/SIRIUS.git /opt/sirius || true
fi

# Install WALKOFF (NSA) - Security orchestration platform
if [ ! -d "/opt/walkoff" ]; then
    print_status "Installing WALKOFF (NSA Security Orchestration)..."
    git clone https://github.com/nsacyber/WALKOFF.git /opt/walkoff || true
fi

# Install Lemongraph (NSA) - Graph database for cybersecurity
if [ ! -d "/opt/lemongraph" ]; then
    print_status "Installing Lemongraph (NSA Graph Database)..."
    git clone https://github.com/NationalSecurityAgency/lemongraph.git /opt/lemongraph || true
fi

# Install GRASSMARLIN (NSA) - Network situational awareness
if [ ! -d "/opt/grassmarlin" ]; then
    print_status "Installing GRASSMARLIN (NSA Network Mapping)..."
    git clone https://github.com/nsacyber/GRASSMARLIN.git /opt/grassmarlin || true
fi

# Install ELITEWOLF (NSA) - Forensic tool
if [ ! -d "/opt/elitewolf" ]; then
    print_status "Installing ELITEWOLF (NSA Forensics)..."
    git clone https://github.com/nsacyber/ELITEWOLF.git /opt/elitewolf || true
fi

# Install BLESS (NSA) - SSH certificate authority
if [ ! -d "/opt/bless" ]; then
    print_status "Installing BLESS (NSA SSH CA)..."
    git clone https://github.com/Netflix/bless.git /opt/bless || true
fi

# Install DEEP-LEARNING-FINGERPRINTING (NSA)
if [ ! -d "/opt/dl-fingerprinting" ]; then
    print_status "Installing Deep Learning Fingerprinting (NSA)..."
    git clone https://github.com/nsacyber/Deep-Learning-Fingerprinting.git /opt/dl-fingerprinting || true
fi

# MARK: - Mobile Security Tools
print_status "Installing mobile security tools..."
brew install frida-tools
pip3 install objection
brew install class-dump
brew install otool

# Install MobSF
if [ ! -d "/opt/mobsf" ]; then
    print_status "Installing Mobile Security Framework (MobSF)..."
    git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git /opt/mobsf
    cd /opt/mobsf
    ./setup.sh
    cd -
fi

# MARK: - Compliance and Audit Tools
print_status "Installing compliance and audit tools..."
brew install lynis
brew install openscap
brew install nessus

# MARK: - Cryptography Tools
print_status "Installing cryptography tools..."
brew install openssl
brew install gnupg
brew install steghide
brew install exiftool

# MARK: - Container Security Tools
print_status "Installing container security tools..."
brew install docker
brew install docker-compose
brew install trivy
brew install grype

# Install Docker security tools
docker pull aquasec/trivy || true
docker pull anchore/grype || true

# MARK: - Cloud Security Tools
print_status "Installing cloud security tools..."
brew install awscli
brew install azure-cli
brew install google-cloud-sdk

# Cloud security scanners
pip3 install prowler
pip3 install scoutsuite
pip3 install cloudsploit

# MARK: - Additional Kali Tools
print_status "Installing additional Kali Linux tools..."
brew install hashid
brew install hash-identifier
brew install trid
brew install pdfcrack
brew install fcrackzip
brew install cewl
brew install crunch

# Social engineering tools
pip3 install social-engineer-toolkit

# MARK: - AI and Machine Learning Tools
print_status "Installing AI/ML tools for cybersecurity..."
pip3 install scikit-learn pandas numpy
pip3 install tensorflow torch
pip3 install transformers
pip3 install langchain

# MARK: - Bug Bounty Specific Tools
print_status "Installing bug bounty specific tools..."
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest

# Install ParamSpider
git clone https://github.com/devanshbatham/ParamSpider.git /opt/paramspider || true

# Install XSStrike
git clone https://github.com/s0md3v/XSStrike.git /opt/xsstrike || true

# MARK: - API Security Tools
print_status "Installing API security tools..."
pip3 install postman-cli
npm install -g newman
pip3 install arjun

# MARK: - Reporting Tools
print_status "Installing reporting tools..."
brew install pandoc
pip3 install reportlab
pip3 install jinja2
npm install -g puppeteer

# MARK: - Python Dependencies for CyberSecAI
print_status "Installing Python dependencies for CyberSecAI integration..."
pip3 install --user requests urllib3 beautifulsoup4
pip3 install --user pymetasploit3
pip3 install --user python-nmap
pip3 install --user shodan
pip3 install --user censys
pip3 install --user virustotal-api
pip3 install --user yara-python

# MARK: - Ollama Setup
print_status "Setting up Ollama for local AI models..."
if ! command -v ollama &> /dev/null; then
    brew install ollama
fi

# Start Ollama service
brew services start ollama

# Download cybersecurity-focused models
print_status "Downloading AI models for cybersecurity..."
ollama pull codellama
ollama pull llama2
ollama pull mistral

# MARK: - Additional NSA Tools and Resources
print_status "Installing additional NSA and government tools..."

# Install YARA (NSA-contributed)
brew install yara

# Install Sigma rules for threat detection
if [ ! -d "/opt/sigma" ]; then
    git clone https://github.com/SigmaHQ/sigma.git /opt/sigma
fi

# Install STIX/TAXII threat intelligence tools
pip3 install stix2 taxii2-client

# MARK: - macOS Specific Security Tools
print_status "Installing macOS specific security tools..."
brew install malwaredetector
brew install knockknock
brew install reikey
brew install oversight

# MARK: - Set Up Tool Configurations
print_status "Configuring tools..."

# Create necessary directories
sudo mkdir -p /opt/nexusphantom/{logs,reports,exploits,wordlists}
sudo chown -R $(whoami):staff /opt/nexusphantom

# Set up Metasploit database
print_status "Initializing Metasploit database..."
msfdb init || true

# Configure Burp Suite for automation
print_status "Configuring Burp Suite for automation..."
mkdir -p ~/BurpSuite/configs

# Create Burp configuration for API access
cat > ~/BurpSuite/configs/nexus_phantom.json << 'EOF'
{
    "proxy": {
        "http": {
            "bind_address": "127.0.0.1",
            "bind_port": 8080,
            "bind_all_interfaces": false
        }
    },
    "spider": {
        "enabled": true,
        "max_depth": 10
    },
    "scanner": {
        "enabled": true,
        "audit_items": {
            "sql_injection": true,
            "xss": true,
            "code_injection": true,
            "path_traversal": true
        }
    }
}
EOF

# MARK: - Environment Setup
print_status "Setting up environment variables..."

# Create environment file for NEXUS PHANTOM
cat > ~/.nexusphantom_env << 'EOF'
# NEXUS PHANTOM Environment Configuration
export NEXUS_PHANTOM_HOME="/Users/$(whoami)/CyberSecAI"
export NEXUS_PHANTOM_TOOLS="/opt/nexusphantom"
export NEXUS_PHANTOM_WORDLISTS="/usr/share/wordlists"
export METASPLOIT_PATH="/opt/metasploit-framework"
export BURP_API_URL="http://127.0.0.1:1337"
export PYTHONPATH="$NEXUS_PHANTOM_HOME:$PYTHONPATH"

# Tool paths
export NMAP_PATH="/usr/local/bin/nmap"
export NUCLEI_PATH="/usr/local/bin/nuclei"
export SUBFINDER_PATH="/usr/local/bin/subfinder"
export AMASS_PATH="/usr/local/bin/amass"
export SQLMAP_PATH="/usr/local/bin/sqlmap"
export JOHN_PATH="/usr/local/bin/john"
export HASHCAT_PATH="/usr/local/bin/hashcat"
export GHIDRA_PATH="/usr/local/bin/ghidra"
export RADARE2_PATH="/usr/local/bin/radare2"

# API Keys (set these manually)
# export SHODAN_API_KEY="your_shodan_api_key"
# export VIRUSTOTAL_API_KEY="your_virustotal_api_key"
# export CENSYS_API_ID="your_censys_id"
# export CENSYS_API_SECRET="your_censys_secret"
EOF

# Add to shell profile
if ! grep -q "nexusphantom_env" ~/.zshrc; then
    echo "source ~/.nexusphantom_env" >> ~/.zshrc
    print_success "Added NEXUS PHANTOM environment to ~/.zshrc"
fi

# MARK: - Create Tool Verification Script
print_status "Creating tool verification script..."

cat > /opt/nexusphantom/verify_tools.py << 'EOF'
#!/usr/bin/env python3
"""
NEXUS PHANTOM Tool Verification Script
Verifies all cybersecurity tools are properly installed
"""

import subprocess
import os
import sys
from pathlib import Path

def check_tool(command, tool_name):
    """Check if a tool is installed and accessible"""
    try:
        result = subprocess.run([command, '--version'], 
                              capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            print(f"✅ {tool_name}: Available")
            return True
        else:
            print(f"❌ {tool_name}: Not working properly")
            return False
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
        print(f"❌ {tool_name}: Not found")
        return False

def check_application(app_path, app_name):
    """Check if a macOS application is installed"""
    if os.path.exists(app_path):
        print(f"✅ {app_name}: Installed")
        return True
    else:
        print(f"❌ {app_name}: Not found")
        return False

def main():
    print("🔍 NEXUS PHANTOM Tool Verification")
    print("=" * 50)
    
    tools_to_check = [
        ('/usr/local/bin/nmap', 'Nmap'),
        ('/usr/local/bin/nuclei', 'Nuclei'),
        ('/usr/local/bin/subfinder', 'Subfinder'),
        ('/usr/local/bin/amass', 'Amass'),
        ('/usr/local/bin/sqlmap', 'SQLMap'),
        ('/usr/local/bin/nikto', 'Nikto'),
        ('/usr/local/bin/gobuster', 'Gobuster'),
        ('/usr/local/bin/ffuf', 'FFUF'),
        ('/usr/local/bin/john', 'John the Ripper'),
        ('/usr/local/bin/hashcat', 'Hashcat'),
        ('/usr/local/bin/hydra', 'Hydra'),
        ('/usr/local/bin/msfconsole', 'Metasploit'),
        ('/usr/local/bin/ghidra', 'Ghidra'),
        ('/usr/local/bin/radare2', 'Radare2'),
        ('/usr/local/bin/bettercap', 'Bettercap'),
        ('/usr/local/bin/aircrack-ng', 'Aircrack-ng'),
        ('/usr/local/bin/recon-ng', 'Recon-ng'),
        ('/usr/local/bin/frida', 'Frida'),
        ('/usr/local/bin/lynis', 'Lynis'),
        ('/usr/local/bin/whatweb', 'WhatWeb'),
        ('/usr/local/bin/wpscan', 'WPScan'),
        ('/usr/local/bin/ollama', 'Ollama')
    ]
    
    applications_to_check = [
        ('/Applications/Burp Suite Community Edition.app', 'Burp Suite'),
        ('/Applications/Wireshark.app', 'Wireshark'),
        ('/Applications/Ghidra.app', 'Ghidra GUI'),
        ('/Applications/Maltego.app', 'Maltego'),
        ('/Applications/IDA Freeware.app', 'IDA Pro Freeware')
    ]
    
    print("\\n📦 Command Line Tools:")
    available_tools = 0
    for tool_path, tool_name in tools_to_check:
        if check_tool(tool_path, tool_name):
            available_tools += 1
    
    print("\\n📱 macOS Applications:")
    available_apps = 0
    for app_path, app_name in applications_to_check:
        if check_application(app_path, app_name):
            available_apps += 1
    
    total_tools = len(tools_to_check)
    total_apps = len(applications_to_check)
    
    print("\\n" + "=" * 50)
    print(f"📊 Summary:")
    print(f"   Command Line Tools: {available_tools}/{total_tools}")
    print(f"   macOS Applications: {available_apps}/{total_apps}")
    print(f"   Total Coverage: {available_tools + available_apps}/{total_tools + total_apps}")
    
    if available_tools + available_apps == total_tools + total_apps:
        print("\\n🔥 NEXUS PHANTOM toolkit is fully operational!")
        return 0
    else:
        print("\\n⚠️  Some tools are missing. Run installation script again.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
EOF

chmod +x /opt/nexusphantom/verify_tools.py

# MARK: - Install Additional Python Packages
print_status "Installing additional Python packages..."
pip3 install --user pymetasploit3 python-nmap shodan censys virustotal-api
pip3 install --user beautifulsoup4 requests urllib3 aiohttp
pip3 install --user scapy netfilterqueue
pip3 install --user yara-python python-magic
pip3 install --user elasticsearch redis pymongo
pip3 install --user flask fastapi uvicorn
pip3 install --user rich colorama termcolor

# MARK: - AI Model Dependencies
print_status "Installing AI model dependencies..."
pip3 install --user openai anthropic
pip3 install --user langchain langchain-community
pip3 install --user transformers torch torchvision
pip3 install --user sentence-transformers
pip3 install --user chromadb faiss-cpu

# MARK: - Create Swift Package Dependencies File
print_status "Creating Swift package dependencies..."
mkdir -p /Users/$(whoami)/CyberSecAI/NexusPhantom

cat > /Users/$(whoami)/CyberSecAI/NexusPhantom/Package.swift << 'EOF'
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "NexusPhantom",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "NexusPhantom", targets: ["NexusPhantom"]),
        .library(name: "NexusPhantomCore", targets: ["NexusPhantomCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/grpc/grpc-swift.git", from: "1.21.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.0.0"),
        .package(url: "https://github.com/vapor/redis.git", from: "4.0.0")
    ],
    targets: [
        .executableTarget(
            name: "NexusPhantom",
            dependencies: [
                "NexusPhantomCore",
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "ArgumentParser", package: "swift-argument-parser")
            ]
        ),
        .target(
            name: "NexusPhantomCore",
            dependencies: [
                .product(name: "GRPC", package: "grpc-swift"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Redis", package: "redis")
            ]
        ),
        .testTarget(
            name: "NexusPhantomTests",
            dependencies: ["NexusPhantom", "NexusPhantomCore"]
        )
    ]
)
EOF

# MARK: - Final Setup and Verification
print_status "Running final verification..."
python3 /opt/nexusphantom/verify_tools.py

# Create desktop shortcut for NEXUS PHANTOM
print_status "Creating desktop shortcuts..."
cat > ~/Desktop/NexusPhantom.command << 'EOF'
#!/bin/bash
cd /Users/$(whoami)/CyberSecAI/NexusPhantom
swift run NexusPhantom
EOF
chmod +x ~/Desktop/NexusPhantom.command

# MARK: - Security Permissions Setup
print_status "Setting up security permissions..."
print_warning "Some tools require elevated privileges. Configure sudo access as needed."
print_warning "For network monitoring: sudo chown root:wheel /usr/local/bin/bettercap"
print_warning "For packet capture: sudo chmod +s /usr/local/bin/tcpdump"

# MARK: - Completion Message
echo ""
echo -e "${PURPLE}🔥 NEXUS PHANTOM INSTALLATION COMPLETE! 🔥${NC}"
echo -e "${CYAN}=============================================${NC}"
echo ""
echo -e "${GREEN}✅ Installation Summary:${NC}"
echo "   • All cybersecurity tools installed"
echo "   • NSA public tools configured"
echo "   • AI models downloaded"
echo "   • Python CyberSecAI integration ready"
echo "   • Bug bounty automation toolkit ready"
echo "   • Real-time threat detection capable"
echo ""
echo -e "${YELLOW}🎯 Next Steps:${NC}"
echo "   1. Configure API keys in ~/.nexusphantom_env"
echo "   2. Run: swift run NexusPhantom"
echo "   3. Test voice commands: 'Hey NEXUS, start reconnaissance'"
echo "   4. Launch bug bounty automation on your target"
echo ""
echo -e "${RED}⚠️  Important:${NC}"
echo "   • Only use on authorized targets"
echo "   • Ensure proper legal authorization"
echo "   • Follow responsible disclosure practices"
echo ""
echo -e "${PURPLE}🚀 Ready to make money with elite cybersecurity operations!${NC}"
echo ""

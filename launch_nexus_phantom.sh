#!/bin/bash

# NEXUS PHANTOM Launch Script
# Comprehensive setup and launch for elite cybersecurity AI platform

set -e

# Colors for beautiful output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Function to print styled headers
print_header() {
    echo -e "${PURPLE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                      NEXUS PHANTOM                          ║"
    echo "║              Elite Cybersecurity AI Platform                ║"
    echo "║                                                              ║"
    echo "║    Network EXploit Unified System                           ║"
    echo "║    Penetration & Hacking Adversarial Network Tool           ║"
    echo "║    for Offensive Management                                  ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_status() {
    echo -e "${GREEN}[NEXUS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_cyber() {
    echo -e "${CYAN}[CYBER]${NC} $1"
}

# ASCII Art for NEXUS PHANTOM
print_ascii_art() {
    echo -e "${PURPLE}"
    cat << 'EOF'
    ███╗   ██╗███████╗██╗  ██╗██╗   ██╗███████╗
    ████╗  ██║██╔════╝╚██╗██╔╝██║   ██║██╔════╝
    ██╔██╗ ██║█████╗   ╚███╔╝ ██║   ██║███████╗
    ██║╚██╗██║██╔══╝   ██╔██╗ ██║   ██║╚════██║
    ██║ ╚████║███████╗██╔╝ ██╗╚██████╔╝███████║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
    
    ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
    ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
    ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
    ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
    ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
EOF
    echo -e "${NC}"
}

# Main function
main() {
    clear
    print_ascii_art
    print_header
    
    echo -e "${CYAN}Initializing NEXUS PHANTOM...${NC}"
    echo ""
    
    # Check if we're in the right directory
    if [[ ! -d "/Users/$(whoami)/CyberSecAI" ]]; then
        print_error "CyberSecAI directory not found. Please ensure you're in the correct location."
        exit 1
    fi
    
    cd "/Users/$(whoami)/CyberSecAI"
    
    # Step 1: Environment Check
    print_status "Checking environment..."
    check_environment
    
    # Step 2: Install tools if needed
    print_status "Checking cybersecurity toolkit..."
    check_and_install_tools
    
    # Step 3: Setup Swift project
    print_status "Setting up Swift project..."
    setup_swift_project
    
    # Step 4: Initialize AI models
    print_status "Initializing AI models..."
    initialize_ai_models
    
    # Step 5: Start services
    print_status "Starting services..."
    start_services
    
    # Step 6: Launch NEXUS PHANTOM
    print_status "Launching NEXUS PHANTOM..."
    launch_application
}

check_environment() {
    # Check macOS version
    MACOS_VERSION=$(sw_vers -productVersion)
    print_cyber "macOS Version: $MACOS_VERSION"
    
    # Check Xcode command line tools
    if ! xcode-select -p &> /dev/null; then
        print_warning "Installing Xcode command line tools..."
        xcode-select --install
    else
        print_cyber "Xcode tools: ✅"
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        print_cyber "Python: ✅ $PYTHON_VERSION"
    else
        print_error "Python 3 not found. Please install Python 3.8+"
        exit 1
    fi
    
    # Check Swift
    if command -v swift &> /dev/null; then
        SWIFT_VERSION=$(swift --version | head -n1)
        print_cyber "Swift: ✅ $SWIFT_VERSION"
    else
        print_error "Swift not found. Please install Xcode or Swift toolchain"
        exit 1
    fi
    
    # Check Ollama
    if command -v ollama &> /dev/null; then
        print_cyber "Ollama: ✅ Available"
    else
        print_warning "Ollama not found. Installing..."
        brew install ollama
    fi
}

check_and_install_tools() {
    # Check if our verification script exists
    if [[ -f "/opt/nexusphantom/verify_tools.py" ]]; then
        print_cyber "Running tool verification..."
        python3 /opt/nexusphantom/verify_tools.py
    else
        print_warning "Tools not installed. Running full installation..."
        if [[ -f "NexusPhantom/install_tools.sh" ]]; then
            chmod +x NexusPhantom/install_tools.sh
            ./NexusPhantom/install_tools.sh
        else
            print_error "Installation script not found!"
            exit 1
        fi
    fi
}

setup_swift_project() {
    cd NexusPhantom
    
    # Check if Package.swift exists
    if [[ ! -f "Package.swift" ]]; then
        print_error "Package.swift not found. Project structure incomplete."
        exit 1
    fi
    
    print_cyber "Resolving Swift dependencies..."
    swift package resolve
    
    print_cyber "Building NEXUS PHANTOM..."
    swift build -c release
    
    cd ..
}

initialize_ai_models() {
    # Start Ollama service
    if ! pgrep -x "ollama" > /dev/null; then
        print_cyber "Starting Ollama service..."
        brew services start ollama
        sleep 5
    fi
    
    # Download essential models if not present
    print_cyber "Checking AI models..."
    if ! ollama list | grep -q "codellama"; then
        print_cyber "Downloading CodeLlama for code analysis..."
        ollama pull codellama:7b
    fi
    
    if ! ollama list | grep -q "llama2"; then
        print_cyber "Downloading Llama2 for general AI tasks..."
        ollama pull llama2:7b
    fi
    
    # Verify Python CyberSecAI backend
    if [[ -f "cybersec_ai.py" ]]; then
        print_cyber "Testing CyberSecAI backend..."
        python3 cybersec_ai.py --status
    fi
}

start_services() {
    # Start Redis for real-time data streaming (if available)
    if command -v redis-server &> /dev/null; then
        if ! pgrep -x "redis-server" > /dev/null; then
            print_cyber "Starting Redis server..."
            redis-server &
        fi
    fi
    
    # Start Metasploit RPC (if available)
    if command -v msfconsole &> /dev/null; then
        print_cyber "Checking Metasploit RPC..."
        # Don't auto-start MSF RPC - it should be started on-demand
    fi
    
    # Ensure proper permissions for network tools
    print_cyber "Setting up tool permissions..."
    setup_tool_permissions
}

setup_tool_permissions() {
    # Set up permissions for network monitoring tools
    if [[ -f "/usr/local/bin/bettercap" ]]; then
        sudo chown root:wheel /usr/local/bin/bettercap 2>/dev/null || true
        sudo chmod +s /usr/local/bin/bettercap 2>/dev/null || true
    fi
    
    if [[ -f "/usr/sbin/tcpdump" ]]; then
        sudo chmod +s /usr/sbin/tcpdump 2>/dev/null || true
    fi
    
    # Create necessary directories
    mkdir -p ~/NexusPhantom/{logs,reports,exploits,temp}
    mkdir -p /tmp/{exploits,reports,scans}
}

launch_application() {
    print_header
    echo -e "${GREEN}${BOLD}🔥 NEXUS PHANTOM READY FOR CYBER OPERATIONS 🔥${NC}"
    echo ""
    echo -e "${CYAN}Available Launch Options:${NC}"
    echo -e "${YELLOW}1. GUI Application (Recommended)${NC}"
    echo -e "${YELLOW}2. Command Line Interface${NC}"
    echo -e "${YELLOW}3. Voice-Only Mode${NC}"
    echo -e "${YELLOW}4. Background Service${NC}"
    echo ""
    read -p "Select launch mode (1-4): " choice
    
    case $choice in
        1)
            print_cyber "Launching GUI Application..."
            cd NexusPhantom
            swift run NexusPhantom --gui
            ;;
        2)
            print_cyber "Launching CLI Mode..."
            python3 cybersec_ai.py --interactive
            ;;
        3)
            print_cyber "Launching Voice-Only Mode..."
            cd NexusPhantom
            swift run NexusPhantom --voice-only
            ;;
        4)
            print_cyber "Starting Background Service..."
            cd NexusPhantom
            nohup swift run NexusPhantom --daemon > /tmp/nexus_phantom.log 2>&1 &
            print_cyber "NEXUS PHANTOM running in background. Check /tmp/nexus_phantom.log for logs."
            ;;
        *)
            print_cyber "Invalid option. Launching GUI application..."
            cd NexusPhantom
            swift run NexusPhantom --gui
            ;;
    esac
}

# Quick start menu
show_quick_start() {
    echo ""
    echo -e "${PURPLE}${BOLD}🚀 NEXUS PHANTOM QUICK START MENU 🚀${NC}"
    echo ""
    echo -e "${GREEN}Voice Commands to try:${NC}"
    echo -e "${YELLOW}• 'Hey NEXUS, start reconnaissance on apple.com'${NC}"
    echo -e "${YELLOW}• 'PHANTOM, launch bug bounty mode'${NC}"
    echo -e "${YELLOW}• 'Start threat detection'${NC}"
    echo -e "${YELLOW}• 'Run full security scan'${NC}"
    echo -e "${YELLOW}• 'Execute Burp Suite'${NC}"
    echo -e "${YELLOW}• 'Activate Metasploit framework'${NC}"
    echo ""
    echo -e "${GREEN}GUI Navigation:${NC}"
    echo -e "${YELLOW}• Dashboard: Real-time threat monitoring${NC}"
    echo -e "${YELLOW}• Bug Bounty: Autonomous hunting mode${NC}"
    echo -e "${YELLOW}• Reconnaissance: Advanced target enumeration${NC}"
    echo -e "${YELLOW}• Exploitation: AI-powered exploit development${NC}"
    echo -e "${YELLOW}• Reports: Professional security reporting${NC}"
    echo ""
    echo -e "${RED}${BOLD}⚠️  IMPORTANT SECURITY NOTICE ⚠️${NC}"
    echo -e "${RED}• Only use on authorized targets${NC}"
    echo -e "${RED}• Ensure proper legal authorization${NC}"
    echo -e "${RED}• Follow responsible disclosure practices${NC}"
    echo ""
}

# Installation check
if [[ "$1" == "--install-only" ]]; then
    print_header
    print_status "Running full installation of NEXUS PHANTOM..."
    
    # Run the installation script
    if [[ -f "NexusPhantom/install_tools.sh" ]]; then
        chmod +x NexusPhantom/install_tools.sh
        ./NexusPhantom/install_tools.sh
    else
        print_error "Installation script not found!"
        exit 1
    fi
    
    print_success "Installation complete! Run without --install-only to launch."
    exit 0
fi

# Quick launch for experienced users
if [[ "$1" == "--quick" ]]; then
    print_header
    print_cyber "🚀 Quick launching NEXUS PHANTOM..."
    cd NexusPhantom
    swift run NexusPhantom
    exit 0
fi

# Voice test mode
if [[ "$1" == "--voice-test" ]]; then
    print_header
    print_cyber "🎤 Testing voice capabilities..."
    cd NexusPhantom
    swift run NexusPhantom --test-voice
    exit 0
fi

# Show help
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    print_header
    echo -e "${CYAN}NEXUS PHANTOM Launch Options:${NC}"
    echo ""
    echo -e "${YELLOW}./launch_nexus_phantom.sh${NC}          - Full interactive setup and launch"
    echo -e "${YELLOW}./launch_nexus_phantom.sh --quick${NC}   - Quick launch (skip checks)"
    echo -e "${YELLOW}./launch_nexus_phantom.sh --install-only${NC} - Install tools only"
    echo -e "${YELLOW}./launch_nexus_phantom.sh --voice-test${NC} - Test voice capabilities"
    echo -e "${YELLOW}./launch_nexus_phantom.sh --help${NC}    - Show this help"
    echo ""
    echo -e "${GREEN}Environment Variables:${NC}"
    echo -e "${YELLOW}NEXUS_PHANTOM_HOME${NC}     - Home directory"
    echo -e "${YELLOW}NEXUS_PHANTOM_TOOLS${NC}    - Tools directory"
    echo -e "${YELLOW}NEXUS_PHANTOM_API_KEYS${NC} - API keys file"
    echo ""
    exit 0
fi

# Default: Full interactive launch
main

# Show quick start guide
show_quick_start

print_header
echo -e "${GREEN}${BOLD}🎯 NEXUS PHANTOM is now operational and ready for elite cybersecurity operations!${NC}"
echo -e "${PURPLE}Make money, stay legal, hack responsibly. 🚀${NC}"
echo ""

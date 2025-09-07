#!/bin/bash
# Self-test script for Apple Bug Bounty Research Environment

echo "🧪 Apple Bug Bounty Research Environment Self-Test"
echo "=================================================="

PASS_COUNT=0
FAIL_COUNT=0

# Function to test tool availability
test_tool() {
    local tool_name=$1
    local test_cmd=$2
    
    echo -n "Testing $tool_name... "
    if eval "$test_cmd" >/dev/null 2>&1; then
        echo "✅ PASS"
        ((PASS_COUNT++))
    else
        echo "❌ FAIL"
        ((FAIL_COUNT++))
    fi
}

# Test core tools
echo "--- Core Tools ---"
test_tool "radare2" "radare2 -v"
test_tool "frida" "frida --version"
test_tool "python3" "python3 --version"
test_tool "lldb" "lldb --version"
test_tool "nmap" "nmap --version"
test_tool "wireshark" "tshark --version"

# Test Python packages (in venv)
echo "--- Python Security Packages ---"
source apple_bounty_research/venv/bin/activate 2>/dev/null || echo "Warning: Virtual environment not found"
test_tool "frida-tools" "python3 -c 'import frida'"
test_tool "objection" "python3 -c 'import objection'"
test_tool "cryptography" "python3 -c 'import cryptography'"
test_tool "pwntools" "python3 -c 'import pwn'"
test_tool "capstone" "python3 -c 'import capstone'"

# Test custom scripts
echo "--- Custom Scripts ---"
test_tool "enum_macos.sh" "test -x apple_bounty_research/tools/enum_macos.sh"
test_tool "test_sandbox.py" "test -x apple_bounty_research/tools/test_sandbox.py"
test_tool "nexus_phantom_integration.py" "test -x apple_bounty_research/nexus_phantom_integration.py"

# Test baseline data
echo "--- Baseline Data ---"
test_tool "enumeration baseline" "test -f apple_bounty_research/baseline/enumeration.txt"
test_tool "sandbox results" "test -f apple_bounty_research/baseline/sandbox_results.txt"
test_tool "baseline archive" "test -f apple_bounty_research/baseline.tar.gz"
test_tool "baseline hash" "test -f apple_bounty_research/baseline.sha256"

# Test directories
echo "--- Directory Structure ---"
test_tool "tools directory" "test -d apple_bounty_research/tools"
test_tool "reports directory" "test -d apple_bounty_research/reports"
test_tool "evidence directory" "test -d apple_bounty_research/evidence"
test_tool "logs directory" "test -d apple_bounty_research/logs"

echo "=================================================="
echo "Self-Test Results:"
echo "  ✅ PASSED: $PASS_COUNT"
echo "  ❌ FAILED: $FAIL_COUNT"

if [ $FAIL_COUNT -eq 0 ]; then
    echo "🎉 All tests passed! Environment is ready for Apple bug bounty research."
    exit 0
else
    echo "⚠️  Some tests failed. Please review and fix issues before proceeding."
    exit 1
fi

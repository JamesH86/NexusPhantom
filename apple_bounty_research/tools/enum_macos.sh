#!/bin/bash
# macOS System Enumeration for Security Research

echo "=== macOS Security Research Enumeration ==="
echo "Timestamp: $(date)"
echo

# System information
echo "--- System Information ---"
system_profiler SPHardwareDataType SPSoftwareDataType | head -20

# Security features status
echo "--- Security Features ---"
echo "System Integrity Protection: $(csrutil status)"
echo "Secure Boot: $(nvram 94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy 2>/dev/null || echo 'Not available')"

# Running services
echo "--- Running Services ---"
launchctl list | grep -E '(com\.apple\.|system)' | head -20

# Network services
echo "--- Network Services ---"
netstat -an | grep LISTEN | head -10

# File permissions on critical directories
echo "--- Critical Directory Permissions ---"
ls -la /System/Library/LaunchDaemons/ | head -10
ls -la /Library/LaunchDaemons/ | head -10

# Installed applications with elevated permissions
echo "--- Applications with Elevated Permissions ---"
find /Applications -name "*.app" -perm +4000 2>/dev/null || echo "None found"

echo "=== Enumeration Complete ==="

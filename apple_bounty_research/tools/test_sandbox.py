#!/usr/bin/env python3
"""
macOS Sandbox Testing Script for Apple Bug Bounty Research
Tests various sandbox escape techniques
"""

import os
import sys
import subprocess
import tempfile

def test_file_access():
    """Test file system access boundaries"""
    print("[+] Testing file system access...")
    
    test_paths = [
        '/etc/passwd',
        '/System/Library/Frameworks/',
        '/Users/',
        '~/Library/Keychains/',
        '/private/var/db/'
    ]
    
    for path in test_paths:
        try:
            expanded_path = os.path.expanduser(path)
            if os.path.exists(expanded_path):
                readable = os.access(expanded_path, os.R_OK)
                writable = os.access(expanded_path, os.W_OK)
                print(f"  {path}: Read={readable}, Write={writable}")
        except Exception as e:
            print(f"  {path}: Error - {e}")

def test_network_access():
    """Test network access capabilities"""
    print("[+] Testing network access...")
    
    try:
        result = subprocess.run(['ping', '-c', '1', '8.8.8.8'], 
                              capture_output=True, timeout=5)
        print(f"  Network ping: {'Success' if result.returncode == 0 else 'Failed'}")
    except Exception as e:
        print(f"  Network ping: Error - {e}")

def test_process_access():
    """Test process access capabilities"""
    print("[+] Testing process access...")
    
    try:
        result = subprocess.run(['ps', 'aux'], capture_output=True)
        lines = len(result.stdout.decode().split('\n'))
        print(f"  Process list access: {lines} processes visible")
    except Exception as e:
        print(f"  Process list access: Error - {e}")

def main():
    print("=== macOS Sandbox Testing ===")
    print(f"Running as: {os.getuid()}:{os.getgid()}")
    print(f"Current directory: {os.getcwd()}")
    print()
    
    test_file_access()
    print()
    test_network_access()
    print()
    test_process_access()
    
    print("\n=== Testing Complete ===")

if __name__ == "__main__":
    main()

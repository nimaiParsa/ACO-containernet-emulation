#!/bin/bash

# Usage: ./discover_network.sh <target_ip>
# Example: ./discover_network.sh 10.0.1.2

TARGET_IP="$1"

if [ -z "$TARGET_IP" ]; then
    echo "[!] Usage: $0 <target_ip>"
    exit 1
fi

echo "[*] Running Nmap service discovery on $TARGET_IP..."

# Run a TCP SYN scan on common ports with service version detection
nmap -sS -sV -T4 --open "$TARGET_IP"

echo "[*] Service discovery completed."

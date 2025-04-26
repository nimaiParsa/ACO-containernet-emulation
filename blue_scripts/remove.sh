#!/bin/bash

# Remove Script for Blue Agent
# Terminates all suspicious connections (e.g., reverse shell connections)

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <host-ip>"
    exit 1
fi

HOST_IP=$1
LOG_FILE="/home/hacker/blue_scripts/log/blue_agent_remove_$HOST_IP.log"


mkdir -p "$(dirname "$LOG_FILE")"

> "$LOG_FILE"

# Function to terminate suspicious connections
terminate_suspicious_connections() {
    local host=$1
    echo "[*] Starting removal process for host: $host" >> "$LOG_FILE"

    # Get a list of active connections
    sshpass -p "root" ssh -o StrictHostKeyChecking=no root@"$host" "netstat -antp | grep ESTABLISHED" > /tmp/connections.txt 2>/dev/null

    if [ ! -s /tmp/connections.txt ]; then
        echo "[!] No active connections found on $host" >> "$LOG_FILE"
        return
    fi

    echo "[*] Active connections on $host:" >> "$LOG_FILE"
    cat /tmp/connections.txt >> "$LOG_FILE"

    # Parse and terminate suspicious connections
    while read -r line; do
        local src_ip=$(echo "$line" | awk '{print $5}' | cut -d':' -f1)
        local pid=$(echo "$line" | awk '{print $7}' | cut -d'/' -f1)

        # Exclude connections to known safe IPs (e.g., internal services or trusted hosts)
        if [[ "$src_ip" != "127.0.0.1" && "$src_ip" != "$host" ]]; then
            echo "[*] Terminating connection from $src_ip with PID $pid" >> "$LOG_FILE"

            sshpass -p "root" ssh -o StrictHostKeyChecking=no root@"$host" "kill -9 $pid" 2>/dev/null

            if [ $? -eq 0 ]; then
                echo "[+] Successfully terminated connection from $src_ip (PID: $pid)" >> "$LOG_FILE"
            else
                echo "[-] Failed to terminate connection from $src_ip (PID: $pid)" >> "$LOG_FILE"
            fi
        fi
    done < /tmp/connections.txt

    echo "[*] Removal process completed for host: $host" >> "$LOG_FILE"
}

# Run the removal process
terminate_suspicious_connections "$HOST_IP"

# Summary of results
echo "Removal process completed for host $HOST_IP. Results saved in $LOG_FILE."

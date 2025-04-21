#!/bin/bash


# list of IP addresses to monitor
HOSTS=("10.0.0.1" "10.0.0.2" "10.0.0.3")

# Log file for flagged malicious activity
LOG_FILE="/home/hacker/blue_scripts/blue_agent_monitor.log"

# Function to scan a host for suspicious files and connections
scan_host() {
    local host=$1
    echo "[*] Monitoring host: $host" >> "$LOG_FILE"

    # Check for new files in /tmp (Linux)
    sshpass -p "root" ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no root@"$host" "find /tmp -type f" > tmp_files.txt 2>/dev/null

    while read -r file; do
        echo "[!] New file detected: $file" >> "$LOG_FILE"
    done < tmp_files.txt

    # Check for suspicious network connections and log new ones
    echo "[*] Network connections on $host:" >> "$LOG_FILE"
    sshpass -p "root" ssh -o StrictHostKeyChecking=no -o PubkeyAuthentication=no root@"$host" "netstat -antp | grep -E 'ESTABLISHED|LISTEN'" >> "$LOG_FILE" 2>/dev/null

    echo "[*] Monitoring completed for host: $host" >> "$LOG_FILE"
}

# Main monitoring loop
> "$LOG_FILE"  # Clear the log file
for host in "${HOSTS[@]}"; do
    scan_host "$host"
done

# Summary of results
echo "Monitoring completed for all hosts. Results saved in $LOG_FILE."

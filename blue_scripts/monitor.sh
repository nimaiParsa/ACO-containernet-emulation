#!/bin/bash

# Monitor Script for Blue Agent
# Collects information about flagged malicious activity on all hosts

# Hard-coded list of IP addresses to monitor
HOSTS=("10.0.0.1", "10.0.0.2", "10.0.0.3")

# Log file for flagged malicious activity
LOG_FILE="/home/hacker/blue_scripts/blue_agent_monitor.log"

# Function to calculate file entropy (density)
calculate_density() {
    local file=$1
    if [ ! -f "$file" ]; then
        echo "0"
        return
    fi

    # Calculate entropy (density) using hexdump and awk
    hexdump -v -e '/1 "%02X\n"' "$file" | \
    awk '{count[$1]++} END {for (i in count) {p = count[i] / NR; entropy += -p * log(p) / log(2)}; print entropy}'
}

# Function to scan a host for malicious activity
scan_host() {
    local host=$1
    echo "[*] Monitoring host: $host" >> "$LOG_FILE"

    # Check for malicious files in /tmp (Linux) or C:\\temp\\ (Windows)
    ssh "$host" "find /tmp -type f" > tmp_files.txt 2>/dev/null

    while read -r file; do
        density=$(ssh "$host" "$(declare -f calculate_density); calculate_density '$file'")

        if (( $(echo "$density > 0.9" | bc -l) )); then
            echo "[!] Malicious file detected: $file (Density: $density)" >> "$LOG_FILE"
        fi
    done < tmp_files.txt

    # Check for suspicious network connections
    ssh "$host" "netstat -antp | grep -E 'ESTABLISHED|LISTEN'" >> "$LOG_FILE" 2>/dev/null

    echo "[*] Monitoring completed for host: $host" >> "$LOG_FILE"
}

# Main monitoring loop
> "$LOG_FILE"  # Clear the log file
for host in "${HOSTS[@]}"; do
    scan_host "$host"
done

# Summary of results
echo "Monitoring completed for all hosts. Results saved in $LOG_FILE."

#!/bin/bash

# Analyse Script for Blue Agent
# Collects detailed information on a specific host to identify red agent activity

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <hostname>"
    exit 1
fi

HOSTNAME=$1
LOG_FILE="/var/log/blue_agent_analyse_$HOSTNAME.log"
TMP_DIR="/tmp/blue_agent_analyse"

# Ensure temporary directory exists
mkdir -p "$TMP_DIR"

# Clear the log file
> "$LOG_FILE"

# Function to calculate file density (entropy)
calculate_density() {
    local file=$1
    if [ ! -f "$file" ]; then
        echo "0"
        return
    fi

    hexdump -v -e '/1 "%02X\n"' "$file" | \
    awk '{count[$1]++} END {for (i in count) {p = count[i] / NR; entropy += -p * log(p) / log(2)}; print entropy}'
}

# Function to run SigCheck (placeholder)
run_sigcheck() {
    local file=$1
    # Placeholder: Simulate signature verification (real implementation depends on tools available)
    # Example: Check if the file is signed and trusted
    if [[ "$file" == *"unsigned"* ]]; then
        echo "Unsigned"
    else
        echo "Signed"
    fi
}

# Function to analyse a host
analyse_host() {
    local host=$1
    echo "[*] Analysing host: $host" >> "$LOG_FILE"

    # Fetch list of files in temporary directory
    ssh "$host" "find /tmp -type f" > "$TMP_DIR/files_list.txt" 2>/dev/null

    while read -r file; do
        # Fetch the file to the local machine for analysis
        scp "$host:$file" "$TMP_DIR/" 2>/dev/null

        local_file="$TMP_DIR/$(basename "$file")"

        # Calculate density (entropy)
        density=$(calculate_density "$local_file")

        # Run SigCheck (placeholder)
        signature=$(run_sigcheck "$local_file")

        echo "File: $file" >> "$LOG_FILE"
        echo "  Density: $density" >> "$LOG_FILE"
        echo "  Signature: $signature" >> "$LOG_FILE"

        # Flag file as suspicious if density > 0.9 or unsigned
        if (( $(echo "$density > 0.9" | bc -l) )) || [ "$signature" == "Unsigned" ]; then
            echo "  Status: Suspicious" >> "$LOG_FILE"
        else
            echo "  Status: Clean" >> "$LOG_FILE"
        fi

        # Clean up local copy of the file
        rm -f "$local_file"
    done < "$TMP_DIR/files_list.txt"

    echo "[*] Analysis completed for host: $host" >> "$LOG_FILE"
}

# Perform analysis on the specified host
analyse_host "$HOSTNAME"

# Summary of results
echo "Analysis completed for host $HOSTNAME. Results saved in $LOG_FILE."

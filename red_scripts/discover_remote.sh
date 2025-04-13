#!/bin/bash
SUBNET=$1
echo "[*] Scanning subnet: $SUBNET.0/24"
for i in $(seq 1 254); do
    ping -c 1 -W 1 $SUBNET.$i > /dev/null 2>&1 && echo "Host up: $SUBNET.$i" &
done
wait
echo "[*] Scanning completed."
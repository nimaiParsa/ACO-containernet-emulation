#!/bin/bash
echo "[*] Attempting to impact service on this host..."
pkill -f http.server
if [ $? -eq 0 ]; then
    echo "[!] Service successfully disrupted"
else
    echo "[!] No running service found to impact"
fi

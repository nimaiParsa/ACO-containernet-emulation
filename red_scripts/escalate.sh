#!/bin/bash

# Check sudo privileges
echo "[*] Checking sudo privileges..."
sudo -l

# Attempt to escalate to root
echo "[*] Trying privilege escalation via sudo..."
sudo bash

# If successful, print whoami
echo "[*] Who am I now?"
whoami

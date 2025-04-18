#!/bin/bash

# Start SSH in the background
service ssh start

# Start HTTP server in the background
python3 -m http.server 8080 --directory / &

# Prevent container from exiting by keeping a foreground process
# tail -f /dev/null

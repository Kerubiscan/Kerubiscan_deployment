#!/bin/bash

echo "=========================================="
echo "   Kerubiscan Automated Deployment        "
echo "=========================================="

# 1. Detect the primary IP address of the server
# This gets the first IP address bound to the hostname/interfaces
HOST_IP=$(hostname -I | awk '{print $1}')

if [ -z "$HOST_IP" ]; then
    echo "Error: Could not detect host IP address."
    exit 1
fi

echo "Detected Host IP: $HOST_IP"

# 2. Check if .env.example exists
if [ ! -f ".env.example" ]; then
    echo "Error: .env.example file not found! Are you in the Kerubiscan_deployment root?"
    exit 1
fi

# 3. Copy the example environment file if .env doesn't exist, or ask to overwrite
if [ -f ".env" ]; then
    echo "Warning: .env already exists. It will be backed up to .env.backup"
    cp .env .env.backup
fi

echo "Generating new .env file from .env.example..."
cp .env.example .env

# 4. Inject the detected IP into the .env file
# Replaces the default IP placeholder '192.168.1.253' with the detected IP
sed -i "s/192.168.1.253/$HOST_IP/g" .env

# 5. Optional: Prompt user to fill in GEMINI_API_KEY if they want
echo "Notice: Remember to add your GEMINI_API_KEY to the .env file if AI features are needed."

# 6. Start the docker containers
echo "Starting deployment on $HOST_IP..."
docker compose down
docker compose up -d

echo "=========================================="
echo " Deployment Initialized Successfully!     "
echo " Frontend URL: http://$HOST_IP:9443       "
echo " Keycloak URL: http://$HOST_IP:1990       "
echo "=========================================="

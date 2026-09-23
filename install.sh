#!/usr/bin/env bash
#
# install.sh - Generates the .env for Kerubiscan with the detected host IP
# and automatically starts the deployment.
#
# Usage:
#   ./install.sh                   # Detects IP, generates .env, runs build+up
#   ./install.sh --env-only        # Detects IP, generates .env only
#   HOST_IP=1.2.3.4 ./install.sh   # Forces a specific IP

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

TEMPLATE_FILE=".env.template"
ENV_FILE=".env"

# --- 1. Host IP Detection -------------------------------

detect_host_ip() {
    # Allow manual override via environment variable
    if [[ -n "${HOST_IP:-}" ]]; then
        echo "$HOST_IP"
        return
    fi

    local ip=""

    # Method 1: Default route to the outside (most reliable for Linux VMs)
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}' || true)"

    # Method 2: Fallback to hostname -I
    if [[ -z "$ip" ]]; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    fi

    # Method 3: Fallback for macOS (if running locally on Mac)
    if [[ -z "$ip" ]]; then
        ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
    fi

    if [[ -z "$ip" ]]; then
        echo "ERROR: Could not automatically detect host IP." >&2
        echo "Please run with: HOST_IP=your.ip.address ./install.sh" >&2
        exit 1
    fi

    echo "$ip"
}

HOST_IP_DETECTED="$(detect_host_ip)"
echo ">> Detected Host IP : $HOST_IP_DETECTED"

# --- 2. Generate .env from template -----------------------

if [[ ! -f "$TEMPLATE_FILE" ]]; then
    echo "ERROR: $TEMPLATE_FILE not found in $SCRIPT_DIR" >&2
    exit 1
fi

# Detect OS for sed inline compatibility (macOS vs GNU)
if sed --version 2>/dev/null | grep -q GNU; then
    sed "s/__HOST_IP__/${HOST_IP_DETECTED}/g" "$TEMPLATE_FILE" > "$ENV_FILE"
else
    # BSD/macOS sed fallback
    cat "$TEMPLATE_FILE" | sed "s/__HOST_IP__/${HOST_IP_DETECTED}/g" > "$ENV_FILE"
fi

echo ">> Generated $ENV_FILE with IP $HOST_IP_DETECTED"

# --- 3. Optional docker-compose launch --------------------------

if [[ "${1:-}" == "--env-only" ]]; then
    echo ">> --env-only requested. Stopping here (Docker Compose not launched)."
    exit 0
fi

echo ">> Building & launching containers..."
docker compose up -d --build

echo ""
echo "=== Deployment Complete ==="
echo "Frontend : http://${HOST_IP_DETECTED}:9443"
echo "Keycloak : http://${HOST_IP_DETECTED}:1990"
echo "API      : http://${HOST_IP_DETECTED}:9445"

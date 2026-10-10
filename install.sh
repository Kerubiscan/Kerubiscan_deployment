#!/usr/bin/env bash
#
# install.sh - Generates the .env for KVS with the detected host IP
# and automatically starts the deployment.
#
# Usage:
#   ./install.sh                   # Generates .env, runs build+up
#   ./install.sh --env-only        # Generates .env only
#   ./install.sh --update-env      # Updates an EXISTING .env so it no longer depends on the IP
#                                  # (keeps every secret), then rebuilds and restarts
#   HOST_IP=1.2.3.4 ./install.sh   # Forces the IP shown at the end
#
# The platform follows the address the browser uses: after an IP change (bridge -> NAT, DHCP)
# nothing has to be regenerated. The detected IP is only printed (and used as the OpenVAS UI name).

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

# --- 2. Update an existing .env (--update-env) ---------------
# Older .env files pinned the IP in NEXTAUTH_URL, KEYCLOAK_PUBLIC_URL, BACKEND_API_URL and
# AI_ENDPOINT: the portal broke as soon as the server changed address.

set_env_value() {   # set_env_value KEY VALUE  (adds the line when missing)
    local key="$1" value="$2"
    if grep -q "^${key}=" "$ENV_FILE"; then
        sed -i "s|^${key}=.*|${key}=\"${value}\"|" "$ENV_FILE"
    else
        printf '%s="%s"\n' "$key" "$value" >> "$ENV_FILE"
    fi
}

if [[ "${1:-}" == "--update-env" ]]; then
    if [[ ! -f "$ENV_FILE" ]]; then
        echo "ERROR: no $ENV_FILE to update in $SCRIPT_DIR (run ./install.sh first)" >&2
        exit 1
    fi
    cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%Y%m%d%H%M%S)"
    set_env_value NEXTAUTH_URL ""
    set_env_value KEYCLOAK_PUBLIC_URL ""
    set_env_value BACKEND_API_URL "http://api:8000"
    set_env_value OPENVAS_HOSTNAME "$HOST_IP_DETECTED"
    # Only an Ollama on this host (IP:11434) is rewritten; a remote AI server is kept
    if grep -qE '^AI_ENDPOINT="?http://[0-9.]+:11434' "$ENV_FILE"; then
        set_env_value AI_ENDPOINT "http://host.docker.internal:11434/api/chat"
    fi
    echo ">> $ENV_FILE updated (backup kept as $ENV_FILE.bak.*): it no longer depends on the IP"
    echo ">> Rebuilding (the frontend reads BACKEND_API_URL at build time) and restarting..."
    docker compose -f docker-compose.yml build
    docker compose -f docker-compose.yml up -d
    echo ""
    echo "Portal: http://${HOST_IP_DETECTED}:9443 (or any address that reaches this server)"
    exit 0
fi

# --- 3. Generate .env from template -----------------------

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

# --- 4. Optional docker-compose launch --------------------------

if [[ "${1:-}" == "--env-only" ]]; then
    echo ">> --env-only requested. Stopping here (Docker Compose not launched)."
    exit 0
fi

echo ">> Building & launching containers..."
# -f: docker-compose.override.yml is for development only (it mounts the source code)
docker compose -f docker-compose.yml up -d --build

echo ""
echo "=== Deployment Complete ==="
echo "Frontend : http://${HOST_IP_DETECTED}:9443"
echo "Keycloak : http://${HOST_IP_DETECTED}:1990"
echo "API      : http://${HOST_IP_DETECTED}:9445"

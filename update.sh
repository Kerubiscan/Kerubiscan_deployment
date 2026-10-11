#!/usr/bin/env bash
# =============================================================================
# KVS - update in one command: code, images, containers. Data (database, OpenVAS feed) is kept.
#
# Usage (on the server):
#   bash update.sh            # refuses while a scan is running (the update would cut it)
#   bash update.sh --force    # updates anyway: running scans are cut
#
# Same steps as docs/DEPLOIEMENT.md, section "Mise à jour", plus: the scan worker is attached
# again to the test lab network when the lab is running (its container is recreated).
# Never prunes volumes nor tagged images (rollback images stay).
# =============================================================================
set -euo pipefail
cd "$(dirname "$0")"
COMPOSE=(docker compose -f docker-compose.yml)

if [[ "${1:-}" != "--force" ]]; then
    running=$("${COMPOSE[@]}" exec -T db psql -U kimia -d kimia_db -tAc \
        "select count(*) from scans where status = 'IN_PROGRESS' and is_deleted is not true" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ "${running:-0}" =~ ^[1-9][0-9]*$ ]]; then
        echo "STOP: $running scan(s) en cours. La mise à jour redémarre le worker et les couperait."
        echo "      Attendez leur fin (ou arrêtez-les), puis relancez. Pour forcer : bash update.sh --force"
        exit 1
    fi
fi

echo ">> Code"
git pull --ff-only
git submodule update --init --recursive
git submodule status

echo ">> Images (the build checks that ZAP starts; on failure the running containers are kept)"
"${COMPOSE[@]}" build

echo ">> Containers"
"${COMPOSE[@]}" up -d

if docker network inspect kerubiscan_lab-net >/dev/null 2>&1; then
    echo ">> Test lab running: worker attached to it again"
    for service in celery-worker openvas; do
        id=$("${COMPOSE[@]}" ps -q "$service" 2>/dev/null || true)
        [[ -n "$id" ]] && docker network connect kerubiscan_lab-net "$id" 2>/dev/null || true
    done
fi

echo ">> Replaced images removed (dangling only: tagged rollback images are kept)"
docker image prune -f >/dev/null

echo ""
echo "Mise à jour terminée."
"${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.Status}}'

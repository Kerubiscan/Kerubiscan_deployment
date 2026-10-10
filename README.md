# KVS Unified Deployment

This repository contains the unified deployment architecture for the **Kerubi Vulnerability Scanner (KVS)**. It uses Docker Compose and Git Submodules to orchestrate the frontend, backend, Keycloak authentication, Vault, Redis, and OpenVAS scanning engine in a single command.

---

> 📘 **Guide complet en français : [docs/DEPLOIEMENT.md](docs/DEPLOIEMENT.md)** — prérequis de la
> machine, installation, mise à jour, vérifications, liste de tous les outils embarqués, variables
> `.env`, durcissement avant la production et dépannage.

## 📋 Prerequisites
- **Machine**: x86_64, 4 vCPU (8 recommended), **12 GB RAM minimum (16 GB recommended)**, 100 GB disk
- **OS**: Ubuntu Server 22.04 / 24.04 or Debian 12
- Docker Engine 24+ and **Docker Compose v2** (`docker compose`)
- Git (with submodule support)
- Outbound Internet access during the build (Docker Hub, quay.io, Debian, PyPI, npm, GitHub) and
  during scans (vulners.com, Greenbone feed, AI provider)

See [docs/DEPLOIEMENT.md](docs/DEPLOIEMENT.md) for the full list of tools and versions.

---

## 🚀 Quick Start Guide

### 1. Clone the Repository
You **must** use the `--recurse-submodules` flag to pull down the frontend and backend code simultaneously:
```bash
git clone --recurse-submodules https://github.com/Kerubiscan/Kerubiscan_deployment.git
cd Kerubiscan_deployment
```

If you already cloned without submodules, run:
```bash
git submodule update --init --recursive
```

### 2. Auto-Detect IP & Launch
We provide automated scripts that will detect your machine's IP address, generate the `.env` file automatically, and launch the deployment.

**On Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

*(Optional)*: If you want to force a specific IP or just generate the `.env` file without starting Docker yet, you can use the flags:
- `./install.sh --env-only`
- `HOST_IP=1.2.3.4 ./install.sh`

Once the script finishes, you can open `.env` and add your `GEMINI_API_KEY` if you want AI-powered remediation features, then restart the containers with `docker compose up -d`.

> Always pass `-f docker-compose.yml` on a test or production server: `docker-compose.override.yml`
> is for development only (it mounts the source code into the containers).
> ```bash
> docker compose -f docker-compose.yml build
> docker compose -f docker-compose.yml up -d
> ```

### 3. Updating
Merge the backend and frontend pull requests first, then the deployment one (it pins both
submodules). On the server:
```bash
git pull && git submodule update --init --recursive
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
docker image prune -f
```
Do not rebuild while a scan is running (the worker is recreated), and never run
`docker system prune -a` or `docker volume prune`.

---

## 🎯 How to Run Scans Properly

KVS uses a **Two-Phase Scanning Architecture** to ensure fast, accurate, and targeted vulnerability assessments:

### Phase 1: Asset Discovery (Nmap)
When you start a scan on a target IP or domain, KVS first runs a comprehensive Nmap discovery scan (`-sV -O -p-`). 
- It maps out all open ports, running services, MAC addresses, and the Operating System.
- **Auto-Creation:** If the target is not already in your database, KVS will dynamically create a new Asset for it on the fly.
- **Real-time Updates:** The exact moment Phase 1 finishes (usually 10-20 minutes depending on the network), your dashboard's **Assets** page will update. You can click the **Eye icon** to immediately view the open ports, OS, and services—even before the vulnerability scan finishes!

### Phase 2: Targeted Vulnerability Scanning
Once Phase 1 finishes, it passes the exact list of open ports directly to the vulnerability scanners (Nuclei, ZAP, or Nmap).
- **Nuclei & Nmap:** Instead of blindly attacking all 65,535 ports, these scanners will *only* attack the specific ports that Phase 1 found open. This acts as a massive speed filter.
- **OWASP ZAP:** If the target is online, ZAP will automatically spider and attack the web services (HTTP/HTTPS) on standard ports. If no open ports are found on the host at all, Phase 2 is skipped entirely to save time.

### Best Practices:
- Always give Phase 1 enough time to finish. It uses a stealthy, comprehensive sweep, so it may take time on heavily firewalled targets.
- Use the **Assets** tab to monitor the discovery data as soon as Phase 1 completes.
- For purely web-based targets, ensure the domain name is reachable, as ZAP relies on DNS resolution.

---

## 🌐 Services Access
Once the containers are healthy, you can access the platform using your server's IP address:

| Service | Address |
| --- | --- |
| **KVS Portal (Frontend)** | `http://<YOUR_IP>:9443` |
| **Backend API (Swagger Docs)** | `http://<YOUR_IP>:9445/docs` |
| **Keycloak Management** | `http://<YOUR_IP>:1990` |
| **OpenVAS Greenbone UI** | `http://<YOUR_IP>:9392` |
| **Vault UI** | `http://<YOUR_IP>:8200` |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              KVS-net (bridge)             │
│                                                  │
│  frontend:3000  ──►  api:8000  ──►  db:5432     │
│       │               │             redis:6379   │
│       │               │             vault:8200   │
│       └──► keycloak:8080           openvas:9390  │
│                                    celery-worker  │
│                                    celery-beat    │
└─────────────────────────────────────────────────┘
```

**Port mappings (host → container):**
- `9443` → frontend
- `9445` → api
- `1990` → keycloak
- `9392` → openvas UI
- `8200` → vault

---

## 💾 Migrating Existing Data
If you are upgrading from a legacy standalone setup and want to retain your database and scan data:

1. Run `docker volume ls` to find your old volumes (e.g. `kimia_postgres_data`, `kimia_openvas_data`).
2. Edit the bottom of `docker-compose.yml` to reference them:
```yaml
volumes:
  postgres_data:
    external: true
    name: your_old_postgres_volume_name
  openvas_data:
    external: true
    name: your_old_openvas_volume_name
```
3. Run `docker compose up -d` to restart with your old data intact.

---

## 🔧 Troubleshooting

### Dashboard stays in loading state
This is caused by `BACKEND_API_URL` not being set in `.env` before building. The frontend proxy is configured at **build time**.
**Fix:** Set `BACKEND_API_URL` in `.env` to your server's IP and port, then rebuild:
```bash
docker compose build --no-cache frontend
docker compose up -d
```

### Keycloak theme not loading
The Keycloak theme is built inside Docker automatically via a multi-stage build — no manual pre-build step is needed. If the theme appears unstyled, do a full rebuild:
```bash
docker compose build --no-cache keycloak
```

### Submodule is out of date
```bash
git submodule update --remote --merge
```

### Unable to access site
```bash
docker compose down  
docker compose up -d --build

#or

docker compose down -v
docker compose up -d --build

```

### Dashboard fails to load or login fails (Database Migrations)
If the dashboard refuses to load or you see `client_not_found` errors in the Keycloak logs, you likely need to apply your backend database migrations. Run this command to apply them inside the API container:
```bash
docker compose exec api alembic upgrade head
```
*(Note: If you wiped your database with `docker compose down -v`, you will always need to re-run this migration).*

### Keycloak "Client Not Found"
If migrations are up to date but you still cannot log in, ensure Keycloak imported the `realm-export.json` correctly. If Keycloak skipped the import because the realm already exists, you can force a clean import:
1. Run `docker compose down -v` to wipe the old Keycloak database (**WARNING: Wipes all backend scan data too!**)
2. Run `docker compose up -d` to restart everything fresh and force Keycloak to re-import the realm.
3. Re-run your backend database migrations using the `alembic upgrade head` command described above.

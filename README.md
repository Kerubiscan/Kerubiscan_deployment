# KerubiScan Unified Deployment

This repository contains the unified deployment architecture for the **Kimia Vulnerability Scanner (KerubiScan)**. It uses Docker Compose and Git Submodules to orchestrate the frontend, backend, Keycloak authentication, Vault, Redis, and OpenVAS scanning engine in a single command.

---

## 📋 Prerequisites
- Docker Engine & Docker Compose
- Git (with submodule support)

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

### 2. Prepare Environment
Copy the example environment file and fill in the required values:
```bash
cp .env.example .env
```

Open `.env` and set at minimum:

| Variable | Description | Example |
| --- | --- | --- |
| `BACKEND_API_URL` | Public URL of the backend API (your server IP + port 9445) | `http://<YOUR_SERVER_IP>:9445` |
| `NEXTAUTH_URL` | Public URL of the frontend (your server IP + port 9443) | `http://<YOUR_SERVER_IP>:9443` |
| `KEYCLOAK_PUBLIC_URL` | Public URL of Keycloak (your server IP + port 1990) | `http://<YOUR_SERVER_IP>:1990` |
| `GEMINI_API_KEY` | *(Optional)* API key to enable AI-powered vulnerability remediation | `your_key_here` |

> **Important:** `BACKEND_API_URL` must be set to your **server's actual IP address** (not `localhost`). It is used at **build time** to configure the frontend's API proxy. If left unset, the dashboard will hang in a loading state.

### 3. Build and Launch
Launch the entire infrastructure:
```bash
docker compose up -d --build
```

> For a clean rebuild (recommended after pulling submodule updates):
> ```bash
> docker compose down
> docker compose build --no-cache
> docker compose up -d
> ```

### 4. Updating Submodules
When new backend or frontend changes are pushed, update your local submodules:
```bash
git submodule update --remote --merge
docker compose up -d --build
```

---

## 🌐 Services Access
Once the containers are healthy, you can access the platform using your server's IP address:

| Service | Address |
| --- | --- |
| **Kerubiscan Portal (Frontend)** | `http://<YOUR_IP>:9443` |
| **Backend API (Swagger Docs)** | `http://<YOUR_IP>:9445/docs` |
| **Keycloak Management** | `http://<YOUR_IP>:1990` |
| **OpenVAS Greenbone UI** | `http://<YOUR_IP>:9392` |
| **Vault UI** | `http://<YOUR_IP>:8200` |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────┐
│              kerubiscan-net (bridge)             │
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

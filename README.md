# KerubiScan Unified Deployment

This repository contains the unified, zero-config deployment architecture for the **Kimia Vulnerability Scanner (KerubiScan)**. It utilizes Docker Compose and Git Submodules to orchestrate the frontend, backend, Keycloak authentication, and OpenVAS scanning engine in a single command.

## 🌟 Zero-Config Architecture
This deployment features dynamic IP detection. You **do not** need to manually configure IP addresses or hardcode domains in environment variables. 
The Next.js frontend will dynamically detect the server's IP via the HTTP `Host` header and seamlessly route authentication flows to Keycloak.

## 📋 Prerequisites
- Docker Engine & Docker Compose
- Git (with submodule support)

## 🚀 Quick Start Guide

### 1. Clone the Repository
You **must** use the `--recurse-submodules` flag to pull down the frontend and backend code simultaneously:
```bash
git clone --recurse-submodules https://github.com/Kerubiscan/Kerubiscan_deployment.git
cd Kerubiscan_deployment
```

### 2. Prepare Environment
Copy the example environment file:
```bash
cp .env.example .env
```
*(Optional)*: Open `.env` and provide your `GEMINI_API_KEY` to enable AI-powered vulnerability remediation features.

### 3. Build and Launch
Launch the entire infrastructure:
```bash
docker compose up -d --build
```

---

## 🌐 Services Access
Once the containers are healthy, you can access the platform in your browser using your server's IP address:

| Service | Address |
| --- | --- |
| **Kerubiscan Portal (Frontend)** | `http://<YOUR_IP>:9443` |
| **Backend API** | `http://<YOUR_IP>:9445/docs` |
| **Keycloak Management** | `http://<YOUR_IP>:1990` |
| **OpenVAS Greenbone UI** | `http://<YOUR_IP>:9392` |

---

## 💾 Migrating Existing Data
If you are upgrading from a legacy standalone setup and want to retain your database/scans:
1. Run `docker volume ls` to find your old volumes (e.g. `kerubiscan_postgres_data`, `kerubiscan_openvas_data`).
2. Edit the bottom of `docker-compose.yml` to point to them:
```yaml
volumes:
  postgres_data:
    external: true
    name: kerubiscan_postgres_data
  openvas_data:
    external: true
    name: kerubiscan_openvas_data
```
3. Run `docker compose up -d` to restart with your old data intact!

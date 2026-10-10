# Guide de déploiement de KVS (Kerubi Vulnerability Scanner)

Ce guide décrit la machine à prévoir, l'installation, la mise à jour et le contenu de chaque
conteneur. Il correspond au dépôt `Kerubiscan_deployment` avec le backend `5620458` et le
frontend `88d5eed` (octobre 2026).

> Les commandes de ce guide utilisent toujours `docker compose -f docker-compose.yml`. Ce fichier
> seul est la configuration de recette et de production. `docker-compose.override.yml` est réservé
> au développement : il monte le code source dans les conteneurs à la place du code de l'image.

---

## 1. Prérequis de la machine

### Matériel

| Ressource | Minimum | Recommandé | Pourquoi |
|---|---|---|---|
| Processeur | 4 vCPU | 8 vCPU | OpenVAS, ZAP (Java + 2 navigateurs) et Nuclei tournent en parallèle |
| Mémoire | 12 Go | 16 Go | Limites fixées : worker de scan **6 Go** (2 scans ZAP en parallèle), OpenVAS 4 Go, worker secondaire 1 Go, plus la base, Keycloak, l'API et le frontend. Avec 12 Go, baisser `SCAN_CONCURRENCY` à 1 et le worker à 3 Go |
| Disque | 100 Go | 150 Go | Images (environ 15 Go), feed OpenVAS, base de données, cache de build. Un build consomme plusieurs Go temporairement |
| Architecture | x86_64 (amd64) | x86_64 | Nuclei et ZAP sont téléchargés en version Linux amd64 |

Sur le serveur de test (`vapt`), 6 Go de RAM ne suffisaient pas : ZAP a été tué par manque de
mémoire. Avec 10 Go, les scans passent.

### Système et logiciels de l'hôte

| Logiciel | Version | Rôle |
|---|---|---|
| Ubuntu Server 22.04 / 24.04, ou Debian 12 | 64 bits | Système testé : Ubuntu sur une VM avec LVM |
| Docker Engine | 24 ou plus | Exécution des conteneurs |
| Docker Compose | v2 (plugin `docker compose`) | Orchestration ; la commande `docker-compose` v1 n'est pas prise en charge |
| Git | 2.30 ou plus | Clonage avec les sous-modules |
| GitHub CLI (`gh`) | facultatif | Fusion des pull requests depuis un poste |
| `iproute2` | — | Détection de l'IP par `install.sh` |

Installation de Docker sur Ubuntu (dépôt officiel) :
```bash
sudo apt-get update && sudo apt-get install -y ca-certificates curl git
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER"   # puis se reconnecter
docker version && docker compose version
```

### Réseau

**Accès sortant pendant le build** (images et outils) :
- `registry-1.docker.io` et `quay.io` (images de base, Keycloak) ;
- `deb.debian.org` (Nmap, Java, Firefox ESR) ;
- `pypi.org` et `files.pythonhosted.org` (dépendances Python) ;
- `registry.npmjs.org` (dépendances du frontend) ;
- `github.com` et `objects.githubusercontent.com` (ZAP 2.17.0, Nuclei 3.11.1, templates Nuclei) ;
- `playwright.azureedge.net` / `cdn.playwright.dev` (Chromium pour les PDF).

**Accès sortant pendant les scans** :
- `vulners.com` : le script Nmap `vulners` interroge son API pour associer les versions aux CVE ;
- le feed communautaire Greenbone : mises à jour des tests OpenVAS (désactivables avec `OPENVAS_SKIPSYNC=true`) ;
- le fournisseur d'IA choisi (`AI_PROVIDER` : API Gemini, ou serveur Ollama de `AI_ENDPOINT`) ;
- bien sûr, les cibles à scanner.

**Ports ouverts sur l'hôte** (voir la section 7 pour ceux à fermer avant la production) :

| Port | Service |
|---|---|
| 9443 | Portail KVS (frontend) |
| 9445 | API backend (documentation sur `/docs`) |
| 1990 | Keycloak (authentification) |
| 9392 / 9390 | OpenVAS : interface web et protocole GMP |
| 8200 | Vault |
| 5432 | PostgreSQL |
| 6379 | Redis |
| 5672 / 15672 | RabbitMQ et sa console |

---

## 2. Installation

```bash
git clone --recurse-submodules https://github.com/Kerubiscan/Kerubiscan_deployment.git
cd Kerubiscan_deployment
chmod +x install.sh
./install.sh --env-only            # génère .env à partir de .env.template avec l'IP détectée
```
Vérifier et compléter `.env` (section 6), puis :
```bash
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
docker compose -f docker-compose.yml ps
```

Au premier démarrage :
- l'API applique les migrations de la base (Alembic) toute seule ;
- OpenVAS charge son feed de tests, ce qui peut prendre **plus d'une heure**. Tant que ce n'est
  pas terminé, les scans OpenVAS sont refusés avec le message « Feed NVT absent ».

### Changement d'adresse IP du serveur

La plateforme **ne dépend pas de l'IP du serveur** : le portail et Keycloak utilisent l'adresse
que le navigateur a appelée. Après un changement d'IP (passage du mode pont au mode NAT, nouvelle
adresse DHCP, VM déplacée), il n'y a **rien à régénérer ni à reconstruire** : il suffit d'ouvrir
le portail avec la nouvelle adresse, `http://<nouvelle IP>:9443`.

Conditions :
- `NEXTAUTH_URL` et `KEYCLOAK_PUBLIC_URL` restent **vides** dans `.env`. Ne les renseigner que pour
  une adresse publique fixe (nom de domaine, HTTPS derrière un proxy).
- `BACKEND_API_URL` vaut `http://api:8000` (réseau Docker interne, sans IP).
- En **NAT avec redirection de ports** (VirtualBox, par exemple), rediriger les ports **avec les
  mêmes numéros** côté hôte et côté VM : au moins 9443 (portail) et 1990 (Keycloak, appelé sur
  le même nom d'hôte que le portail), et 9445 pour la documentation de l'API.

**Serveur installé avant cette version** : son `.env` contient encore l'IP en dur. Le mettre à
jour une seule fois ; les secrets sont conservés et une sauvegarde `.env.bak.*` est créée :
```bash
cd /home/user/Kerubiscan_deployment
git pull && git submodule update --init --recursive
./install.sh --update-env      # corrige .env, reconstruit et redémarre
```
Seul le nom affiché par l'interface web d'OpenVAS (`OPENVAS_HOSTNAME`, port 9392) reprend l'IP
détectée ; les scans ne l'utilisent pas.

---

## 3. Mise à jour

Sur un poste avec `gh`, fusionner les pull requests dans l'ordre **backend, frontend, puis
déploiement** (le dépôt de déploiement fixe les versions des deux autres). Puis, sur le serveur :

```bash
cd /home/user/Kerubiscan_deployment
git pull && git submodule update --init --recursive
git submodule status                       # versions attendues du backend et du frontend
docker compose -f docker-compose.yml build
docker compose -f docker-compose.yml up -d
docker image prune -f                      # supprime les images remplacées
```

À savoir :
- **Ne pas reconstruire pendant un scan** : le worker est recréé et le scan en cours est coupé.
- Le build vérifie que ZAP démarre (`ZAP started in …s`) et que son spider AJAX est disponible.
  S'il échoue, les conteneurs en place continuent de tourner : le `up -d` n'est pas exécuté.
- **Ne jamais lancer `docker system prune -a` ni `docker volume prune`** : le premier supprime les
  images de retour arrière éventuelles, le second les données (base, feed OpenVAS).
- Libérer de la place sans risque : `docker builder prune -f` (cache de build).

### Retour arrière

Avant une mise à jour risquée, étiqueter les images en service :
```bash
for s in api celery-worker celery-beat frontend; do
  docker tag kerubiscan_deployment-$s:latest kerubiscan_deployment-$s:rollback-$(date +%Y%m%d)
done
```
Les supprimer une fois la nouvelle version validée (`docker rmi …`) : chaque jeu prend plusieurs Go.

---

## 4. Vérifications après déploiement

```bash
# Tous les conteneurs « Up » (et « healthy » pour OpenVAS)
docker compose -f docker-compose.yml ps

# Outils de scan présents dans le worker
W=kerubiscan_deployment-celery-worker-1
docker exec $W nmap --version | head -1
docker exec $W nuclei -version
docker exec $W sh -c 'find /root/nuclei-templates -name "*.yaml" | wc -l'   # plus de 10 000
docker exec $W ls /opt/zaproxy/plugin | grep -E "spiderAjax|webdriverlinux"
docker exec $W firefox-esr --version

# Connexion à OpenVAS et état du feed
docker exec $W python -c "
from src.scans.adapters.outbound.gvm_adapter import GVMAdapter
a = GVMAdapter(); print(a.connect(), a.check_feeds()); a.disconnect()"
```
Puis ouvrir `http://<IP>:9443`, se connecter, et lancer un scan Nmap court sur une cible autorisée.

---

## 5. Contenu de la plateforme

### Conteneurs

| Service | Image | Rôle | Mémoire max |
|---|---|---|---|
| `frontend` | build de `Kerubiscan_frontend/kerubiscan` | Portail web | — |
| `api` | build de `Kerubiscan_backend` | API REST (FastAPI), migrations au démarrage | — |
| `celery-worker` | build de `Kerubiscan_backend` | Exécute les scans (file `scans`), `SCAN_CONCURRENCY` scans en parallèle | 3 Go |
| `celery-worker-default` | build de `Kerubiscan_backend` | Suivi d'OpenVAS, rapports, IA, planification (file `celery`) | 1 Go |
| `celery-beat` | build de `Kerubiscan_backend` | Tâches périodiques (planification, chien de garde) | — |
| `db` | `postgres:15-alpine` | Base de données (application et Keycloak) | — |
| `redis` | `redis:7-alpine` | Résultats des tâches Celery | — |
| `rabbitmq` | `rabbitmq:3-management-alpine` | File de messages des tâches | — |
| `keycloak` | `quay.io/keycloak/keycloak:24.0.0` (+ thème KVS) | Authentification et rôles | — |
| `vault` | `hashicorp/vault:1.15` | Coffre des identifiants de scan authentifié | — |
| `openvas` | `immauss/openvas:latest` | Scanner OpenVAS / Greenbone (GVM) | 4 Go |

### Outils dans l'image backend (`api` et workers)

| Outil | Version | Utilisation |
|---|---|---|
| Python | 3.12 (image `python:3.12-slim`, Debian) | Langage du backend |
| Nmap | paquet Debian (7.95 sur le serveur de test) | Découverte réseau, phase 1 de tous les scans, moteur « Nmap » |
| Script Nmap `vulners.nse` | celui du paquet Nmap | CVE d'après les versions de services (format « ID CVSS URL ») |
| Nuclei | 3.11.1 | Moteur « Nuclei » (modèles de détection) |
| Templates Nuclei | 10.5.0 (dans `/root/nuclei-templates`) | Plus de 10 000 modèles ; exclusions DoS / fuzzing / force brute via `.nuclei-ignore` |
| OWASP ZAP | 2.17.0 (`/opt/zaproxy`) | Moteur « OWASP ZAP » : spider, spider AJAX, scan actif |
| Java (OpenJDK) | `default-jre` de Debian | Exécution de ZAP |
| Firefox ESR | paquet Debian | Navigateur du spider AJAX de ZAP (2 navigateurs au plus) |
| geckodriver | fourni par le module ZAP `webdriverlinux` | Pilotage de Firefox par ZAP |
| Chromium (Playwright) | Playwright 1.63.0 | Impression des rapports HTML en PDF |
| Police Open Sans | paquet Debian | Rendu des rapports |

### Bibliothèques Python principales

FastAPI 0.112 et Uvicorn 0.30 (API), SQLAlchemy 2.0 et Alembic 1.13 (base et migrations),
psycopg2 (PostgreSQL), Celery 5.4 (tâches), redis-py 5.0, python-gvm 24.3 (pilotage d'OpenVAS),
python-keycloak 4.5 (authentification), hvac 2.3 (Vault), Jinja2 3.1 (rapports HTML),
ReportLab 4.1 (PDF de secours sans Chromium), slowapi (limitation de débit), httpx, Pydantic 2.8.

### Frontend

Node.js 20 (image `node:20-alpine`), Next.js 16.3, React 19.2, NextAuth 4 (connexion Keycloak),
next-intl 4 (français / anglais), Recharts 3 (graphiques), Tailwind CSS 4, lucide-react (icônes).

### Moteurs de scan disponibles

| Moteur | Type de cible | Ce qu'il apporte |
|---|---|---|
| Nmap | IP, réseau, nom d'hôte | Ports, services, système, CVE par version (à confirmer) |
| Nuclei | hôte ou application web | Failles connues testées par modèle |
| OWASP ZAP | application web (URL) | Failles applicatives : injection SQL, XSS, redirections… |
| OpenVAS | IP, réseau, nom d'hôte | Tests actifs réseau et système, scores CVSS, preuves d'exploitation |

---

## 6. Variables d'environnement (`.env`)

`install.sh` génère `.env` depuis `.env.template`. Les valeurs ne sont pas reproduites ici.

| Variable | Rôle |
|---|---|
| `BACKEND_API_URL` | URL de l'API vue par le frontend : `http://api:8000` (réseau Docker interne) ; **prise en compte au build** du frontend |
| `NEXTAUTH_URL`, `NEXTAUTH_SECRET` | Adresse publique du portail (**vide** : celle qu'utilise le navigateur) et clé de session |
| `KEYCLOAK_PUBLIC_URL`, `KEYCLOAK_REALM`, `KEYCLOAK_REALM_NAME` | Keycloak vu du navigateur (**vide** : même adresse que le portail, port 1990) et royaume |
| `FRONTEND_KEYCLOAK_CLIENT_ID` / `_SECRET` | Client Keycloak du frontend |
| `BACKEND_KEYCLOAK_CLIENT_ID` / `_SECRET` | Client Keycloak du backend |
| `POSTGRES_URL`, `REDIS_URL` | Accès base et Redis |
| `PROJECT_NAME`, `VERSION` | Nom et version affichés |
| `AI_PROVIDER`, `AI_MODEL`, `GEMINI_API_KEY`, `AI_ENDPOINT` | Résumés et remédiations par IA (Gemini ou Ollama ; Ollama de l'hôte : `http://host.docker.internal:11434/api/chat`) |
| `OPENVAS_HOSTNAME`, `OPENVAS_PASSWORD`, `OPENVAS_SKIPSYNC` | Connexion à OpenVAS ; `SKIPSYNC=true` saute la mise à jour du feed |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS` | Courriels de fin de scan (sans SMTP : envoi simulé dans les logs) |
| `SCAN_CONCURRENCY` | Nombre de scans exécutés en parallèle par le worker (défaut **2**). Au-delà de 2, augmenter la RAM et le `mem_limit` du worker ; en cas de mémoire limitée, remettre 1 |
| `SCAN_ALLOWED_TARGETS` | Périmètre autorisé (IP, réseaux, domaines séparés par des virgules) ; vide = aucune restriction |
| `OPENVAS_STALL_HOURS` | Délai sans progrès avant qu'une tâche OpenVAS soit déclarée bloquée |
| `AUDIT_RETENTION_DAYS`, `RAW_OUTPUT_RETENTION_DAYS` | Durée de conservation du journal d'audit et des sorties brutes |

Le fuseau horaire des conteneurs est `Africa/Lagos` (`TZ` dans `docker-compose.yml`) : il sert aux
dates des rapports et du tableau de bord.

---

## 7. Avant la production

- **Fermer les ports internes** : PostgreSQL (5432), Redis (6379), RabbitMQ (5672, 15672),
  Vault (8200) et OpenVAS (9390, 9392) n'ont pas à être joignables depuis le réseau. Retirer leurs
  `ports:` dans `docker-compose.yml`, ou les lier à `127.0.0.1`.
- **Changer les mots de passe et jetons par défaut** présents dans `docker-compose.yml` (base de
  données, Vault, OpenVAS) et dans `.env`.
- **Vault** tourne en mode développement (données en mémoire) et **Keycloak** en `start-dev` : à
  passer en mode production.
- **Définir `SCAN_ALLOWED_TARGETS`** pour limiter les scans aux réseaux autorisés par le client.
- **Mettre le portail derrière HTTPS** (proxy inverse) : le navigateur affiche aujourd'hui « Non
  sécurisé ».

---

## 8. Labo de test (facultatif)

`lab/docker-compose.lab.yml` lance des cibles **volontairement vulnérables** sur un réseau Docker
isolé, sans accès Internet et sans port publié : Apache 2.4.49 (`app.lab.internal`, CVE-2021-41773),
OWASP Juice Shop et un serveur SSH avec un compte de test. Réservé à une machine de test.

```bash
docker compose -f lab/docker-compose.lab.yml up -d
docker network connect kerubiscan_lab-net kerubiscan_deployment-celery-worker-1
docker network connect kerubiscan_lab-net kerubiscan_deployment-openvas-1
```
La connexion du worker est à refaire **après chaque recréation** du conteneur (donc après chaque
mise à jour). Le message `already exists` signifie qu'elle est déjà en place.

---

## 9. Dépannage

| Symptôme | Cause probable | Action |
|---|---|---|
| Disque plein pendant le build | Cache de build et images remplacées | `docker builder prune -f` puis `docker image prune -f` |
| Le build s'arrête sur « ZAP did not answer » | ZAP ne démarre pas dans l'image | Envoyer la fin du journal affichée par le build |
| Scan ZAP tué (`Connection reset by peer`) | Mémoire insuffisante | Passer la machine à 10 Go ou plus |
| « Feed NVT absent » | Feed OpenVAS pas encore chargé | Attendre ; suivre `docker logs -f kerubiscan_deployment-openvas-1` |
| Une cible du labo est injoignable | Worker recréé, plus relié au réseau du labo | `docker network connect kerubiscan_lab-net kerubiscan_deployment-celery-worker-1` |
| Le portail reste en chargement | `BACKEND_API_URL` absent ou faux au build du frontend | `BACKEND_API_URL="http://api:8000"` dans `.env`, puis `docker compose -f docker-compose.yml build frontend` |
| Portail ou connexion cassés après un changement d'IP | `.env` d'avant cette version, avec l'IP en dur | `./install.sh --update-env` (une seule fois) |
| Logs d'un scan | — | `docker logs -f kerubiscan_deployment-celery-worker-1` (scans) et `…-celery-worker-default-1` (OpenVAS) |

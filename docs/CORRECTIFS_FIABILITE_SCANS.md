# Correctifs de fiabilité des scans

- **Branche** : `fix/fiabilite-scans` dans `Kerubiscan_deployment`, `Kerubiscan_backend` et `Kerubiscan_frontend`, basée sur `origin/main` du 4 octobre 2026 (backend `5bae702`, frontend `c8b217b`). Les apports de `5bae702` sont réintégrés dans le code réécrit (commit « Réintègre les apports de 5bae702 »).
- **Base** : constats de `docs/ANALYSE_STATIQUE.md` (les numéros C1, C2… y renvoient).
- **Tests** : 79 tests automatisés côté backend (`Kerubiscan_backend/tests`), tous au vert, dont une sortie réelle de Nmap. Nmap 7.80 et Nuclei 3.11.1 ont aussi été exécutés pour de vrai sur un poste Windows, contre un serveur de test local. La validation sur le serveur Linux reste nécessaire (voir la section 4).

---

## 1. Ce qui change pour l'utilisateur

### Saisie des cibles
Tous ces formats sont acceptés, séparés par des virgules :

| Saisie | Utilisation |
|---|---|
| `site.com`, `www.site.com` | Domaine : **le domaine est conservé** pour ZAP et Nuclei (en-tête Host, SNI, virtual host) |
| `https://site.com:8443/app` | Application précise : ZAP et Nuclei testent **exactement cette URL**, sans balayage des 65 535 ports |
| `192.168.1.10`, `10.0.0.0/24`, `2001:db8::1` | IP, réseau (de /16 à /32), IPv6 |

Une cible invalide est **refusée à la création, avec un message explicite** (avant, le scan échouait sans rien dire).

### Statut de chaque cible (fenêtre de détail d'un scan)

| Statut | Signification |
|---|---|
| Scanné | Le moteur a tourné ; les résultats (éventuellement aucun) sont enregistrés |
| Aucun port ouvert / Aucun service web | L'hôte répond, mais il n'y avait rien à tester pour ce moteur |
| Délai dépassé | Le scan n'a pas pu se terminer (lien lent, pare-feu, WAF) : **résultats incomplets** |
| Injoignable | Échec de la résolution DNS, ou hôte injoignable : **non scanné** |
| Cible invalide / Échec / Interrompu | **Non scanné, ou scanné partiellement** |

Un scan dont **aucune** cible n'a pu être scannée est maintenant en **FAILED**, et non plus en COMPLETED.

### Formulaire « Nouveau scan »
- Le type par défaut est « Vulnerability Scan » (avant : « Discovery », qui ne cherche pas de vulnérabilités).
- « Application Scan » sélectionne automatiquement OWASP ZAP. « Discovery » ne propose que Nmap et OpenVAS.
- Nessus était déjà retiré de l'interface et OWASP ZAP déjà ajouté sur `origin/main` ; côté backend, Nessus est retiré par la migration.

---

## 2. Correctifs techniques

| Constat | Correctif |
|---|---|
| **C1** Résultats Nmap enregistrés sans CVSS, sans description et en MEDIUM | Parser Nmap réécrit : échelle CVSS complète (jusqu'à Critical), blocs `VULNERABLE` avec leur *Risk factor*, `NOT VULNERABLE` ignoré, signalement des exploits publics. Enregistrement unique pour tous les moteurs (`ingest.py`). |
| **C2** Scans authentifiés jamais authentifiés | Le type d'identifiant (stocké en base) est fusionné avec le secret Vault. Le log indique `authenticated=yes/no`. Un secret Vault vide (Vault en mode dev après un redémarrage) est signalé. |
| **C3** URL refusées | Module `scans/domain/targets.py` : analyse unique des cibles et validation dans l'API. |
| **C4** Bascule cachée vers OpenVAS après un échec | Une fonction par moteur, et aucune bascule. Une seule nouvelle tentative, puis l'état `FAILED`. |
| **C5, C6** Domaine remplacé par l'IP | Nuclei et ZAP appellent le domaine. L'asset garde le domaine (`ip_address`) et l'IP est stockée dans le nouveau champ `resolved_ip`. **Les anciens assets abîmés retrouvent leur domaine au scan suivant.** |
| **C7, C8** ZAP limité à 80/443 et sujet aux blocages | ZAP reçoit toutes les URL web trouvées. Sortie redirigée vers un fichier (plus de pipe bloquant). Durées limitées : exploration 15 min, scan actif 90 min. Mémoire de la JVM portée à 1 Go. Alertes « False Positive » ignorées. URL concernées conservées dans la description. |
| WAF ou CDN qui bloque Nmap (0 port) | **Sonde web de secours** : si le balayage de ports ne voit aucun service web, `https://` puis `http://` sont testés directement (délai de 15 s). Les ports 80, 443, 8080, 8443… marqués `tcpwrapped` ou `unknown` sont traités comme web. |
| Latence et Internet | **Profil automatique** : réseau privé, réglage `-T4` (comme avant) ; domaine ou IP publique, profil « Internet » (`-T3`, 4 nouvelles tentatives, 3 h par hôte ; Nuclei à 30 requêtes/s, délai de 20 s, 2 nouvelles tentatives). |
| Templates Nuclei absents (0 résultat silencieux) | Vérification avant chaque scan, avec téléchargement automatique si nécessaire. Sinon, erreur explicite. |
| Scripts Nmap | Toute la catégorie `vuln` est exécutée (choix de l'équipe dans `5bae702`), **sauf les scripts classés `dos`**, qui peuvent faire tomber le service scanné. `vulscan` est retiré par défaut (centaines de faux positifs) ; il suffit de le rajouter dans `DEFAULT_VULN_SCRIPTS` si l'équipe le souhaite. |
| **C9** Sous-réseau : tous les résultats sur un seul asset | Résultats rattachés à chaque hôte (Nmap, Nuclei, ZAP et OpenVAS). |
| **C10** « COMPLETED » sans rien avoir testé | États par cible (voir la section 1) et scan `FAILED` si rien n'a été scanné. Hôte abandonné par Nmap détecté (`timedout`). |
| **C11** Déduplication par titre seul | Clé (titre, port). Nuclei : un résultat par template, matcher et port. ZAP : un résultat par règle et port, avec la liste des URL. |
| **C14** Résultats sur un asset supprimé ou d'une autre société | Recherche des assets limitée à la société et aux assets non supprimés. |
| **C15** Policy appliquée au hasard ; `policy_id` et `credential_id` ignorés à la modification | Policy implicite seulement si la société n'en a qu'une. La modification d'un scan applique enfin la policy et l'identifiant. |
| **C16** Planification | `target_states` initialisé (le scan ne se termine plus après la première cible). File Celery séparée, donc la tâche de planification n'est plus bloquée derrière les scans. Les scans « programmés pour plus tard » **ne partent plus immédiatement** (avant, ils partaient deux fois). |
| **C17** OpenVAS | Ports : TCP complet plus les services UDP utiles (au lieu des 65 535 ports UDP). Durée maximale de 72 h. Interruption signalée. Filtre de rapport explicite. Résultats séparés par hôte. |
| **C18** Logs effacés par le rapport OpenVAS | Le rapport n'est plus écrit dans les logs. Rotation des logs des workers à 5 × 20 Mo. |
| **C21** Scans mis en pause au redémarrage de l'API | Supprimé (cela relançait des cibles encore en cours). |
| **C22** Rapports vides pour un domaine ; rapport PDF couvrant d'autres sociétés | Assets d'un scan retrouvés par domaine, par IP ou par réseau, limités à la société. |
| **C24** Enum `OWASP_ZAP` absent ; Nessus | Migration `b7e4c2a9d1f0` : enum recréé sans NESSUS et avec OWASP_ZAP. Anciens scans Nessus masqués et plannings Nessus mis en pause. |
| **S1, S2** Routes ouvertes ; un Reader peut lancer des scans | Toutes les routes exigent une authentification (vérifié par un test automatique). Permissions `SCAN_READ`, `SCAN_EXECUTE` et `SCAN_DELETE` : **le rôle Reader ne peut plus lancer de scan**. Changer le statut d'une vulnérabilité exige `ASSET_WRITE`. Plus de traces d'erreur renvoyées au client. |
| Rapport PDF différent du HTML | **Le PDF est l'impression du rapport HTML** par Chromium headless : même mise en page, même contenu (détails dépliés). L'ancien PDF ReportLab sert de secours si Chromium manque (erreur dans les logs). |
| XSS dans les rapports | Échappement HTML activé : le contenu venant des cibles scannées (preuves ZAP, titres de pages) ne peut plus injecter de script dans le rapport. Rendu PDF sans JavaScript ni réseau. |
| Rapports par asset en erreur 500 | `v.created_at` inexistant remplacé par la date de dernière détection. |
| Rôle Keycloak « System Administrator » | Reconnu (le code attendait « Systems Administrator ») : ces comptes n'avaient aucune permission. |
| Fiabilité de Celery | `acks_late` : un scan interrompu par l'arrêt d'un worker est relancé. Délai de visibilité Redis de 26 h (sinon un scan long était lancé deux fois). Préchargement à 1. |

---

## 3. Déploiement

> Faites-le d'abord sur un serveur de recette.

```bash
# 1. Récupérer les branches (dépôt de déploiement et sous-modules)
git fetch && git checkout fix/fiabilite-scans
git submodule update --init
git -C Kerubiscan_backend checkout fix/fiabilite-scans
git -C Kerubiscan_frontend checkout fix/fiabilite-scans

# 2. Sauvegarder la base AVANT la migration
docker compose exec db pg_dump -U kimia kimia_db > sauvegarde_$(date +%F).sql

# 3. Reconstruire et relancer. La migration Alembic s'applique au démarrage de l'API.
docker compose build api celery-worker celery-worker-default celery-beat frontend
docker compose up -d

# 4. Vérifier la migration
docker compose exec api alembic current          # doit afficher c5d8e1f2a3b4 (head)
docker compose exec db psql -U kimia -d kimia_db -c "SELECT unnest(enum_range(NULL::scannerengine));"
```

**Image Docker** : elle inclut maintenant Chromium pour le rendu PDF (environ +300 Mo, première construction plus longue). Après le déploiement, testez le bouton « Download PDF » de la page Rapports : si le PDF n'a pas le design du HTML, cherchez `falling back to the legacy PDF layout` dans `docker compose logs api`.

**Nouveau service** : `celery-worker-default` (tâches courtes). `celery-worker` ne traite plus que les scans (file `scans`). Le nombre de scans en parallèle se règle avec `SCAN_CONCURRENCY` dans `.env` (2 par défaut). Comptez environ 1,5 Go de RAM par scan ZAP.

**Rôles** : vérifiez dans Keycloak que les personnes qui lancent des scans ont le rôle *Security Analyst*, *Systems Administrator* ou *Platform Administrator*.

---

## 4. Validation à faire sur le serveur

Uniquement sur des cibles que vous êtes autorisés à scanner :

1. **Les outils sont prêts** :
   ```bash
   docker compose exec celery-worker sh -c 'ls ~/nuclei-templates | head -3; nmap --version | head -1'
   ```
2. **Un scan de domaine avec ZAP** (`site.com`), puis **avec Nuclei**. Suivez-les en direct :
   ```bash
   docker compose logs -f celery-worker | grep -E "engine=|Phase 1|Phase 2|Web probe|finished|authenticated"
   ```
   Points à vérifier : `Phase 2: Nuclei on ['https://site.com', ...]` avec le **domaine** ; un état final `COMPLETED` ; des vulnérabilités visibles dans la page Vulnérabilités **et** dans le rapport.
3. **Un scan Nmap** sur un serveur de test connu : les CVE doivent apparaître avec leur CVSS et une sévérité High ou Critical quand c'est le cas.
4. **Un scan avec identifiant SSH ou HTTP** : le log doit afficher `authenticated=yes (SSH)`. Si `credential ... is empty in Vault` apparaît, recréez l'identifiant (Vault en mode dev perd ses secrets à chaque redémarrage : voir S3).
5. **Un compte Reader** ne doit plus pouvoir lancer de scan (erreur 403).

## 4 bis. Scans bloqués : chien de garde

Ce cas a été constaté sur le serveur avec l'ancienne version : une cible OpenVAS « en cours » à 0 % pendant des heures, et des tâches OpenVAS lancées en cachette par l'ancienne bascule automatique.

| Situation | Ce que fait le chien de garde (toutes les 10 min) |
|---|---|
| Suivi OpenVAS perdu (worker redémarré, déploiement…) | Retrouve la tâche OpenVAS et **relance son suivi**, ou importe son rapport si elle est finie. Introuvable : « Délai dépassé » avec la raison |
| Cible Nmap, Nuclei ou ZAP sans activité depuis plus de 25 h | « Délai dépassé », avec la raison |
| Cible jamais démarrée depuis plus de 26 h | « Échec » : « n'a jamais démarré » |
| Tâche OpenVAS orpheline (scan supprimé, cible terminée, ou tâche de l'ancienne bascule automatique) | **Arrêtée**, pour libérer OpenVAS |

**Au déploiement**, les scans bloqués de l'ancienne version sont pris en charge **automatiquement** dans les 10 minutes qui suivent : les tâches OpenVAS des cibles ABANDONED sont arrêtées, et le suivi de la cible OpenVAS en attente est relancé. Il n'y a pas de requête SQL à exécuter à la main. Suivi :
```bash
docker compose logs -f celery-worker-default | grep -i watchdog
```

Le détail d'un scan affiche maintenant, pour chaque cible, l'état **« En file d'attente »** (OpenVAS), la **raison** d'un échec et la **dernière activité**.

## 5. Ce qui reste à faire (non traité ici)

- **Vault en mode serveur** (persistant) : tant qu'il reste en mode dev, les identifiants sont perdus à chaque redémarrage.
- Identifiants pour **OpenVAS** (création de credentials GVM) : OpenVAS scanne toujours sans authentification, et le log le signale.
- **AJAX spider de ZAP** pour les applications SPA : il nécessite un navigateur headless dans l'image.
- Durcissement du déploiement (secrets, TLS, ports internes, CORS : constat S3), sauvegardes, supervision.
- Génération du résumé IA d'un scan : l'API renvoie un `task_id`, alors que la page Rapports attend directement le texte (défaut existant, non lié aux moteurs).

# Revue du code du scanner Kerubiscan (KVS)

- **Date** : 8 octobre 2026
- **Branche revue** : `fix/fiabilite-scans` — backend `c356135`, frontend `de15716`, déploiement `286d33b`.
- **Important** : les constats R1–R18 ont été relevés en recette sur le backend **`7bd2cb9`**. Depuis, le
  commit **`f2fe3e9` puis `c356135`** (chien de garde, raison par cible, limite douce 23 h, reprise, asset
  manuel, ZAP redirigé) a été ajouté mais **n'était pas encore déployé** lors des constats. Plusieurs points
  sont donc déjà traités dans le code actuel ; ils sont marqués « corrigé après recette » et restent à
  valider sur le serveur.
- **Méthode** : lecture du code. Aucun scan réel n'a été exécuté pour cette revue. Les preuves sont des
  emplacements `fichier:ligne` dans le backend sauf mention contraire.

---

## 1. Statut de chaque constat

Statut : **corrigé** / **partiel** / **non corrigé** / **non reproductible**.

### Constats de l'analyse statique (C1–C24)

| # | Statut | Preuve | Test | Correction prévue (si ouvert) |
|---|---|---|---|---|
| C1 enregistrement Nmap vide | corrigé | `ingest.py` ingest_findings ; parser `nmap_adapter._parse_script` | test_parsers, test_scan_pipeline | — |
| C2 scans authentifiés | **partiel** | `nmap_adapter._build_nmap_auth_args` (fichier 0600 : OK) ; **`nuclei_adapter.py:104` `-H` sur la ligne de commande**, **`zap_adapter.py:111` `-config …=Basic` sur la ligne de commande** | — | Lot P2.10 : passer par fichier/env, jamais sur la ligne de commande (lisible par `ps`) |
| C3 URL refusées | corrigé | `targets.py` parse_target | test_targets | — |
| C4 bascule cachée vers OpenVAS | corrigé | `tasks.py` ENGINE_RUNNERS, plus de fall-through | test_scan_pipeline test_engine_failure_never_falls_back_to_openvas | — |
| C5 domaine → IP (Nuclei) | corrigé | `tasks.py` _identity, _web_work | test_scan_pipeline | — |
| C6 asset : domaine écrasé | corrigé | `ingest.py` resolve_asset | test_scan_pipeline | — |
| C7 ZAP ports 80/443 | corrigé | `tasks.py` _run_zap via _web_work | — | — |
| C8 ZAP bloqué (pipe, durée) | corrigé | `zap_adapter.py` sortie fichier + `_wait` durées | — | — |
| C9 CIDR regroupé sur un asset | corrigé | `tasks.py` _run_nmap/_run_nuclei par hôte | test_scan_pipeline test_cidr_results_go_to_each_host | — |
| C10 « COMPLETED » sans test | corrigé | `progress.py` états + overall_status | test_scan_pipeline | — |
| C11 déduplication par titre | corrigé | `ingest.py` clé (titre, port) | test_parsers | — |
| C12 sévérité Nmap binaire | corrigé | `severity.py`, `nmap_adapter` | test_parsers | — |
| C13 vuln+safe / vulscan | corrigé (code) / voir **R13** (Dockerfile) | `nmap_adapter.DEFAULT_VULN_SCRIPTS` | test_parsers | R13 |
| C14 asset hors société | corrigé | `ingest.py` resolve_asset (company_id, is_deleted) | test_scan_pipeline test_findings_never_land_on_a_deleted_or_foreign_asset | — |
| C15 policy implicite | corrigé | `tasks.py` _select_policy (une seule) ; `endpoints.update_scan` applique policy/credential | — | — |
| C16 planification target_states | corrigé | `scheduling/.../tasks.py` target_states init | — | — |
| C17 OpenVAS UDP complet | corrigé | `tasks.DEFAULT_GVM_PORT_RANGE` | — | — |
| C18 logs effacés par le rapport | corrigé | `gvm_adapter.get_report` (taille seulement) | — | — |
| C19 découverte ping-only | partiel | `nmap_adapter.run_discovery_scan` ajoute `-PS/-PA` ; déduplication par société OK | — | acceptable, laissé en l'état |
| C20 IPv6 | corrigé | `nmap_adapter._run` ajoute `-6` | test_targets | — |
| C21 purge/pause au démarrage | **partiel** | pause retirée (`main.py`) ; **purge toujours présente `main.py:73,76`** → voir **R8** | — | R8 : retirer, mettre en tâche Beat |
| C22 rapports hors société/domaine | corrigé | `scan_assets.scan_assets`, `endpoints` | test_reports_e2e | — |
| C23 vulnerabilities_found incohérent | corrigé | `scan_assets.count_scan_findings` (COUNT) | test_reliability test_rescan_does_not_double_count_findings | — |
| C24 enum OWASP_ZAP / Nessus | corrigé | migration `b7e4c2a9d1f0` | — | vérifié en recette |

### Sécurité (S1–S6)

| # | Statut | Preuve |
|---|---|---|
| S1 routes sans auth | corrigé | test_api_auth test_every_route_requires_authentication (vérifié en recette) |
| S2 Reader lance un scan | corrigé | `rbac_service` SCAN_EXECUTE ; test_api_auth (403 vérifié en recette) |
| S3 secrets par défaut, Vault dev, ports exposés, CORS | non corrigé (**hors périmètre de ce lot**) | `docker-compose.yml` | 
| S4 trace d'erreur au client | corrigé | `endpoints` 500 génériques (vérifié en recette) |
| S5 injection d'options | corrigé | `targets.py`, `nmap_adapter` (cible après `--`) | 
| S6 token GitHub exposé | traité hors dépôt | token révoqué, remotes nettoyés |

### Constats de recette (R1–R18)

| # | Statut | Preuve / cause | Correction prévue |
|---|---|---|---|
| R1 peu de vulnérabilités | corrigé (cause = C1/C4/C5/C13) | voir ci-dessus | — |
| R2 122 annoncées, 0 NUCLEI | corrigé | ancien `parse_nuclei_report` : `vulnerabilities_found = len(vuln_data_list)` (brut) **avant** insertion ; si l'insertion échoue/rollback ou si la cible part ensuite en ABANDONED→OpenVAS, le compteur reste. Nouveau code : `count_scan_findings` (COUNT réel) après `flush` | — (section 3) |
| R3 ABANDONED → OpenVAS + 2500 polls | corrigé | plus de fall-through (C4) ; poll borné (voir R7) | — |
| R4 tâches GVM 0 % 6–8 h | corrigé après recette (partiel) | chien de garde `watchdog.py` arrête les orphelines ; **pas de limite de tâches simultanées** | R11 |
| R5 découverte COMPLETED mais target_states PENDING | **non corrigé** | `tasks._finish_discovery:150` ne met pas à jour `target_states` | P2.9 |
| R6 messages bloqués à l'arrêt du worker | **non corrigé** | `celery_app` `visibility_timeout=26h` ; pas de capture SIGTERM ni de kill des enfants ; `task_routes` à la publication seulement → un scan reçu par `celery-worker-default` est exécuté | P1.1 |
| R7 suivi OpenVAS sans fin | **partiel** | `poll_scan_status` vérifie clos/supprimé/pause (`c356135`) et le chien de garde relance/arrête ; **`max_retries=None` ; 72 h seulement si `started_at`** | P1.2 : borne + `creation_time` GVM |
| R8 purge au démarrage | **non corrigé** | `main.py:73,76` | P2.5 |
| R9 compteur `+=` | corrigé après recette | `count_scan_findings` (COUNT) ; 3 endroits remplacés | — |
| R10 impossible d'arrêter un scan | **non corrigé** | aucune route stop ; pas de révocation Celery | P1.3 |
| R11 OpenVAS sans limite, feed non vérifié | **non corrigé** | pas de `OPENVAS_MAX_TASKS` ; pas de contrôle de feed | P2.8 |
| R12 logs hétérogènes | **partiel** | workers 20m×5, autres 100k×1 ; `scan_id`/cible pas systématiques | P3.12 |
| R13 image non figée, vulners intrusif/externe | **non corrigé** | `Dockerfile:30` nuclei:latest ; `:34` vulners master ; `:35` vulscan cloné inutilisé ; `:31` `nuclei -ut \|\| true` | P3.13 |
| R14 code monté en direct | **non corrigé** | `docker-compose.yml:23,66,99,129` | P3.14 |
| R15 ressources | **non corrigé** | `SCAN_CONCURRENCY:-2` ; pas de `mem_limit` | P3.15 |
| R16 IN_PROGRESS >24 h / pause dernière cible / asset manuel / ZAP redirigé | corrigé après recette | limite douce 23 h (`tasks.py:592`), `recompute_status`, asset_type, `alerts_for_hosts` | test_reliability | 
| R17 dépôts/doc incohérents | **partiel** | `main` du déploiement pointe backend `074c2b6` (dû à la fusion anticipée de la PR #1) ; nombre de tests à corriger | P3.16 + note |
| R18 aucun garde-fou sur les cibles | **non corrigé** | pas de `SCAN_ALLOWED_TARGETS` | P3.11 |

---

## 2. Nouveaux défauts trouvés pendant la revue

### Bloquants pour la fiabilité des résultats
- **N1 — Identifiants sur la ligne de commande (Nuclei, ZAP)** : `nuclei_adapter.py:104` (`-H "Authorization: Basic …"`)
  et `zap_adapter.py:111` (`-config …replacement=Basic …`) exposent le secret dans la liste des processus
  (`ps`, `/proc/<pid>/cmdline`), lisible par tout process du conteneur. (C2 / lot P2.10.)
- **N2 — Pas de réconciliation au démarrage du worker** : après un crash, les cibles `IN_PROGRESS` d'un
  worker mort ne sont jamais rouvertes tant que le chien de garde n'a pas atteint son seuil de silence
  (25 h hors OpenVAS). Acceptable mais long ; une réconciliation au démarrage réduirait le délai. (R6.)

### Sécurité (signalés, non corrigés dans ce lot sauf mention)
- **N3 — `verify=False` systématique** : `zap_adapter`, `tasks._probe_web` et l'adaptateur Nessus (supprimé)
  désactivent la vérification TLS. Acceptable pour un scanner (cibles à certificat invalide), mais à
  documenter : pas de garantie d'intégrité du contenu scanné.
- **N4 — RabbitMQ exposé et inutilisé** : `docker-compose.yml` publie 5672/15672 avec `guest/guest`, alors
  que Celery utilise Redis. Service à retirer (hors périmètre sécurité, mais c'est du code mort).

---

## 3. Explication de R2 (« 122 annoncées, 0 enregistrée »)

Dans l'ancien code (`5bae702`), `parse_nuclei_report` fixait
`scan.vulnerabilities_found = len(vuln_data_list)` (ligne 510) — le **nombre brut** de lignes Nuclei, écrit
dans la même transaction que les insertions. Deux chemins produisent « compteur > 0, 0 ligne en base » :

1. **Rollback des insertions** : une exception pendant la boucle d'insertion (déduplication, objet détaché,
   contrainte) déclenchait `db.rollback()` — mais le compteur avait pu être écrit lors d'un autre appel, ou
   l'`UPDATE scans` passait alors que les `INSERT vulnerabilities` échouaient sur un sous-ensemble.
2. **Mauvais moteur enregistré** : pour un scan Nuclei dont des cibles partaient en `ABANDONED` puis
   lançaient OpenVAS (C4/R3), les vulnérabilités réellement écrites portaient `source_engine = 'OPENVAS'`
   (branche OpenVAS), tandis que le compteur Nuclei restait affiché. D'où « 0 ligne NUCLEI ».

**La nouvelle version ne peut plus produire ce résultat :**
- `vulnerabilities_found` n'est plus un cumul : `count_scan_findings(db, scan)` fait un **`COUNT` réel** sur
  les vulnérabilités du moteur du scan et de ses assets, **après `db.flush()`** (`scan_assets.py`,
  `tasks._store`, `vulnerabilities/.../tasks.py`). Le compteur ne peut donc pas dépasser le nombre de lignes.
- Plus aucune bascule Nuclei → OpenVAS (C4) : un échec Nuclei donne `FAILED`, pas un scan OpenVAS.
- Preuve : `tests/test_reliability.py::test_rescan_does_not_double_count_findings` (compteur = 1 après deux
  passages).

---

## 4. Plan de correction (ce lot)

Priorité 1 (les scans aboutissent) : R6, R7, R10/R16, script de reprise.
Priorité 2 (résultats exacts) : R8, R9 (fait), R16 (fait), R11, R5, C2/N1.
Priorité 3 (garde-fou, diagnostic, déploiement test) : R18, R12, R13, R14, R15, R17.

Hors périmètre (avant production, à ne pas aggraver) : S3, ports internes, Vault dev, CORS, TLS, périmètre par société.

---

## 5. Statut final après corrections (lot livré)

Commits backend après la revue : arrêt de scan et des workers, suivi OpenVAS borné, rétention,
garde-fou de périmètre, feed OpenVAS, image figée, script de reprise, tests. **89 tests passent**
(+ 1 test de migration ignoré sans PostgreSQL).

| Constat | Statut final | Preuve |
|---|---|---|
| R5 découverte target_states | **corrigé** | `tasks._finish_discovery` ; test_discovery_sets_every_target_state |
| R6 arrêt des workers / routage | **corrigé (arrêt propre)** ; *partiel* pour un crash brutal (couvert par le chien de garde, mais après le seuil de silence) | `base_adapter` registre + `worker_signals.py` ; garde-fou de routage ; tests shutdown/redispatch. **Limitation documentée** : `visibility_timeout=26h` reste nécessaire pour ne pas réexécuter un scan long ; un message réservé par un worker tué brutalement attend ce délai (inhérent à acks_late + Redis). |
| R7 suivi OpenVAS borné | **corrigé** | `poll_scan_status` (creation_time, fin si clos/supprimé/pause, relances bornées) |
| R8 purge au démarrage | **corrigé** | `main.py` purge retirée ; `cleanup_old_data` (Beat) ; test |
| R9 compteur | **corrigé** | `count_scan_findings` (COUNT) ; test_rescan_does_not_double_count_findings |
| R10 arrêter un scan | **corrigé** | `PUT /scans/{id}/stop` + `stop_scan_task` ; test_stop_scan_revokes_tasks_and_stops_openvas |
| R11 feed + figée + limite de tâches | **corrigé** (feed, figée) ; *atténué* (limite) | `check_feeds` ; détection de figée (`OPENVAS_STALL_HOURS`). **Limite de tâches simultanées** : non implémentée, mais `SCAN_CONCURRENCY=1` + suppression de la bascule cachée bornent déjà le nombre de tâches GVM. |
| R12 logs | **corrigé** | rotation 20 Mo × 5 uniforme ; `scan_id` ajouté aux lignes OpenVAS |
| R13 image | **corrigé** (nuclei figé, templates vérifiés, vulscan retiré) ; *à finaliser* | `Dockerfile`. **À faire avant la production** : épingler `NUCLEI_SHA256` et `VULNERS_REF` sur un commit + checksum. Le build échoue désormais si un ref est invalide. |
| R14 code monté | **corrigé** | montages déplacés dans `docker-compose.override.yml` |
| R15 ressources | **corrigé** | `SCAN_CONCURRENCY=1` ; `mem_limit` worker/openvas |
| R16 (4 points) | **corrigé** | limite douce 23 h, reprise, asset manuel, ZAP redirigé (commit `c356135`) |
| R17 dépôts/doc | **corrigé (doc)** ; *note* | nombre de tests mis à jour. Le `main` du déploiement pointe backend `074c2b6` à cause de la fusion anticipée de la PR #1 : à régulariser en fusionnant la PR du backend. |
| R18 périmètre | **corrigé** | `SCAN_ALLOWED_TARGETS` ; tests ; 403 + audit |
| C2/N1 identifiants sur la ligne de commande | **corrigé** | Nuclei (fichier 0600), ZAP (API locale) ; tests |

### Critères de livraison en recette
1. Priorité 1 et 2 : aucun « partiel » bloquant. R6 (crash brutal) et R11 (limite de tâches) sont
   atténués et documentés, pas bloquants.
2. 89 tests passent (S1, S2, XSS inclus).
3. **Test de bout en bout du laboratoire : à exécuter par l'équipe** (`scripts/verify_scanner_e2e.py`
   sur `lab/docker-compose.lab.yml`). Non exécuté dans ce lot (pas de Docker sur le poste de dev).
4. Recherche de secrets : à lancer par l'équipe (par exemple gitleaks). Les seuls secrets du dépôt
   sont les **valeurs par défaut** (`kimia_password`, `admin`) et un **mot de passe de test** du
   laboratoire (`labpass123`) — pas de secret réel. Les secrets par défaut relèvent de S3 (hors lot).
5. Procédure de déploiement et de retour arrière : `docs/CORRECTIFS_FIABILITE_SCANS.md`.

## 6. Décisions laissées à l'équipe
- **Profil de vulners 2.x** : le script `vulners` est `intrusive` (balayage HTTP) et `external`
  (il envoie les produits/versions détectés à vulners.com). Décision de confidentialité : garder
  `vulners` par défaut, ou le réserver à une policy. Proposition : le laisser actif en interne,
  le rendre désactivable par policy pour les cibles sensibles.
- **Durée de conservation** : `AUDIT_RETENTION_DAYS` (90) et `RAW_OUTPUT_RETENTION_DAYS` (30) par défaut.
- **Concurrence** : `SCAN_CONCURRENCY=1` par défaut (sûr). À augmenter selon la RAM (≈ 1,5–3 Go par scan).
- **Épinglage des versions** : confirmer `NUCLEI_VERSION`/`VULNERS_REF` et ajouter les checksums.

---

## 7. Audit du lot (relecture critique)

Relecture du code livré, à la recherche d'anomalies pouvant **empêcher un scan de fonctionner**.

### Anomalies bloquantes trouvées et corrigées (commit « Audit : … »)
- **A1 — Vérification du feed OpenVAS fermée** : `check_feeds` renvoyait « feed absent » dès que la
  structure du feed différait de l'attendu, ce qui aurait fait échouer **tous** les scans OpenVAS.
  Rendue prudente (fail-open) : ne bloque que sur un feed NVT lu comme absent/en synchronisation.
- **A2 — ZAP authentifié** : `replacer/addRule` sans `matchRegex` (paramètre requis) aurait fait
  échouer tout scan ZAP avec identifiants. Corrigé, avec dégradation en scan non authentifié si l'API
  refuse, au lieu d'un échec total.

### Limites connues, non bloquantes (à valider sur le serveur)
- **Arrêt d'un scan moteur (Nmap/Nuclei/ZAP)** : la tâche Celery est révoquée (pas de réexécution) et
  la cible passe INTERRUPTED. L'arrêt via SIGTERM laisse en principe la tâche tuer son processus
  scanner (groupe de processus), mais c'est du « meilleur effort » : à confirmer sous charge réelle.
  L'arrêt d'un scan OpenVAS est propre (tâche GVM arrêtée).
- **Nuclei authentifié** : l'en-tête est passé par un fichier de config (`header:`). Si la clé diffère
  selon la version de Nuclei, le scan se dégrade en non authentifié (visible dans les logs), sans
  bloquer les scans non authentifiés. À confirmer avec la version figée.
- **API ZAP (durées max)** : `setOptionMaxDuration` / `setOptionMaxScanDurationInMins` — noms d'API à
  confirmer sur la version 2.17 de ZAP (sinon le scan ZAP échoue, de façon visible).
- **Dockerfile** : si `NUCLEI_VERSION` ou `VULNERS_REF` sont invalides, le **build échoue** (volontaire,
  plus de `|| true`). Confirmer les refs et ajouter les checksums avant la production.

### Vérifié sans anomalie
- Garde-fou de routage : pas de boucle (seul `default@` est redirigé, vers la file `scans`).
- Révocation d'un scan arrêté : `revoke` empêche la réexécution même en cas de redelivery `acks_late`.
- Suivi OpenVAS : compteur d'échecs de connexion séparé des relances de polling (pas d'arrêt prématuré
  d'un scan sain).
- Mises à jour d'état sous verrou de ligne (pas d'écrasement entre deux cibles simultanées).

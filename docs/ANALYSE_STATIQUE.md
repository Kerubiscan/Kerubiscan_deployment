# Analyse statique de Kerubiscan (KVS) : efficacité des scans, stabilité et sécurité

- **Date** : 6 octobre 2026
- **Code analysé** : `Kerubiscan_deployment` @ `08a9a0f`, `Kerubiscan_backend` @ `2a95559`, `Kerubiscan_frontend` @ `0b53a6c`
- **Méthode** : lecture du code uniquement. Aucun scanner, aucun conteneur et aucune base de données n'a été lancé. Un seul test a été exécuté localement : le parser Nuclei sur une sortie d'exemple (voir l'annexe C). Le parser Nmap n'a pas pu être exécuté, car `lxml` n'est pas installé sur le poste.
- **Niveaux de certitude** :
  - **Certain** : le défaut se lit directement dans le code ;
  - **Probable** : il dépend du comportement d'un outil externe ou des données réelles ;
  - **À vérifier** : impossible à trancher sans exécution.

Sauf mention contraire, les chemins sont relatifs à `Kerubiscan_backend/`.

---

## 1. Résumé

Le faible nombre de vulnérabilités ne vient pas principalement d'une mauvaise utilisation. **Le code perd ou dégrade une grande partie des résultats après l'exécution des scanners.** Causes classées par impact :

1. **Les résultats Nmap sont vidés à l'enregistrement** (C1, certain). `parse_nmap_report` lit des clés que le parser Nmap ne produit pas. Résultat : aucun CVSS, aucune description, et une sévérité jamais supérieure à MEDIUM.
2. **Les scans authentifiés ne s'authentifient jamais** (C2, certain). Le type d'identifiant n'est pas stocké dans Vault, donc aucun moteur n'active l'authentification. OpenVAS ignore en plus totalement les identifiants.
3. **Les scans « Application » (URL) échouent toujours** (C3, certain). L'interface demande `https://exemple.com`, mais la phase 1 Nmap rejette toute URL. Après les retries, le code bascule à tort sur un scan OpenVAS (C4).
4. **Les noms de domaine sont remplacés par leur IP** (C5 et C6, certains). Nuclei reçoit `http://IP:port` (perte de l'en-tête Host, du SNI et du virtual host), et l'asset perd son domaine au profit de l'IP. Les scans suivants lancés depuis la page Assets ciblent donc l'IP.
5. **ZAP ne teste que les ports 80 et 443** (C7, certain), et il **peut se bloquer** à cause de pipes jamais lus et de boucles sans limite de durée (C8, probable).
6. **Les scans d'un sous-réseau en mode vulnérabilité regroupent tous les résultats sur un seul asset** (C9, certain).
7. **Un scan sans résultat ou en échec s'affiche « COMPLETED »** (C10, certain). On ne peut pas distinguer « aucune vulnérabilité » de « scan non effectué ».
8. **La déduplication par titre écrase des résultats réels** (C11, certain ; testé : 4 résultats Nuclei donnent 2 enregistrements).
9. Côté sécurité, **13 routes de l'API répondent sans authentification** (S1). Toute personne connectée peut lancer des scans actifs, quel que soit son rôle (S2).

**Verdict global : défaut de code d'abord, configuration ensuite, utilisation en dernier.**

---

## 2. Fiches par moteur

Tous les moteurs passent par `run_vulnerability_scan` (`src/scans/application/services/tasks.py:394`), appelé une fois par cible séparée par une virgule (`src/scans/adapters/inbound/api/endpoints.py:179-180`). Nmap, Nuclei et ZAP commencent par une **phase 1 Nmap** commune, dont le code est dupliqué trois fois (lignes 473-534, 586-666 et 731-792).

### 2.1 Nmap — verdict : **défectueux** (certain)

**Commandes reconstituées** (`src/scans/adapters/outbound/nmap_adapter.py`) :

```text
# Phase 1 (run_detailed_discovery_scan, l.116-120)
nmap -sS -sV -O -Pn --max-retries 2 --host-timeout 30m -p- -T4 \
     --script nbstat,smb-os-discovery [--script-args-file <fichier>] -oX out.xml -- <cible>

# Phase 2 (run_vulnerability_scan, l.143-148), seulement sur les ports ouverts trouvés en phase 1
nmap -sS -sV -Pn --max-retries 2 --host-timeout 30m -p <ports> \
     --script "vuln and safe,vulners,vulscan/" [--script-args-file <fichier>] -oX out.xml -- <cible>
```

Pour une IP ou un domaine, la commande est identique : Nmap résout lui-même le domaine. `<cible>` passe par `_validate_targets` (l.16-27) : IP, CIDR ou nom d'hôte. **Les URL sont refusées** (voir C3).

**Limites de détection** :
- `vuln and safe` exclut tous les scripts `vuln` classés `intrusive`, qui sont nombreux (C13, probable).
- `vulners` interroge l'API vulners.com et ne donne rien sans accès Internet sortant (à vérifier).
- `vulscan/` interroge toutes ses bases locales et produit souvent des centaines de correspondances par service, pour la plupart des faux positifs (C13, probable).
- Les cibles IPv6 sont acceptées par la validation, mais les commandes n'ont pas l'option `-6` (C20, certain).

**Parsing** (`_parse_nmap_xml`, l.192-375) : correct dans l'ensemble. Pour chaque résultat, il produit `{id, name, description, cvss_score, severity, cve_id}`.
- La sévérité est grossière : « high » si CVSS > 7.0, sinon « medium », et jamais « critical » (l.276 et 316).
- Un script qui renvoie « VULNERABLE » sans CVE est classé « info » (l.347-352).

**Enregistrement** (`parse_nmap_report`, `src/vulnerabilities/application/services/tasks.py:262`) : **c'est le défaut principal (C1).**

| Le parser produit | `parse_nmap_report` lit | Conséquence |
|---|---|---|
| `name` = « Port 443 Vuln CVE-… » | `title = v.get("id")` (l.316) | Le titre affiché est un identifiant technique (`nmap-443-cve-2014-0160`) |
| `description` | `v.get("output", "")` (l.318) | **Description toujours vide** |
| `cvss_score` | `v.get("cvss")` (l.320) | **CVSS toujours à 0** |
| `severity` | ignoré | La sévérité est recalculée à partir de la description vide : **INFO**, ou **MEDIUM** si un CVE est présent (l.334-348) |

En plus, aucun `contextual_risk_score` n'est calculé pour Nmap (l.359-368). Ces vulnérabilités sont donc absentes des tris par risque, par exemple dans le résumé IA.

### 2.2 Nuclei — verdict : **dégradé** (certain pour les domaines, probable pour le reste)

**Commande** (`src/scans/adapters/outbound/nuclei_adapter.py:41`) :

```text
nuclei -duc -nc -l targets.txt -jle results.jsonl [-H "Authorization: Basic …"]
```

`targets.txt` est construit dans `tasks.py:597-628` à partir de la phase 1 :
- pour un service reconnu comme web : `http://<IP>:<port>` ou `https://<IP>:<port>` ;
- sinon : `<IP>:<port>`.

**Pour un domaine, c'est toujours l'IP qui est utilisée**, car `host_ip` vient du XML Nmap (C5).

**Limites** :
- Le domaine est perdu (C5). Derrière un reverse proxy, un CDN ou un hébergement mutualisé, Nuclei ne teste que la page par défaut, et le certificat ou le SNI ne correspondent pas.
- `-duc` désactive la vérification des mises à jour. Les templates dépendent de l'image (`RUN nuclei -ut || true` dans le Dockerfile : **un échec à la construction de l'image est ignoré**) et de la tâche Beat quotidienne `update_nuclei_templates`. Le nombre réel de templates est à vérifier.
- Un service web non reconnu par Nmap (`unknown`, `tcpwrapped`) n'est passé que sous la forme `IP:port`. Que Nuclei fasse ou non une détection HTTP automatique sur ce format est à vérifier.

**Parsing** (`_parse_nuclei_jsonl`, l.75-117) : correct. Testé : 4 lignes donnent 4 résultats (annexe C).

**Enregistrement** (`parse_nuclei_report`) : la déduplication se fait **par titre seulement, tous moteurs confondus** (l.438-439 et 475). Le même template trouvé sur deux ports, ou avec plusieurs `matcher-name`, ne donne qu'une seule ligne (C11, testé). Le port n'est jamais stocké.

### 2.3 OWASP ZAP — verdict : **dégradé, avec risque de blocage**

**Appels reconstitués** (`src/scans/adapters/outbound/zap_adapter.py`) :

```text
zap.sh -daemon -host 127.0.0.1 -dir <tmp> -port <libre> -config api.key=<aléatoire> [replacer Basic Auth]
GET https://<cible>  (test, délai 3 s, sinon http://<cible>)      l.124-133
/JSON/core/action/accessUrl  →  /JSON/spider/action/scan  →  attente de status == "100"   l.136-149
/JSON/ascan/action/scan  →  attente de status == "100"                                  l.151-166
/JSON/core/view/alerts  →  /JSON/core/action/shutdown                                   l.168-173
```

`<cible>` est la chaîne saisie, c'est-à-dire le domaine s'il y en a un (`tasks.py:802`). C'est correct pour un domaine **lors du premier scan seulement** (voir C6).

**Limites** :
- **Seuls les ports par défaut (80 et 443) sont testés.** Les ports web trouvés en phase 1 (8080, 8443, etc.) sont ignorés (C7, certain).
- Il n'y a pas d'AJAX spider : une application SPA (Angular, React) est très mal explorée (probable).
- Il n'y a **aucune limite de durée** pour le spider ni pour le scan actif. Si l'API ne renvoie pas `status`, la boucle ne s'arrête jamais (l.145-149 et 162-166).
- **`stdout` et `stderr` du daemon sont en `PIPE` et ne sont jamais lus** (l.94-101). Quand le tampon du pipe (environ 64 Ko) est plein, la JVM se bloque en écriture, et la tâche reste bloquée jusqu'à la limite Celery de 24 h (C8, probable).
- `-Xmx512m` peut être insuffisant pour un scan actif sur une application volumineuse (à vérifier).

**Parsing** (`_parse_zap_alerts`) : correct. L'URL concernée est placée dans `matched_at`.

**Enregistrement** (`parse_zap_report`) : `matched_at` **n'est jamais enregistré** (l.582-584 lit une clé `reference` qui n'existe pas). La déduplication par titre réduit toutes les occurrences d'une alerte à une seule ligne, sans URL. L'analyste ne sait donc pas où se trouve la faille (C11).

### 2.4 OpenVAS / GVM — verdict : **dégradé** (probable)

**Appels** (`src/scans/adapters/outbound/gvm_adapter.py` et `tasks.py:817-837`) :

```text
create_target(hosts=[<cible>], alive_test=CONSIDER_ALIVE, port_range="T:1-65535,U:1-65535")
create_task(config_id="daba56c8-…" (Full and fast), scanner_id="08b69003-…")
start_task  →  poll_scan_status toutes les 10 s, sans limite (max_retries=None)
get_report(details=True, ignore_pagination=True)  →  parse_scan_report
```

**Limites** :
- **Tous les ports UDP sont scannés par défaut** (`T:1-65535,U:1-65535`, `tasks.py:824`). Un scan peut alors durer des heures, voire des jours (probable). Avec une policy, seul TCP est conservé, et une plage qui commence par `!` retombe sur la valeur par défaut (l.825-829).
- **Les identifiants ne sont jamais transmis à OpenVAS** : aucune création de credential GVM. Les scans ne sont donc jamais authentifiés (C2).
- Les états « Stopped » et « Interrupted » sont traités comme un succès, et le scan finit « COMPLETED » (l.874-892).
- Le rapport XML complet est écrit dans les logs au niveau INFO (`gvm_adapter.py:129`). Avec la rotation Docker à `max-size: 100k` et `max-file: 1`, **un seul rapport efface tous les autres logs** (C18, certain).
- Le filtre par défaut de `get_report` (seuil de QoD) peut masquer des résultats à faible QoD (à vérifier).

**Parsing** (`parse_scan_report`) :
- La déduplication par **CVE** fusionne la même faille trouvée sur plusieurs ports (l.184-190).
- Si la cible est un domaine, `host[ip='<domaine>']` ne correspond à rien : l'OS et les ports ne sont pas enrichis (l.96).
- `vulnerabilities_found` compte aussi les résultats de type Log (l.241).

---

## 3. Parcours d'un scan de domaine (`app.exemple.com`)

| Étape | Code | Ce qui se passe | Perte d'information |
|---|---|---|---|
| 1. Saisie | `NewScanModal.tsx:201-212` | Avec « Application Scan », l'interface **demande une URL** (`https://example.com`). | **Toute URL fait échouer le scan (C3).** Il faut saisir le domaine nu. |
| 2. Création | `scans/…/endpoints.py:113-180` | Aucune validation de la cible. Découpage par virgule, puis une tâche par cible. `WEB_APP` est traité comme `VULNERABILITY`. | Aucune erreur claire n'est renvoyée à l'utilisateur. |
| 3. Phase 1 Nmap | `nmap_adapter.py:110-130` | Nmap résout le domaine et scanne **la première IP seulement** (comportement standard de Nmap, probable). | Les autres IP du domaine ne sont pas scannées. |
| 4. Enregistrement de l'asset | `tasks.py:498-531` | Asset recherché par `ip_address == domaine`, puis par `name == domaine`, puis par `ip_address == IP`. **`asset.ip_address` est remplacé par l'IP** (l.524-529). | Le domaine ne survit que dans `name`, et seulement si l'asset a été créé par le scan. |
| 5a. Nuclei | `tasks.py:597-628` | Cibles construites sous la forme `http(s)://<IP>:<port>`. | **En-tête Host, SNI et virtual host perdus (C5).** |
| 5b. ZAP | `tasks.py:802`, `zap_adapter.py:124-133` | Cible = domaine, sur les ports 80 et 443 uniquement. | Les ports non standard sont perdus (C7). |
| 5c. Nmap phase 2 | `tasks.py:557` | Cible = domaine. | Sans conséquence notable. |
| 6. Enregistrement des vulnérabilités | `vulnerabilities/…/tasks.py` | Asset retrouvé par `name == domaine`. | Correct si l'asset porte bien le domaine en `name`. |
| 7. Scan suivant depuis la page Assets | `assets/page.tsx:174, 186, 255` | La cible envoyée est `asset.ip_address`, **qui est maintenant l'IP**. | **Tous les scans suivants ciblent l'IP (C6).** Même ZAP perd alors le virtual host. |

**Cas non gérés** : domaine qui ne se résout pas (Nmap échoue, 3 retries, puis ABANDONED et bascule sur OpenVAS, voir C4) ; domaine avec plusieurs IP ; IPv6 ; redirection vers un autre domaine (rien ne limite le périmètre de ZAP à part son comportement par défaut).

---

## 4. Tableau des constats

Gravité : **C** = critique, **H** = haute, **M** = moyenne, **B** = basse.

### 4.1 Efficacité des scans et fiabilité des résultats

| N° | Axe | Grav. | Certitude | Emplacement | Description | Scénario | Correction proposée |
|---|---|---|---|---|---|---|---|
| C1 | Moteurs | **C** | Certain | `vulnerabilities/application/services/tasks.py:316-320` | `parse_nmap_report` lit `id`, `output` et `cvss` au lieu de `name`, `description` et `cvss_score`. | Heartbleed (CVSS 7.5) détecté : enregistré avec le titre `nmap-443-cve-2014-0160`, sans description, CVSS 0, sévérité MEDIUM. | Lire les bonnes clés et reprendre la `severity` de l'adaptateur. Calculer le `contextual_risk_score`. Ajouter un test sur une sortie XML réelle. |
| C2 | Moteurs | **C** | Certain | `secrets/adapters/inbound/api/endpoints.py:86` (et équivalents) ; `nmap_adapter.py:59` ; `nuclei_adapter.py:43` ; `zap_adapter.py:71` ; `tasks.py:454-460` | `credential_type` est exclu des données envoyées à Vault, alors que les adaptateurs en ont besoin pour activer l'authentification. OpenVAS ignore totalement les identifiants. | Identifiant SSH ajouté sur un asset, puis scan : aucune option d'authentification n'est passée, et le scan reste non authentifié sans aucun avertissement. | Fusionner `credential.credential_type` (base) avec le secret Vault dans `run_vulnerability_scan`. Créer les credentials GVM pour OpenVAS. Journaliser « scan authentifié : oui/non ». |
| C3 | Utilisation et code | **C** | Certain | `NewScanModal.tsx:201-212` ; `nmap_adapter.py:16-27` | L'interface demande une URL pour « Application Scan », mais la phase 1 Nmap, commune à tous les moteurs, rejette les URL. | `https://site.com` avec ZAP : ValueError, 3 retries, puis ABANDONED, puis bascule sur OpenVAS (C4). | Côté API : accepter une URL, extraire hôte, port et schéma, et passer l'URL complète à ZAP et Nuclei. Côté interface : corriger le texte d'aide. |
| C4 | Orchestration | **H** | Certain (code) / Probable (comportement Celery) | `tasks.py:570-579`, `683-692`, `720-723`, `806-815`, puis `817` | Quand les retries sont épuisés, les branches NMAP, NUCLEI et ZAP ne font pas de `return`. L'exécution continue jusqu'au bloc OpenVAS. Si GVM est injoignable, `self.retry(max_retries=60)` relance **toute** la tâche, phase 1 Nmap comprise, jusqu'à 60 fois. | Une cible Nuclei injoignable lance ensuite un scan OpenVAS complet (TCP et UDP) non demandé, ou 60 nouveaux scans Nmap `-p-`. | Ajouter `return` après `ABANDONED`. Créer une fonction par moteur. Ne jamais tomber par défaut sur OpenVAS. |
| C5 | Domaines | **H** | Certain | `tasks.py:597-628` | Les URL Nuclei sont construites avec l'IP résolue au lieu du domaine. | Un site derrière un reverse proxy : Nuclei ne voit que la page par défaut et trouve très peu de choses. | Construire `http(s)://<domaine>:<port>` quand la cible est un nom d'hôte. Conserver l'IP pour les templates réseau. |
| C6 | Domaines | **H** | Certain | `tasks.py:524-529`, `656-661`, `782-787` ; `assets/page.tsx:174, 186, 255` | `asset.ip_address` est écrasé par l'IP, et la page Assets relance les scans sur `ip_address`. | Deuxième scan du domaine depuis Assets : la cible est l'IP, même pour ZAP. | Ajouter un champ `hostname` ou `fqdn` à l'asset (migration). Ne plus écraser. Relancer les scans sur le domaine. |
| C7 | Moteurs | **H** | Certain | `tasks.py:802` ; `zap_adapter.py:124-133` | ZAP ignore les ports trouvés en phase 1 : seuls `https://cible` ou `http://cible` sont testés. | Une application sur le port 8080 n'est jamais testée par ZAP. | Passer à ZAP la liste des URL web issue de la phase 1, comme pour Nuclei. |
| C8 | Stabilité | **H** | Probable | `zap_adapter.py:94-101`, `145-149`, `162-166` | `stdout` et `stderr` en PIPE jamais lus, et boucles d'attente sans limite de durée. | Un long scan actif bloque la JVM ; la tâche reste bloquée jusqu'à 24 h et occupe un slot du worker. | Rediriger vers un fichier ou `DEVNULL`. Configurer `spider.maxDuration` et `ascan.maxScanDurationInMins`, et ajouter une limite globale. |
| C9 | Orchestration | **H** | Certain | `tasks.py:498-506` ; `core/database.py:12` (`autoflush=False`) ; `vulnerabilities/…/tasks.py:270-272` | Avec un CIDR en mode vulnérabilité, la phase 1 crée un asset par hôte, mais tous portent le nom du CIDR. Toutes les vulnérabilités de la phase 2 sont ensuite rattachées au premier asset trouvé (`.first()`). | `10.0.0.0/24` avec Nmap : les failles de 20 hôtes apparaissent sur un seul asset. | Éclater le CIDR en hôtes après la phase 1, avec une tâche et un `target_state` par hôte, et rattacher chaque résultat par son IP. |
| C10 | Orchestration | **H** | Certain | `tasks.py:547-551`, `668-672`, `794-798` ; `tasks.py:88-92` | Une phase 2 sautée (aucun port trouvé, ou hôte abandonné par `--host-timeout`) donne « COMPLETED ». `FAILED` et `ABANDONED` comptent aussi comme terminés, donc le scan global est « COMPLETED » même si tout a échoué. | Un hôte filtré donne un scan « COMPLETED » sans vulnérabilité, et l'analyste conclut que l'hôte est sain. | Ajouter des statuts `COMPLETED_WITH_ERRORS` ou `NO_SERVICE_FOUND`, avec le motif affiché dans l'interface. |
| C11 | Enregistrement | **M** | Certain (testé) | `vulnerabilities/…/tasks.py:438-439, 475` (Nuclei) ; `565-566, 598, 582-584` (ZAP) ; `184-190` (OpenVAS) | Déduplication par titre (Nuclei, ZAP) ou par CVE (OpenVAS), sans tenir compte du port ni de l'URL. Pour Nuclei et ZAP, elle se fait aussi tous moteurs confondus. | Le même CVE sur les ports 80 et 8080 ne donne qu'une ligne (test : 4 résultats donnent 2 lignes). | Clé de déduplication = (asset, moteur, identifiant de règle, port ou URL). Stocker `port` et `matched_at`. |
| C12 | Moteurs | **M** | Certain | `nmap_adapter.py:276, 316, 347-352` | La sévérité Nmap n'a que deux niveaux (high ou medium) et « VULNERABLE » sans CVE donne « info ». | CVSS 9.8 donne « high » ; `smb-vuln-*` sans CVE donne « info ». | Utiliser l'échelle CVSS complète et détecter `State: VULNERABLE`. |
| C13 | Configuration | **M** | Probable | `nmap_adapter.py:146` ; `vulnerabilities/page.tsx:131` | `vuln and safe` limite la détection ; `vulscan` génère beaucoup de bruit. L'interface ne charge que les 500 dernières vulnérabilités. | Le bruit de vulscan repousse les vraies failles au-delà de la limite de 500. | Rendre les scripts configurables par policy. Désactiver vulscan par défaut ou le restreindre à une base. Paginer côté serveur. |
| C14 | Enregistrement | **M** | Certain | `tasks.py:498-502` (et l.630-634, 756-760) ; `vulnerabilities/…/tasks.py:72-74, 270-272, 412-414, 539-541` | Les recherches d'asset ne filtrent ni `company_id` ni `is_deleted`. | Après la suppression d'un asset, un nouveau scan attache ses résultats à l'asset supprimé (invisible dans Assets). Deux clientes avec la même IP privée : les résultats peuvent être croisés. | Filtrer sur `company_id` et `is_deleted == False` partout. |
| C15 | Utilisation | **M** | Certain | `tasks.py:437-452` ; `NewScanModal.tsx:66-75` ; `scans/…/endpoints.py:295-303` ; `scheduling/…/tasks.py:52-61` | L'interface ne permet pas de choisir une policy ou un identifiant. Le backend applique alors **la première policy de la société** et **le premier identifiant de l'asset**, quel que soit son type. `update_scan` ignore `policy_id` et `credential_id`. Les scans planifiés ne les transmettent pas. | Une policy « ports 80,443 » créée pour un autre usage limite silencieusement tous les scans de la société. | Choix explicite dans l'interface, aucune sélection implicite, et affichage de la policy utilisée dans le détail du scan. |
| C16 | Orchestration | **M** | Certain / Probable | `scheduling/application/services/tasks.py:52-61`, `31-42` | Les scans récurrents sont créés sans `target_states`, donc le scan passe « COMPLETED » dès la première cible terminée (certain). Le déclenchement exige une égalité exacte sur l'heure et la minute : si la tâche Beat s'exécute en retard derrière de longs scans, le créneau est manqué (probable). | Un planning à 02:00 est sauté quand le worker est occupé. | Initialiser `target_states`. Stocker `next_run_at` en datetime et déclencher quand `<= now`. Utiliser une file Celery dédiée pour Beat. |
| C17 | Moteurs | **M** | Probable | `tasks.py:824, 855-904` | OpenVAS : scan UDP complet par défaut ; polling infini ; « Stopped » et « Interrupted » traités comme un succès. | Scan OpenVAS toujours « en cours » après 48 h. | Utiliser une liste de ports GVM standard (« All IANA TCP »), une durée maximale et un statut d'échec en cas d'interruption. |
| C18 | Diagnostic | **M** | Certain | `gvm_adapter.py:129` ; `docker-compose.yml` (`max-size: 100k`, `max-file: 1`) | Le rapport XML complet est écrit dans les logs, et la rotation ne garde que 100 Ko. | Après un scan OpenVAS, les logs des autres scans ont disparu. | Logger seulement la taille du rapport (DEBUG). Augmenter la rétention des logs. |
| C19 | Découverte | **M** | Certain | `nmap_adapter.py:94` ; `tasks.py:164-166` ; `tasks.py:359-368` | Découverte Nmap = ping sweep `-sn` : les hôtes qui ne répondent pas au ping sont invisibles. Une seule erreur sur un hôte fait échouer toute la découverte. La découverte OpenVAS recrée des assets en double à chaque exécution. | Un serveur qui filtre l'ICMP est absent de l'inventaire. | Ajouter des sondes TCP (`-PS`/`-PA`) ; mettre un try/except par hôte ; dédupliquer par (société, IP). |
| C20 | Domaines | **B** | Certain / Probable | `nmap_adapter.py:22` | IPv6 accepté par la validation, mais pas d'option `-6`. Nmap ne scanne que la première IP d'un domaine. | Une cible `2001:db8::1` échoue toujours. | Ajouter `-6` pour l'IPv6 ; utiliser `--resolve-all` ou éclater les IP. |
| C21 | Stabilité | **M** | Certain | `src/main.py:44-80` | Au démarrage, l'API met en pause tous les scans `IN_PROGRESS` (alors que le worker continue), purge les données et mélange `create_all` et `alembic stamp`. | Redémarrer seulement l'API met en pause des scans actifs, dont les résultats arrivent ensuite sur un scan « PAUSED ». | Sortir ces opérations du démarrage : migrations explicites, purges dans Beat, et récupération des scans orphelins basée sur l'état réel de Celery. |
| C22 | Rapports | **M** | Certain | `scans/…/endpoints.py:353-357` ; `endpoints.py:593` | Le résumé IA cherche les vulnérabilités par `ip_address == scan.target`, ce qui ne donne rien pour un domaine, un CIDR ou plusieurs cibles. Le rapport PDF d'un sous-réseau parcourt **tous les assets de toutes les sociétés**. | Rapport PDF pour `10.0.0.0/24` d'une cliente A : il inclut les assets de la cliente B dans la même plage. | Utiliser les assets réellement liés au scan (table de liaison) et filtrer par société. |
| C23 | Données | **B** | Certain | `vulnerabilities/…/tasks.py:241, 383, 510, 639` | `vulnerabilities_found` est tantôt écrasé, tantôt incrémenté, et compte aussi les logs. | Compteur incohérent dans le cas de plusieurs cibles. | Calculer le compteur à partir de la table des vulnérabilités. |
| C24 | Base de données | **H** | À vérifier | `alembic/versions/a93e432317eb_add_scanner_engines.py:23` | L'enum PostgreSQL `scannerengine` créé par migration ne contient pas `OWASP_ZAP`, et aucune migration ne l'ajoute. Seules les bases initialisées par `create_all` l'ont. | Sur une base migrée depuis une ancienne version, créer un scan ZAP provoque une erreur 500 (`invalid input value for enum`). | Migration `ALTER TYPE scannerengine ADD VALUE IF NOT EXISTS 'OWASP_ZAP'`. |

### 4.2 Sécurité de l'API et du déploiement

| N° | Grav. | Certitude | Emplacement | Description | Correction proposée |
|---|---|---|---|---|---|
| S1 | **C** | Certain | voir annexe A | 13 routes sans authentification, dont la génération de rapports complets de vulnérabilités (`/reporting/{id}/html|pdf`, `/scans/{id}/report/*`), la liste des scans et des sociétés, et la modification du résumé exécutif. | Ajouter `require_permissions` sur chaque route, et un test automatique qui parcourt toutes les routes. |
| S2 | **H** | Certain | `scans/…/endpoints.py:97, 114, 238, 264, 288, 526, 648, 685` ; `vulnerabilities/…/endpoints.py:56` ; `audit/…/endpoints.py:17-19` | Les scans n'exigent qu'une connexion : un **Reader** peut lancer un scan actif, supprimer **tous** les scans ou une société. Changer le statut d'une vulnérabilité exige seulement `ASSET_READ`. Le contrôle de rôle du journal d'audit est commenté. | Ajouter les permissions `SCAN_READ`, `SCAN_EXECUTE` et `SCAN_DELETE`, et `VULN_WRITE`. Réactiver le contrôle d'audit. |
| S3 | **H** | Certain | `docker-compose.yml` ; `.env.template` ; `realm-export.json` ; `src/main.py:93` | Vault en mode dev (token root, **secrets perdus à chaque redémarrage**). Mots de passe par défaut pour Keycloak, Postgres et OpenVAS, et secrets de clients fixes. Postgres, Redis, Vault et RabbitMQ publiés sur l'hôte. CORS `*` avec credentials. | Générer des secrets à l'installation, faire tourner Vault en mode serveur, ne plus publier les ports internes et restreindre CORS. |
| S4 | **M** | Certain | `scans/…/endpoints.py:257-261, 281-285` | Les erreurs 500 renvoient la trace complète (`traceback`) au client. | Renvoyer un message générique et garder le détail dans les logs. |
| S5 | Info | Certain | `nmap_adapter.py:16-41, 94, 120, 148` ; `nuclei_adapter.py:37-41` ; `zap_adapter.py:138-155` ; `gvm_adapter.py:47-63` | **Point positif.** Injection d'options : Nmap valide les cibles et les ports et les place après `--`. Nuclei lit ses cibles dans un fichier. ZAP et OpenVAS passent par des API. Aucun `shell=True`. Seule réserve : ni Nuclei ni ZAP ne valident la cible. | Centraliser la validation des cibles dans l'API. |
| S6 | **H** | Certain | `.git/config` du dépôt de déploiement (pas dans le code) | Un token GitHub personnel figure dans l'URL du remote `origin`. | Révoquer le token et retirer l'URL. (Valeur volontairement non reproduite ici.) |

### 4.3 Qualité et déploiement

| N° | Grav. | Certitude | Constat |
|---|---|---|---|
| Q1 | M | Probable | `lxml` et `requests` sont importés directement mais absents de `requirements.txt`. Ils n'arrivent que comme dépendances de `python-gvm` et `python-keycloak`. |
| Q2 | M | Certain | Images non figées (`immauss/openvas:latest`, `projectdiscovery/nuclei:latest`) et `nuclei -ut \|\| true` dans le Dockerfile. |
| Q3 | M | Certain | Code source monté en volume (`./Kerubiscan_backend/src:/app/src`) en production. |
| Q4 | B | Certain | Valeurs codées en dur : `AI_ENDPOINT` vers `192.168.1.56`, `TZ=Africa/Lagos`, e-mail par défaut `admin@KVS.local`. |
| Q5 | B | Certain | Client Keycloak du frontend nommé `kerubiscan-web` par défaut dans `docker-compose.yml`, mais `KVS-web` dans `.env.template` et `realm-export.json`. |
| Q6 | B | Certain | Scripts de debug versionnés : `alter_db.py`, `check_db.py`, `patch_realm.py`, `src/fix_roles.py`, `src/scratch_db.py`, plus deux fichiers `openapi*.json`. |
| Q7 | M | Certain | Aucun test automatisé. Le bloc « phase 1 » est copié trois fois (environ 80 lignes chacun), ce qui explique les corrections incohérentes entre moteurs. |
| Q8 | B | Certain | Une seule file Celery pour les scans (jusqu'à 24 h), les parsers et Beat. Pas de `acks_late`, ni de concurrence ou de file par type de tâche. |

---

## 5. Classement des causes

| Catégorie | Constats | Part estimée du problème « peu de vulnérabilités » |
|---|---|---|
| **Défaut de code** | C1, C2, C4, C5, C6, C7, C9, C10, C11, C12, C14, C16, C22, C24 | **Majoritaire.** C1, C2, C5 et C7 suffisent à expliquer des résultats faibles ou peu crédibles sur Nmap, Nuclei, ZAP et les scans authentifiés. |
| **Configuration** | C8, C13, C17, C18, S3 (Vault dev), Q2 | Importante : bruit de vulscan, durée d'OpenVAS, templates Nuclei, logs inexploitables. |
| **Utilisation** (souvent induite par l'interface) | C3, C15, choix « Discovery » qui ne cherche pas de vulnérabilités, Nessus encore proposé | Réelle, mais **causée par l'interface** : texte d'aide faux pour les URL, aucun choix de policy ni d'identifiant, moteur Nessus factice. |

---

## 6. Plan de correction par priorité

Ces corrections ne sont **pas appliquées**. L'effort est indiqué en jours de travail : **S** = moins d'un jour, **M** = de 1 à 3 jours, **L** = plus de 3 jours.

| Prio. | Correction | Constats | Effort | Risque |
|---|---|---|---|---|
| P0 | Corriger le mapping des clés dans `parse_nmap_report`, avec un test sur une sortie réelle | C1, C12 | S | Faible |
| P0 | Fusionner `credential_type` avec le secret Vault, et journaliser si le scan est authentifié | C2 | S | Faible |
| P0 | Ajouter `return` après `ABANDONED` et supprimer la bascule vers OpenVAS | C4 | S | Faible |
| P0 | Authentification et RBAC sur toutes les routes, avec un test de non-régression | S1, S2 | M | Moyen (vérifier que le frontend envoie bien le token sur chaque appel) |
| P1 | Gestion des domaines : champ `hostname` sur l'asset (migration), URL avec domaine pour Nuclei et ZAP, plus d'écrasement de l'IP, page Assets qui relance sur le domaine | C5, C6 | M | Moyen (migration de données) |
| P1 | Cibles URL acceptées (extraction de l'hôte pour Nmap, URL complète pour ZAP et Nuclei) et texte de l'interface corrigé | C3 | S | Faible |
| P1 | ZAP : URL issues de la phase 1, pipes redirigés, limites de durée | C7, C8 | M | Faible |
| P1 | Statuts honnêtes (`COMPLETED_WITH_ERRORS`, `NO_SERVICE_FOUND`) avec le motif dans l'interface | C10, C17 | M | Moyen (enum, migration, interface) |
| P1 | Clé de déduplication par (asset, moteur, règle, port ou URL) et enregistrement de `port` et `matched_at` | C11 | M | Moyen (la déduplication des données existantes change) |
| P1 | Migration `OWASP_ZAP` dans l'enum, et retrait de Nessus (section 7) | C24, Nessus | S | Moyen (enum PostgreSQL) |
| P2 | Éclatement des CIDR en hôtes pour les scans de vulnérabilités | C9 | M | Moyen |
| P2 | Recherches d'asset filtrées par société et `is_deleted` ; rapports filtrés par société | C14, C22 | S | Faible |
| P2 | Choix explicite de la policy et de l'identifiant dans l'interface, sans sélection implicite | C15 | M | Faible |
| P2 | Planification : `target_states`, `next_run_at` en datetime, file Celery dédiée | C16, Q8 | M | Moyen |
| P2 | Policy de scan Nmap configurable ; vulscan désactivé par défaut ; pagination serveur | C13 | M | Faible |
| P2 | `lifespan` : plus de pause, de purge ni de `create_all` au démarrage | C21 | S | Moyen |
| P3 | OpenVAS : liste de ports standard, durée maximale, credentials GVM, logs allégés | C17, C18, C2 | M | Faible |
| P3 | Durcissement du déploiement (secrets, Vault, ports, CORS) | S3, S4, Q1-Q5 | M | Moyen (installations existantes : prévoir une migration) |
| P3 | Factoriser la phase 1 commune ; tests unitaires des parsers ; CI | Q7 | L | Faible |

**Retrait de Nessus.** Le code contient 18 références dans 10 fichiers.

| Fichier | Ligne | Action |
|---|---|---|
| `src/scans/adapters/outbound/nessus_adapter.py` | entier | Supprimer le fichier. |
| `src/scans/application/services/tasks.py` | 694-723 | Supprimer la branche NESSUS. |
| `src/scans/domain/entities.py` | 18 | Retirer `NESSUS` de l'enum **seulement après** la migration de données (sinon SQLAlchemy lève une `LookupError` en lisant les anciens scans). |
| `src/scans/adapters/inbound/api/endpoints.py` | 33 | Mettre à jour le commentaire. Refuser explicitement un moteur inconnu (erreur 400) au lieu de basculer sur OPENVAS (l.131 et 302). |
| `alembic/versions/a93e432317eb_add_scanner_engines.py` | 23 | **Ne pas modifier** (migration déjà appliquée). |
| `NewScanModal.tsx:49`, `EditScanModal.tsx:38`, `assets/page.tsx:330`, `scheduling/page.tsx:437`, `settings/page.tsx:48` | — | Retirer l'option Nessus. |

**Migration Alembic proposée** (nouvelle révision) :
1. Données : `UPDATE scans SET scanner_engine='OPENVAS', is_deleted=true WHERE scanner_engine='NESSUS'`. Ces scans n'ont jamais produit de résultat. Faire de même dans `schedules` (colonne texte) : passer les plannings Nessus à `status='Paused'`.
2. Enum : `ALTER TYPE scannerengine RENAME TO scannerengine_old`, puis `CREATE TYPE scannerengine AS ENUM ('OPENVAS','NMAP','NUCLEI','OWASP_ZAP')`, puis `ALTER TABLE scans ALTER COLUMN scanner_engine DROP DEFAULT`, puis `ALTER COLUMN scanner_engine TYPE scannerengine USING scanner_engine::text::scannerengine`, puis remettre `SET DEFAULT 'OPENVAS'`, puis `DROP TYPE scannerengine_old`. Cette étape règle aussi C24.
3. Le `downgrade` recrée l'ancien type, valeur `NESSUS` comprise.

---

## 7. Points à vérifier sur un serveur

| Point | Test précis |
|---|---|
| Comportement de `self.retry` une fois les retries épuisés (C4) | Scan Nmap sur un hôte injoignable : vérifier dans les logs du worker la présence de `Max retries exceeded`, suivie d'une connexion à GVM et d'un `create_target`. |
| Blocage de ZAP par les pipes (C8) | Scan ZAP sur DVWA ou Juice Shop : suivre le daemon avec `py-spy dump` ou `jstack` et voir si les threads sont bloqués en écriture sur la sortie standard ; mesurer la durée totale. |
| Templates Nuclei présents (C5, Q2) | Dans `celery-worker` : `nuclei -tl \| wc -l` et date de `~/nuclei-templates`. |
| `vulners` sans Internet (C13) | `nmap -sV --script vulners -p 22 <hôte de test>` dans le worker, avec puis sans accès sortant. |
| Volume de bruit de `vulscan` (C13) | Compter les lignes `vulscan` sur un Apache 2.4.49 de laboratoire. |
| Enum `OWASP_ZAP` en base (C24) | `SELECT unnest(enum_range(NULL::scannerengine));` sur chaque base de production. |
| Scans `NESSUS` existants | `SELECT count(*) FROM scans WHERE scanner_engine='NESSUS'` et `SELECT count(*) FROM schedules WHERE scanner_engine='NESSUS'`. |
| Filtre QoD d'OpenVAS (2.4) | Comparer le nombre de résultats renvoyés par `get_report` sans filtre et avec `filter_string="min_qod=0"`. |
| Durée d'OpenVAS en UDP complet (C17) | Mesurer la durée d'un scan « Full and fast » sur un hôte avec `T:1-65535,U:1-65535`, puis avec la liste « All IANA assigned TCP ». |
| Scan d'un domaine derrière un reverse proxy (C5, C6) | Laboratoire nginx servant une application vulnérable uniquement sur `app.lab.local` : comparer les résultats Nuclei en ciblant le domaine et en ciblant l'IP. |
| Planification manquée (C16) | Lancer 4 longs scans (pour occuper la concurrence du worker), puis vérifier si un planning `HH:MM` se déclenche. |
| Multi-IP et IPv6 (C20) | Scan d'un domaine qui résout vers deux A et un AAAA. |
| Volume des logs (C18) | Après un scan OpenVAS : `docker compose logs celery-worker \| wc -c` et vérifier si les logs des scans précédents sont encore présents. |

---

## Annexe A — Inventaire des routes

« Auth seule » signifie : connexion exigée, sans contrôle de rôle ni de permission.

| Méthode | Route | Protection |
|---|---|---|
| GET | `/api/v1/notifications/unread-count` | **Aucune** |
| POST | `/api/v1/reporting/{asset_id}/html` | **Aucune** |
| POST | `/api/v1/reporting/{asset_id}/pdf` | **Aucune** |
| GET | `/api/v1/scans/status` | **Aucune** |
| GET | `/api/v1/scans/companies` | **Aucune** |
| GET | `/api/v1/scans` | **Aucune** |
| POST | `/api/v1/scans/{id}/generate-summary` | **Aucune** |
| PUT | `/api/v1/scans/{id}/summary` | **Aucune** |
| GET | `/api/v1/scans/{id}/report/html` | **Aucune** |
| GET | `/api/v1/scans/tasks/{task_id}` | **Aucune** |
| POST | `/api/v1/scans/{id}/report/pdf` | **Aucune** |
| GET | `/health` | Aucune (normal) |
| GET | `/api/v1/openapi.json`, `/docs` | Aucune (documentation exposée) |
| POST, PUT, DELETE | `/api/v1/scans`, `/scans/{id}`, `/scans/{id}/pause\|resume`, `/scans/companies/{id}`, `/scans/scanners/update` | Auth seule |
| GET | `/api/v1/admin/audits` | Auth seule (contrôle de rôle commenté) |
| GET, POST | `/api/v1/admin/users`, `/admin/users/{id}/roles` | Auth, puis rôle « Platform Administrator » vérifié dans le corps de la fonction |
| PATCH | `/api/v1/vulnerabilities/{id}/status` | `ASSET_READ` (trop faible) |
| autres routes assets, vulnerabilities, policies, scheduling, dashboard, reporting (GET) | — | `require_permissions` adapté |
| routes secrets | — | `SECRET_WRITE` ou `SECRET_DELETE` |

## Annexe B — Ce qui a été vérifié et ce qui ne l'a pas été

- **Lu en entier** : `scans/application/services/tasks.py` ; `vulnerabilities/application/services/tasks.py` ; adaptateurs Nmap (parsing), ZAP, GVM, Nuclei et base ; `scans/adapters/inbound/api/endpoints.py` ; `scheduling/application/services/tasks.py` ; `admin_endpoints.py` ; `main.py` ; `docker-compose.yml` ; `Dockerfile`.
- **Lu partiellement** : endpoints secrets, assets, vulnerabilities et reporting ; `NewScanModal.tsx` ; `EditScanModal.tsx` ; pages Assets et Vulnerabilities.
- **Non analysé** : `ai/application/services/nlp.py` (contenu des prompts IA), générateurs HTML et PDF, thème Keycloak, internationalisation.

## Annexe C — Test exécuté localement

Test du parser Nuclei (`_parse_nuclei_jsonl`), puis reproduction de la clé de déduplication de `parse_nuclei_report` (titre), sur 4 lignes JSONL écrites à la main :
- 2 matchers du template `http-missing-security-headers` ;
- le CVE-2021-41773 trouvé sur les ports 80 et 8080.

```text
Résultats du parser : 4
Vulnérabilités enregistrées après déduplication par titre : 2
 - HTTP Missing Security Headers | https://app.exemple.com
 - Apache 2.4.49 - Path Traversal | http://10.0.0.5:80/cgi-bin/.%2e/etc/passwd
```

L'occurrence sur le port 8080 et le détail des en-têtes manquants sont perdus (C11).

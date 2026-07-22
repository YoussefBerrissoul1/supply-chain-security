# Prompt pour agent IA — Correction backend Security Scanner (FastAPI)

## Contexte du projet

Backend Python (FastAPI + SQLAlchemy) qui analyse un dépôt GitHub :
- `github_analyzer.py` : clone/analyse le repo
- `dependency_scanner.py` : extrait les dépendances (requirements.txt, package.json, etc.)
- `cve_service.py` : interroge OSV API puis NVD API pour trouver les CVE de chaque dépendance
- `docker_scanner.py` : lance Trivy sur le Dockerfile du repo si présent
- `score_service.py` : calcule un score de sécurité global (0-100) à partir des CVE + Docker
- `ai_service.py` : génère des recommandations IA (Gemini/OpenRouter)
- `report_service.py` : génère un rapport PDF/HTML final
- Modèles SQLAlchemy : `Analysis`, `Dependency`, `Vulnerability`, `DockerResult`, `Recommendation`, `Report`

Deux modes de scan existent : `standard` (rapide) et `deep` (complet, enrichissement NVD systématique).

## Problèmes identifiés à corriger

### 1. Performance du scan "deep" trop lente / risque de timeout

Dans `cve_service.py`, le mode deep interroge NVD pour **chaque** CVE trouvée (pas seulement celles à score 0.0), avec seulement 3 workers en parallèle et un délai de 6 secondes entre requêtes NVD sans clé API (5 req/30s). Sur un repo avec beaucoup de dépendances vulnérables, cela peut prendre plusieurs minutes et faire timeout la requête HTTP côté serveur/proxy.

**Tâches :**
- Vérifier si `NVD_API_KEY` est configurée dans `app/core/config.py` / `.env`. Si absente, l'ajouter comme variable d'environnement (clé gratuite sur https://nvd.nist.gov/developers/request-an-api-key) et documenter son obtention dans le README.
- Convertir l'exécution du scan (au minimum le mode `deep`) en **tâche asynchrone en arrière-plan** : soit avec Celery/RQ + Redis comme broker, soit avec `BackgroundTasks` de FastAPI si l'infra ne permet pas Celery. L'endpoint qui déclenche l'analyse doit retourner immédiatement un `analysis_id` avec `status = PENDING`, et le frontend doit pouvoir poller `GET /analyses/{id}` pour suivre l'avancement (`PENDING → RUNNING → DONE/FAILED`).
- Ajouter un cache (Redis, ou table SQL dédiée avec TTL) sur les résultats `query_nvd_by_cve_id()` et `query_osv()`, indexé par `cve_id` ou `name@version`, avec une durée de vie de quelques jours, pour éviter de re-interroger les mêmes CVE lors de scans répétés (même repo, ou dépendances partagées entre repos comme `lodash`, `express`, etc.).
- Ajouter un timeout global configurable sur `scan_all_vulnerabilities()` pour le mode deep, avec repli propre sur les résultats déjà obtenus si le budget temps est dépassé (plutôt que de bloquer indéfiniment).

**Configuration de la clé NVD API (déjà obtenue) :**

L'endpoint utilisé est `https://services.nvd.nist.gov/rest/json/cves/2.0` — c'est le bon, c'est celui que `cve_service.py` appelle déjà via `settings.NVD_API_URL`.

Ajouter dans le `.env` :
```
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=<clé reçue par email depuis nvd.nist.gov/developers/request-an-api-key>
```

Vérifier que `app/core/config.py` charge bien ces deux variables (`settings.NVD_API_URL`, `settings.NVD_API_KEY`).

Test rapide en ligne de commande pour valider la clé avant tout déploiement :
```bash
# Sans clé (limite 5 req/30s)
curl "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"

# Avec clé (limite 50 req/30s)
curl -H "apiKey: TA_CLE" "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
```
Une réponse JSON contenant `"vulnerabilities": [...]` confirme que l'API répond correctement.

Aucune modification de code n'est nécessaire pour activer la clé : `query_nvd_by_cve_id()` bascule déjà automatiquement de `NVD_DELAY_SECONDS` (6.0s) à `NVD_DELAY_WITH_KEY` (0.7s) dès que `settings.NVD_API_KEY` est défini. Seule la configuration `.env` est requise.

**Procédure d'obtention et d'implémentation de la clé NVD :**
1. Demande faite sur https://nvd.nist.gov/developers/request-an-api-key
2. Un email de confirmation est envoyé — cliquer sur le lien de confirmation qu'il contient (la page `https://nvd.nist.gov/developers/confirm-api-key` est une page d'information générique sur ce processus, pas la clé elle-même).
3. Après confirmation, NVD envoie la clé API réelle par email (format UUID : `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`).
4. Placer la clé dans le fichier `.env` à la racine du projet backend (même niveau que le dossier `app/`) :
   ```
   NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
   NVD_API_KEY=<clé reçue par email>
   OSV_API_URL=https://api.osv.dev/v1/query
   ```
5. Vérifier que `app/core/config.py` déclare bien ces champs (`NVD_API_URL`, `NVD_API_KEY`, `OSV_API_URL`) dans la classe `Settings` (Pydantic `BaseSettings` ou équivalent).
6. Redémarrer le serveur (`uvicorn`/process) — `.env` n'est lu qu'au démarrage, pas à chaud.
7. Confirmer que `.env` est bien listé dans `.gitignore` (ne jamais committer les clés).
8. Valider avec un test manuel avant déploiement :
   ```bash
   curl -H "apiKey: TA_CLE" "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228"
   ```
   Une réponse JSON avec `"vulnerabilities": [...]` confirme que la clé fonctionne.

### 2. Données CVE historiques incorrectes en base (scores/exploits figés)

Des analyses existantes en base contiennent des `Vulnerability.cvss_score` figés à des valeurs rondes (8.0 pour tout HIGH, 5.0 pour MEDIUM, 0.0 pour LOW) et `exploit_available = False` systématique. Cela vient probablement d'une version antérieure de `cve_service.py` qui utilisait un mapping fixe sévérité→score au lieu du calcul réel. Le code actuel de `_extract_cvss_from_osv()` ne fait plus ce mapping fixe (il retourne 0.0 en dernier recours pour forcer l'enrichissement NVD), mais les anciennes lignes en base restent fausses.

**Tâches :**
- Écrire un script de migration/nettoyage (`scripts/rescan_stale_analyses.py`) qui identifie les `Analysis` dont les `Vulnerability` associées ont des `cvss_score` suspects (valeurs exactement égales à 8.0, 5.0, ou 0.0 en masse sur une même analyse) et propose de les re-scanner avec le `cve_service.py` actuel.
- Ajouter un champ `Analysis.cve_service_version` (ou équivalent) pour tracer quelle version du moteur CVE a produit les résultats, afin de détecter facilement les analyses obsolètes à l'avenir.

### 3. Détection d'exploit public trop faible

`_detect_exploit_from_osv()` et la logique équivalente dans `query_nvd_by_cve_id()` ne détectent l'exploitabilité que via mots-clés dans les URLs de référence ou des flags `database_specific`. Beaucoup de CVE avec exploit public connu ne seront pas détectées.

**Tâches :**
- Intégrer le flux **CISA KEV** (Known Exploited Vulnerabilities) : `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`. Télécharger et mettre en cache localement (rafraîchi une fois par jour), puis vérifier chaque `cve_id` détecté contre cette liste. Si présent → `exploit_available = True` avec `source` annoté "CISA KEV".
- Documenter dans le docstring de `_detect_exploit_from_osv()` que la détection reste heuristique et peut sous-estimer le nombre réel d'exploits publics.

### 4. Troncature silencieuse des dépendances

`MAX_DEPS_STANDARD = 100` et `MAX_DEPS_DEEP = 200` tronquent silencieusement la liste de dépendances scannées si le repo en a plus, avec seulement un log serveur (`logger.warning`) — l'utilisateur final ne voit jamais cette limitation dans le rapport.

**Tâches :**
- Faire remonter cette information jusqu'au `Report` final (PDF/HTML) et à la réponse API : ajouter un champ du type `dependencies_truncated: bool` et `dependencies_scanned_count` / `dependencies_total_count` sur `Analysis` ou dans la réponse de scan, affiché clairement dans le rapport ("Scan partiel : 100/174 dépendances analysées").

### 5. Validation de l'existence des CVE

Aucune vérification que les `cve_id` retournés par OSV correspondent bien à des CVE existantes et publiées (pertinent pour des CVE très récentes, ex. CVE-2026-xxxxx).

**Tâches :**
- Dans `query_nvd_by_cve_id()`, si NVD renvoie une liste vide pour un `cve_id` donné, logger cette anomalie de façon visible (`logger.warning` avec le cve_id) plutôt que de simplement retourner `None` silencieusement, pour faciliter le futur débogage.

## Contraintes à respecter pendant les corrections

- Ne pas casser la compatibilité des endpoints API existants (ajouter des champs, ne pas en renommer/supprimer sans coordination).
- Garder la logique actuelle de calcul CVSS depuis le vecteur (`_parse_cvss_v3_base_score`) inchangée — elle est correcte et conforme à la spec officielle CVSS v3.x, ne pas la "simplifier".
- Toute nouvelle dépendance externe (Celery, Redis, etc.) doit être ajoutée à `requirements.txt`/`pyproject.toml` et documentée dans le README avec les instructions de déploiement (ex: `docker-compose` service Redis).
- Écrire des tests unitaires pour chaque fonction modifiée, en particulier `scan_all_vulnerabilities()`, la nouvelle logique de cache, et l'intégration CISA KEV.
- Ne pas introduire de régression de performance sur le mode `standard` (qui doit rester rapide).

## Livrables attendus

1. Code corrigé pour les 5 points ci-dessus.
2. Script de migration/nettoyage des analyses obsolètes.
3. Tests unitaires couvrant les nouveaux comportements.
4. Documentation mise à jour (README) : configuration `NVD_API_KEY`, infra Celery/Redis si ajoutée, nouveau comportement asynchrone du endpoint de scan.

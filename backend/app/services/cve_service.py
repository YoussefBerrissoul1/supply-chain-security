"""
Service CVE — détecte les vulnérabilités dans les dépendances via OSV et NVD.

Position dans la chaîne d'analyse :
    [dependency_scanner] → [cve_service] → [score_service]

Ce service reçoit :
    - Une liste de DependencyInfo (nom, version, écosystème)

Ce service retourne :
    - Un dict : { dependency_name → liste de VulnerabilityResult }

STRATÉGIE D'INTERROGATION :
    1. OSV API  (https://api.osv.dev/v1/query)  ← PRIORITAIRE (gratuite, rapide)
    2. NVD API  (https://services.nvd.nist.gov/) ← Pour le score CVSS précis (deep + enrichissement)

CVSS Scoring :
    - On parse le vecteur CVSS v3 directement pour obtenir le score exact
    - Formule officielle CVSS v3.x implémentée ici (pas de valeurs fixes)

GESTION DU RATE LIMIT :
    - OSV   : pas de limite stricte, délai réduit en mode parallel
    - NVD   : 5 req/30s SANS clé, 50 req/30s AVEC clé

CACHE IN-MEMORY :
    - query_osv()          : clé = "name@version@ecosystem", TTL = 24h
    - query_nvd_by_cve_id(): clé = cve_id,                  TTL = 24h
    - Évite de re-interroger les mêmes CVE lors de scans répétés

CISA KEV :
    - Téléchargé une fois par jour depuis
      https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    - Toute CVE présente dans ce catalogue est marquée exploit_available=True
"""

import logging
import math
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

import requests
from requests.exceptions import ConnectionError, ReadTimeout, HTTPError

from app.core.config import settings
from app.services.dependency_scanner import DependencyInfo

logger = logging.getLogger(__name__)


# ==============================================================
# CONSTANTES
# ==============================================================

# Délai entre requêtes NVD (en secondes)
NVD_DELAY_SECONDS: float = 6.0   # Sans clé : 5 req / 30s
NVD_DELAY_WITH_KEY: float = 0.7  # Avec clé : 50 req / 30s

# Délai entre requêtes OSV — réduit car OSV est très permissif et nous sommes en parallèle
# 0.05s × 15 workers = environ 0.003s d'attente réelle par dépendance
OSV_DELAY_SECONDS: float = 0.05

# Nombre maximum de tentatives en cas de rate limit (429)
MAX_RETRY_ON_RATE_LIMIT: int = 3

# Pause lors d'un rate limit avant retry
RATE_LIMIT_PAUSE_SECONDS: float = 12.0

# Timeout global du scan complet en secondes (évite les blocages indéfinis)
# Standard : 3 min (scan rapide priorité vitesse)
# Deep : 15 min (scan complet priorité exhaustivité)
SCAN_TIMEOUT_STANDARD: float = 180.0
SCAN_TIMEOUT_DEEP: float = 900.0

# Cache TTL en secondes (24h)
CACHE_TTL_SECONDS: float = 86400.0

# CISA KEV URL officiel
CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Mapping OSV/NVD ecosystem → format attendu par l'API OSV
OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "python": "PyPI",
    "nodejs": "npm",
    "java":   "Maven",
    "ruby":   "RubyGems",
    "php":    "Packagist",
    "rust":   "crates.io",
    "go":     "Go",
}

# Nombre max de dépendances à scanner
# Standard : 60 (scan rapide — résultat en < 3 min sur repos larges)
# Deep     : 150 (exhaustif — résultat en < 15 min)
MAX_DEPS_STANDARD: int = 60
MAX_DEPS_DEEP: int = 150

# Version du moteur CVE — à incrémenter à chaque modification de la logique
# Utilisé pour détecter les analyses obsolètes en base (champ Analysis.cve_service_version)
CVE_SERVICE_VERSION: str = "2.0.0"


# ==============================================================
# CACHE IN-MEMORY (thread-safe, TTL-based)
# ==============================================================

class _TTLCache:
    """
    Cache en mémoire thread-safe avec durée de vie (TTL).

    Clé → (valeur, timestamp_expiration)
    Évite de re-interroger les mêmes CVE ou dépendances lors de scans répétés
    (même repo re-scanné, ou dépendances partagées comme lodash, requests, etc.).

    Compatible avec Redis si souhaité à l'avenir — remplacer cette classe
    par un client redis.Redis() avec la même interface get/set.
    """

    def __init__(self, ttl_seconds: float = CACHE_TTL_SECONDS) -> None:
        self._store: dict[str, tuple[Any, float]] = {}
        self._lock = threading.Lock()
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any | None:
        """Retourne la valeur si non expirée, sinon None."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if time.monotonic() > expires_at:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        """Stocke une valeur avec TTL."""
        with self._lock:
            self._store[key] = (value, time.monotonic() + self._ttl)

    def clear(self) -> None:
        """Vide entièrement le cache (utile pour les tests)."""
        with self._lock:
            self._store.clear()

    def size(self) -> int:
        """Retourne le nombre d'entrées valides (non expirées)."""
        now = time.monotonic()
        with self._lock:
            return sum(1 for _, (_, exp) in self._store.items() if now <= exp)


# Instances globales — partagées entre tous les workers du même process
_osv_cache = _TTLCache(ttl_seconds=CACHE_TTL_SECONDS)
_nvd_cache = _TTLCache(ttl_seconds=CACHE_TTL_SECONDS)


# ==============================================================
# CATALOGUE CISA KEV (Known Exploited Vulnerabilities)
# ==============================================================

class _CISAKEVCache:
    """
    Télécharge et met en cache le catalogue CISA KEV.

    Le catalogue est une liste officielle des CVE avec exploitation active connue
    (maintenue par la CISA — Cybersecurity and Infrastructure Security Agency).
    URL : https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

    Rafraîchi automatiquement une fois par jour. Thread-safe.
    Méthode principale : is_exploited(cve_id) → bool
    """

    def __init__(self) -> None:
        self._cve_ids: set[str] = set()
        self._loaded_at: float = 0.0
        self._lock = threading.Lock()
        self._refresh_interval = 86400.0  # 24h

    def _needs_refresh(self) -> bool:
        return (time.monotonic() - self._loaded_at) > self._refresh_interval

    def _load(self) -> None:
        """Télécharge le catalogue CISA KEV depuis l'URL officielle."""
        try:
            logger.info("CISA KEV : téléchargement du catalogue depuis %s", CISA_KEV_URL)
            response = requests.get(CISA_KEV_URL, timeout=30)
            response.raise_for_status()
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            new_ids: set[str] = set()
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "")
                if cve_id:
                    new_ids.add(cve_id)
            with self._lock:
                self._cve_ids = new_ids
                self._loaded_at = time.monotonic()
            logger.info("CISA KEV : %d CVE chargées avec exploitation active connue", len(new_ids))
        except Exception as e:
            logger.warning(
                "CISA KEV : impossible de télécharger le catalogue (%s) — "
                "la détection des exploits CISA sera désactivée pour ce run",
                e,
            )

    def ensure_loaded(self) -> None:
        """Charge le catalogue si nécessaire (lazy loading, thread-safe)."""
        if self._needs_refresh():
            self._load()

    def is_exploited(self, cve_id: str) -> bool:
        """
        Retourne True si ce CVE est dans la liste CISA KEV (exploitation active connue).

        Note : si le catalogue n'a pas pu être téléchargé, retourne toujours False
        (dégradation gracieuse — le reste de la détection reste fonctionnel).
        """
        self.ensure_loaded()
        with self._lock:
            return cve_id in self._cve_ids

    def get_loaded_count(self) -> int:
        """Retourne le nombre de CVE dans le catalogue (0 si non chargé)."""
        with self._lock:
            return len(self._cve_ids)


# Instance globale CISA KEV
_cisa_kev = _CISAKEVCache()


# ==============================================================
# ÉNUMÉRATION : SÉVÉRITÉ
# ==============================================================

class Severity(str, Enum):
    """
    Niveaux de sévérité des CVE, basés sur le score CVSS.
    On utilise str + Enum pour sérialisation JSON directe.
    """
    CRITICAL = "CRITICAL"   # CVSS >= 9.0
    HIGH     = "HIGH"       # CVSS 7.0 – 8.9
    MEDIUM   = "MEDIUM"     # CVSS 4.0 – 6.9
    LOW      = "LOW"        # CVSS 0.1 – 3.9
    NONE     = "NONE"       # CVSS = 0.0 ou inconnu


def cvss_to_severity(cvss_score: float) -> Severity:
    """
    Convertit un score CVSS numérique en niveau de sévérité.

    Basé sur le standard CVSS v3.x :
        9.0 – 10.0 → CRITICAL
        7.0 –  8.9 → HIGH
        4.0 –  6.9 → MEDIUM
        0.1 –  3.9 → LOW
        0.0        → NONE
    """
    if cvss_score >= 9.0:
        return Severity.CRITICAL
    elif cvss_score >= 7.0:
        return Severity.HIGH
    elif cvss_score >= 4.0:
        return Severity.MEDIUM
    elif cvss_score > 0.0:
        return Severity.LOW
    else:
        return Severity.NONE


# ==============================================================
# CALCUL CVSS v3 DEPUIS UN VECTEUR CVSS (OFFICIEL)
# ==============================================================

def _parse_cvss_v3_base_score(vector_string: str) -> float:
    """
    Calcule le score de base CVSS v3 depuis un vecteur CVSS complet.
    Implémente la formule officielle CVSS 3.x (FIRST.org).

    Exemples :
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H  → 9.8  (CRITICAL)
        CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N   → 6.1  (MEDIUM)
        CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H   → 5.5  (MEDIUM)

    Paramètres :
        vector_string : chaîne CVSS (ex: "CVSS:3.1/AV:N/AC:L/...")

    Retourne :
        float : score entre 0.0 et 10.0 (arrondi au dixième supérieur)

    NOTE : Cette fonction est correcte et conforme à la spec CVSS v3.x.
    Ne pas modifier la logique de calcul.
    """
    if not vector_string or 'AV:' not in vector_string:
        return 0.0

    try:
        # Extraire les métriques depuis le vecteur
        metrics: dict[str, str] = {}
        parts = vector_string.split('/')
        for part in parts:
            if ':' in part:
                k, v = part.split(':', 1)
                # Les métriques CVSS ont des clés courtes (2-2 chars généralement)
                if 1 <= len(k) <= 4:
                    metrics[k] = v

        # Tables de valeurs officielles CVSS v3.x
        AV_vals = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
        AC_vals = {'L': 0.77, 'H': 0.44}
        # PR dépend de S (Scope)
        PR_U_vals = {'N': 0.85, 'L': 0.62, 'H': 0.27}   # Scope: Unchanged
        PR_C_vals = {'N': 0.85, 'L': 0.68, 'H': 0.50}   # Scope: Changed
        UI_vals   = {'N': 0.85, 'R': 0.62}
        CIA_vals  = {'H': 0.56, 'L': 0.22, 'N': 0.00}

        AV  = AV_vals.get(metrics.get('AV', ''), 0.85)
        AC  = AC_vals.get(metrics.get('AC', ''), 0.77)
        S   = metrics.get('S', 'U')
        PR  = (PR_C_vals if S == 'C' else PR_U_vals).get(metrics.get('PR', ''), 0.85)
        UI  = UI_vals.get(metrics.get('UI', ''), 0.85)
        C   = CIA_vals.get(metrics.get('C', ''), 0.00)
        I   = CIA_vals.get(metrics.get('I', ''), 0.00)
        A   = CIA_vals.get(metrics.get('A', ''), 0.00)

        # ISC (Impact Sub Score)
        ISCBase = 1.0 - (1.0 - C) * (1.0 - I) * (1.0 - A)

        if S == 'U':
            ISC = 6.42 * ISCBase
        else:
            ISC = 7.52 * (ISCBase - 0.029) - 3.25 * pow(ISCBase - 0.02, 15)

        if ISC <= 0:
            return 0.0

        # ESC (Exploitability Sub Score)
        ESC = 8.22 * AV * AC * PR * UI

        # Base Score (arrondi au dixième supérieur selon spec CVSS)
        if S == 'U':
            raw = ISC + ESC
        else:
            raw = 1.08 * (ISC + ESC)

        raw = min(raw, 10.0)
        # Arrondi au dixième supérieur (ceiling CVSS spec)
        base_score = math.ceil(raw * 10) / 10

        return round(min(base_score, 10.0), 1)

    except Exception:
        return 0.0


# ==============================================================
# STRUCTURE DE DONNÉES : UNE VULNÉRABILITÉ
# ==============================================================

@dataclass
class VulnerabilityResult:
    """
    Représente une vulnérabilité (CVE) détectée pour une dépendance.

    Attributs :
        cve_id      : identifiant CVE (ex: "CVE-2023-12345") ou OSV ID (ex: "GHSA-xxxx")
        cvss_score  : score CVSS v3 entre 0.0 et 10.0 (calculé depuis le vecteur ou NVD)
        severity    : niveau de sévérité calculé à partir du cvss_score
        description : description courte de la vulnérabilité
        source      : "OSV" ou "NVD" ou "OSV+NVD" selon l'API qui l'a trouvée
        fixed_version: version corrigée si disponible, sinon None
        exploit_available: True si un exploit public est connu
        published_date: date de publication ISO (ex: "2023-06-15T00:00:00Z")
    """
    cve_id:        str
    cvss_score:    float
    severity:      Severity
    description:   str
    source:        str = "OSV"
    fixed_version: str | None = None
    exploit_available: bool = False
    published_date: str | None = None

    def to_dict(self) -> dict:
        """Sérialise en dict pour le stockage en base ou les logs."""
        return {
            "cve_id":        self.cve_id,
            "cvss_score":    self.cvss_score,
            "severity":      self.severity.value,
            "description":   self.description,
            "source":        self.source,
            "fixed_version": self.fixed_version,
            "exploit_available": self.exploit_available,
            "published_date": self.published_date,
        }


# ==============================================================
# EXCEPTION PERSONNALISÉE
# ==============================================================

class CVEServiceError(Exception):
    """
    Levée uniquement quand tout le service est en échec total
    (ex: pas de connexion internet du tout).
    Pour une seule dépendance sans résultat, on retourne [] sans exception.
    """
    pass


# ==============================================================
# CLIENT HTTP : REQUÊTE AVEC RETRY
# ==============================================================

def _http_post_with_retry(
    url: str,
    payload: dict,
    headers: dict | None = None,
    delay_before: float = 0.0,
) -> dict | None:
    """
    Effectue une requête POST HTTP avec retry automatique sur rate limit (429).
    """
    if delay_before > 0:
        time.sleep(delay_before)

    headers = headers or {"Content-Type": "application/json"}

    for attempt in range(1, MAX_RETRY_ON_RATE_LIMIT + 1):
        try:
            response = requests.post(
                url,
                json=payload,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT,
            )

            if response.status_code == 429:
                logger.warning(
                    "Rate limit atteint sur %s (tentative %d/%d) — pause de %.0fs",
                    url, attempt, MAX_RETRY_ON_RATE_LIMIT, RATE_LIMIT_PAUSE_SECONDS,
                )
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(RATE_LIMIT_PAUSE_SECONDS)
                    continue
                else:
                    return None

            if response.status_code >= 500:
                logger.warning("Erreur serveur %d depuis %s", response.status_code, url)
                return None

            response.raise_for_status()
            return response.json()

        except ReadTimeout:
            logger.warning("Timeout après %ds sur %s (tentative %d)", settings.HTTP_TIMEOUT, url, attempt)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2)
                continue
            return None

        except ConnectionError:
            logger.error("Impossible de se connecter à %s", url)
            return None

        except HTTPError as e:
            logger.error("Erreur HTTP %s sur %s : %s", e.response.status_code, url, e)
            return None

        except Exception as e:
            logger.error("Erreur inattendue sur %s : %s", url, e)
            return None

    return None


def _http_get_with_retry(
    url: str,
    params: dict | None = None,
    headers: dict | None = None,
    delay_before: float = 0.0,
) -> dict | None:
    """
    Identique à _http_post_with_retry mais pour les requêtes GET (utilisé par NVD).
    """
    if delay_before > 0:
        time.sleep(delay_before)

    headers = headers or {}

    for attempt in range(1, MAX_RETRY_ON_RATE_LIMIT + 1):
        try:
            response = requests.get(
                url,
                params=params,
                headers=headers,
                timeout=settings.HTTP_TIMEOUT,
            )

            if response.status_code == 429:
                logger.warning(
                    "Rate limit NVD (tentative %d/%d) — pause de %.0fs",
                    attempt, MAX_RETRY_ON_RATE_LIMIT, RATE_LIMIT_PAUSE_SECONDS,
                )
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(RATE_LIMIT_PAUSE_SECONDS)
                    continue
                return None

            if response.status_code == 404:
                return None

            if response.status_code >= 500:
                logger.warning("Erreur serveur NVD %d", response.status_code)
                return None

            response.raise_for_status()
            return response.json()

        except ReadTimeout:
            logger.warning("Timeout NVD (tentative %d)", attempt)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2)
                continue
            return None

        except ConnectionError:
            logger.error("Pas de connexion vers NVD API")
            return None

        except Exception as e:
            logger.error("Erreur inattendue NVD : %s", e)
            return None

    return None


# ==============================================================
# REQUÊTEUR OSV API (avec cache)
# ==============================================================

def query_osv(dep: DependencyInfo) -> list[VulnerabilityResult]:
    """
    Interroge l'API OSV pour une dépendance donnée.

    L'API OSV accepte une requête POST au format :
        {
            "package": {
                "name": "requests",
                "ecosystem": "PyPI"
            },
            "version": "2.27.0"   ← optionnel mais améliore la précision
        }

    CACHE : Les résultats sont mis en cache 24h par clé "name@version@ecosystem".
    Les dépendances partagées (lodash, requests, express, etc.) ne sont interrogées
    qu'une seule fois par process, même sur des scans différents.

    Paramètres :
        dep : la dépendance à analyser

    Retourne :
        Liste de VulnerabilityResult (peut être vide si aucune CVE trouvée)
    """
    osv_ecosystem = OSV_ECOSYSTEM_MAP.get(dep.ecosystem)
    if not osv_ecosystem:
        logger.debug(
            "Écosystème '%s' non supporté par OSV — dépendance '%s' ignorée",
            dep.ecosystem, dep.name,
        )
        return []

    # --- Vérification du cache ---
    cache_key = f"{dep.name}@{dep.version}@{osv_ecosystem}"
    cached = _osv_cache.get(cache_key)
    if cached is not None:
        logger.debug("OSV cache HIT : %s (%d résultats)", cache_key, len(cached))
        return cached

    payload: dict = {
        "package": {
            "name": dep.name,
            "ecosystem": osv_ecosystem,
        }
    }

    if dep.version and dep.version != "unknown":
        payload["version"] = dep.version

    logger.debug("OSV query : %s@%s (%s)", dep.name, dep.version, osv_ecosystem)

    response_data = _http_post_with_retry(
        url=settings.OSV_API_URL,
        payload=payload,
        delay_before=OSV_DELAY_SECONDS,
    )

    if not response_data:
        logger.debug("OSV : pas de réponse pour %s", dep.name)
        _osv_cache.set(cache_key, [])
        return []

    vulns = response_data.get("vulns", [])

    if not vulns:
        logger.debug("OSV : aucune vulnérabilité pour %s@%s", dep.name, dep.version)
        _osv_cache.set(cache_key, [])
        return []

    results: list[VulnerabilityResult] = []

    for vuln in vulns:
        cve_id = _extract_cve_id_from_osv(vuln)
        cvss_score = _extract_cvss_from_osv(vuln)
        description = _extract_description_from_osv(vuln)
        fixed_version = _extract_fixed_version_from_osv(vuln, osv_ecosystem, dep.name)
        published_date = vuln.get("published")
        exploit_available = _detect_exploit_from_osv(vuln)

        # Enrichir avec CISA KEV si c'est un vrai CVE-ID
        if not exploit_available and cve_id.startswith("CVE-"):
            if _cisa_kev.is_exploited(cve_id):
                exploit_available = True
                logger.debug("CISA KEV : %s marqué exploit_available=True", cve_id)

        result = VulnerabilityResult(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=cvss_to_severity(cvss_score),
            description=description,
            source="OSV",
            fixed_version=fixed_version,
            exploit_available=exploit_available,
            published_date=published_date,
        )

        results.append(result)
        logger.debug(
            "  CVE trouvée : %s | CVSS: %.1f | Sévérité: %s | Exploit: %s",
            cve_id, cvss_score, result.severity.value, exploit_available,
        )

    logger.info("OSV → %s@%s : %d vulnérabilité(s)", dep.name, dep.version, len(results))

    # Stocker en cache
    _osv_cache.set(cache_key, results)
    return results


# ==============================================================
# FONCTIONS D'EXTRACTION DEPUIS LA RÉPONSE OSV
# ==============================================================

def _extract_cve_id_from_osv(vuln: dict) -> str:
    """
    Extrait l'identifiant CVE depuis un objet de vulnérabilité OSV.
    On préfère toujours le format CVE-xxxx car c'est le standard industriel.
    """
    osv_id = vuln.get("id", "UNKNOWN")

    # Chercher un alias CVE dans la liste aliases
    aliases = vuln.get("aliases", [])
    for alias in aliases:
        if alias.startswith("CVE-"):
            return alias

    return osv_id


def _extract_cvss_from_osv(vuln: dict) -> float:
    """
    Extrait le score CVSS depuis la réponse OSV.

    Stratégie par ordre de priorité :
        1. Calculer depuis le vecteur CVSS v3 (le plus précis — formule officielle)
        2. Lire depuis database_specific.cvss.score (GitHub Advisory)
        3. Lire depuis affected[].severity[].score (format alternatif)
        4. Mapper depuis severity string (UNIQUEMENT si aucune autre option)

    Cette implémentation garantit des scores variés et corrects (pas de HIGH=8.0 fixe).
    """

    # --- Méthode 1 : Vecteur CVSS v3 dans severity[] (le plus précis) ---
    # OSV retourne: "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/..."}]
    severity_list = vuln.get("severity", [])
    for sev_entry in severity_list:
        sev_type = sev_entry.get("type", "")
        score_string = sev_entry.get("score", "")

        if "CVSS_V3" in sev_type and score_string and "AV:" in score_string:
            # Calculer le score numérique depuis le vecteur CVSS v3
            computed_score = _parse_cvss_v3_base_score(score_string)
            if computed_score > 0.0:
                logger.debug("CVSS v3 calculé depuis vecteur : %.1f (from: %s...)", computed_score, score_string[:40])
                return computed_score

        # Vérifier aussi CVSS_V2 comme dernier recours
        if "CVSS_V2" in sev_type and score_string and "AV:" in score_string:
            # Pour CVSS v2, essayer quand même (formule différente, approximation)
            pass

    # --- Méthode 2 : database_specific.cvss.score (GitHub Advisory Database) ---
    db_specific = vuln.get("database_specific", {})

    cvss_info = db_specific.get("cvss", {})
    if isinstance(cvss_info, dict):
        # Essayer vectorString d'abord (plus précis)
        vector_str = cvss_info.get("vectorString", "")
        if vector_str and "AV:" in vector_str:
            computed = _parse_cvss_v3_base_score(vector_str)
            if computed > 0.0:
                return computed

        # Puis le score numérique direct
        score = cvss_info.get("score")
        if score is not None:
            try:
                s = float(score)
                if s > 0:
                    return s
            except (ValueError, TypeError):
                pass

    # --- Méthode 3 : affected[].severity[] (format OSV étendu) ---
    for affected in vuln.get("affected", []):
        sev_list = affected.get("severity", [])
        for sev_entry in sev_list:
            sev_type = sev_entry.get("type", "")
            score_string = sev_entry.get("score", "")
            if "CVSS_V3" in sev_type and score_string and "AV:" in score_string:
                computed = _parse_cvss_v3_base_score(score_string)
                if computed > 0.0:
                    return computed
            # Score numérique direct dans affected
            if "score" in sev_entry:
                try:
                    s = float(sev_entry["score"])
                    if 0 < s <= 10:
                        return s
                except (ValueError, TypeError):
                    pass

    # --- Méthode 4 : database_specific.severity (string) — DERNIER RECOURS ---
    # On doit éviter les valeurs fixes ! On retourne 0.0 pour que NVD soit consulté.
    # Si NVD échoue aussi, la sévérité sera affichée comme NONE (score 0.0)
    # plutôt que d'afficher des valeurs fausses comme HIGH=8.0
    severity_str = db_specific.get("severity", "")
    if severity_str:
        # On log l'information pour le debug mais on ne met PAS de valeur fixe
        logger.debug("OSV : severity textuelle '%s' sans CVSS vector pour %s — NVD requis", severity_str, vuln.get("id", "?"))
        # Retourner 0.0 → sera enrichi par NVD si CVE-ID disponible
        return 0.0

    return 0.0


def _detect_exploit_from_osv(vuln: dict) -> bool:
    """
    Détecte si un exploit public est disponible pour cette vulnérabilité.

    Méthodes de détection (heuristiques — peuvent sous-estimer le nombre réel
    d'exploits publics, car basées sur les URLs/tags OSV) :
        1. Références OSV pointant vers des bases d'exploits
        2. Type de référence "EXPLOIT" dans OSV
        3. CISA KEV (Known Exploited Vulnerabilities) via database_specific
        4. Tags de gravité élevée dans database_specific

    Note : la vérification CISA KEV complète se fait dans query_osv() après
    l'extraction du cve_id, car elle nécessite l'ID CVE normalisé.
    """
    # Domaines et mots-clés associés à des bases d'exploits
    exploit_domains = [
        "exploit-db.com",
        "exploit-database.com",
        "packetstormsecurity.com",
        "0day.today",
        "rapid7.com/db",
        "vulhub.org",
        "seclists.org/fulldisclosure",
        "github.com/exploit",
        "github.com/poc",
        "github.com/cve-poc",
        "metasploit.com",
        "seebug.org",
    ]
    exploit_keywords = ["exploit", "0-day", "0day", "proof-of-concept", "poc/"]

    references = vuln.get("references", [])
    for ref in references:
        ref_url = ref.get("url", "").lower()
        ref_type = ref.get("type", "").upper()

        # Type EXPLOIT explicitement déclaré dans OSV
        if ref_type == "EXPLOIT":
            return True

        # Vérifier les domaines d'exploits
        if any(domain in ref_url for domain in exploit_domains):
            return True

        # Mots-clés dans l'URL
        if any(kw in ref_url for kw in exploit_keywords):
            return True

    # Vérifier database_specific pour CISA KEV ou autres indicateurs
    db_specific = vuln.get("database_specific", {})
    if db_specific.get("exploited", False):
        return True
    if db_specific.get("cisa_exploitation_activity"):
        return True

    return False


def _extract_description_from_osv(vuln: dict) -> str:
    """
    Extrait la description lisible de la vulnérabilité.

    OSV fournit :
        "summary"  : description courte (prioritaire)
        "details"  : description longue (fallback)
    """
    summary = vuln.get("summary", "").strip()
    if summary:
        return summary[:500]

    details = vuln.get("details", "").strip()
    if details:
        first_sentence = details.split(".")[0].strip()
        return (first_sentence[:500] + "...") if len(details) > 500 else details

    return "Aucune description disponible."


def _extract_fixed_version_from_osv(
    vuln: dict,
    ecosystem: str,
    package_name: str,
) -> str | None:
    """
    Extrait la version corrigée depuis la réponse OSV.

    Dans OSV, les versions affectées sont dans "affected[].ranges" :
        "ranges": [{
            "type": "ECOSYSTEM",
            "events": [
                {"introduced": "0"},
                {"fixed": "2.28.2"}   ← c'est ce qu'on cherche
            ]
        }]
    """
    for affected in vuln.get("affected", []):
        pkg = affected.get("package", {})
        if pkg.get("ecosystem") != ecosystem:
            continue
        if pkg.get("name", "").lower() != package_name.lower():
            continue

        for version_range in affected.get("ranges", []):
            events = version_range.get("events", [])
            for event in events:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)

    # Fallback : chercher sans vérifier l'écosystème (pour les cas edge)
    for affected in vuln.get("affected", []):
        for version_range in affected.get("ranges", []):
            events = version_range.get("events", [])
            for event in events:
                fixed = event.get("fixed")
                if fixed:
                    return str(fixed)

    return None


# ==============================================================
# REQUÊTEUR NVD API (fallback / complément, avec cache)
# ==============================================================

def query_nvd_by_cve_id(cve_id: str) -> VulnerabilityResult | None:
    """
    Interroge la NVD API pour obtenir les détails complets d'un CVE spécifique.
    Utilisé pour enrichir un CVE avec le score CVSS précis depuis NVD.

    CACHE : Les résultats sont mis en cache 24h par clé = cve_id.
    Les CVE partagées entre repos (ex: CVE-2021-44228 / Log4Shell) ne sont
    interrogées qu'une seule fois par process.

    Point 5 — Validation : si NVD retourne une liste vide pour un cve_id donné,
    un WARNING visible est émis dans les logs (facilite le débogage des CVE
    récentes ou inexistantes).

    Paramètres :
        cve_id : identifiant CVE au format "CVE-2023-12345"

    Retourne :
        VulnerabilityResult enrichi, ou None si non trouvé
    """
    if not cve_id.startswith("CVE-"):
        return None

    # --- Vérification du cache NVD ---
    cached = _nvd_cache.get(cve_id)
    if cached is not None:
        # cached peut être False (sentinel pour "not found") ou un VulnerabilityResult
        if cached is False:
            return None
        logger.debug("NVD cache HIT : %s", cve_id)
        return cached

    params = {"cveId": cve_id}
    headers = {}

    if settings.NVD_API_KEY:
        headers["apiKey"] = settings.NVD_API_KEY
        delay = NVD_DELAY_WITH_KEY
    else:
        delay = NVD_DELAY_SECONDS

    logger.debug("NVD query : %s", cve_id)

    response_data = _http_get_with_retry(
        url=settings.NVD_API_URL,
        params=params,
        headers=headers,
        delay_before=delay,
    )

    if not response_data:
        # Mettre False en cache pour éviter de re-requêter un CVE inaccessible
        _nvd_cache.set(cve_id, False)
        return None

    vulnerabilities = response_data.get("vulnerabilities", [])
    if not vulnerabilities:
        # Point 5 : log WARNING visible si NVD retourne liste vide
        # Pertinent pour les CVE très récentes (ex: CVE-2026-xxxxx) ou inexistantes
        logger.warning(
            "NVD : aucune donnée pour %s — CVE non trouvée ou trop récente "
            "(vérifier sur https://nvd.nist.gov/vuln/detail/%s)",
            cve_id, cve_id,
        )
        _nvd_cache.set(cve_id, False)
        return None

    cve_data = vulnerabilities[0].get("cve", {})

    cvss_score, severity_str = _extract_cvss_from_nvd(cve_data)
    description = _extract_description_from_nvd(cve_data)

    published_date = cve_data.get("published")

    # Vérifier l'exploitabilité via les références NVD
    exploit_available = False
    references = cve_data.get("references", [])
    for ref in references:
        tags = ref.get("tags", [])
        if "Exploit" in tags:
            exploit_available = True
            break
        ref_url = ref.get("url", "").lower()
        exploit_domains = ["exploit-db.com", "exploit-database.com", "packetstormsecurity.com",
                           "metasploit.com", "github.com/exploit", "github.com/poc"]
        if any(d in ref_url for d in exploit_domains):
            exploit_available = True
            break

    # Vérifier aussi CISA KEV depuis NVD
    if not exploit_available and _cisa_kev.is_exploited(cve_id):
        exploit_available = True
        logger.debug("CISA KEV (NVD path) : %s marqué exploit_available=True", cve_id)

    result = VulnerabilityResult(
        cve_id=cve_id,
        cvss_score=cvss_score,
        severity=cvss_to_severity(cvss_score),
        description=description,
        source="NVD",
        exploit_available=exploit_available,
        published_date=published_date,
    )

    # Mettre en cache le résultat complet
    _nvd_cache.set(cve_id, result)
    return result


def _extract_cvss_from_nvd(cve_data: dict) -> tuple[float, str]:
    """
    Extrait le score CVSS et la sévérité depuis les données NVD.
    NVD supporte CVSS v3.1, v3.0 et v2 (on préfère v3.1 → v3.0 → v2).
    """
    metrics = cve_data.get("metrics", {})

    for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        metric_list = metrics.get(metric_key, [])
        if metric_list:
            cvss_data = metric_list[0].get("cvssData", {})

            # Essayer d'abord le vecteur pour un calcul précis
            vector = cvss_data.get("vectorString", "")
            if vector and "AV:" in vector and metric_key != "cvssMetricV2":
                computed = _parse_cvss_v3_base_score(vector)
                if computed > 0:
                    severity = cvss_data.get("baseSeverity", "NONE")
                    return computed, severity

            score = cvss_data.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "NONE")
            return float(score), severity

    return 0.0, "NONE"


def _extract_description_from_nvd(cve_data: dict) -> str:
    """Extrait la description anglaise depuis les données NVD."""
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "")[:500]
    return "Aucune description NVD disponible."


# ==============================================================
# FONCTION PRINCIPALE : SCANNER TOUTES LES DÉPENDANCES
# ==============================================================

def scan_all_vulnerabilities(
    dependencies: list[DependencyInfo],
    scan_type: str = "standard",
    timeout_seconds: float | None = None,
) -> dict[str, list[VulnerabilityResult]]:
    """
    Fonction principale du service CVE.
    Interroge OSV pour chaque dépendance et retourne toutes les vulnérabilités trouvées.

    Stratégie :
        1. Pour chaque dépendance → OSV API (en PARALLÈLE via ThreadPoolExecutor)
        2. Si la CVE trouvée a un score CVSS = 0 et c'est un vrai CVE-ID → NVD API pour enrichir
           (Dans tous les modes, pas seulement deep)
        3. En mode deep : enrichissement NVD systématique pour plus de précision
        4. Timeout global : si le budget temps est dépassé, repli propre sur les résultats
           déjà obtenus plutôt que de bloquer indéfiniment

    TRONCATURE : si le repo contient plus de MAX_DEPS_STANDARD (100) ou MAX_DEPS_DEEP (200)
    dépendances, elles sont tronquées. Cette information est disponible dans les champs
    retournés (deps_truncated, deps_scanned, deps_total) pour affichage dans les rapports.

    Paramètres :
        dependencies    : liste retournée par dependency_scanner.scan_dependencies()
        scan_type       : "standard" (rapide) ou "deep" (complet + NVD)
        timeout_seconds : timeout global en secondes (None = valeur par défaut selon scan_type)

    Retourne :
        dict : { "fastapi@0.104.1" → [VulnerabilityResult, ...], ... }

    Note : Le dict retourné peut être incomplet si le timeout est atteint.
    Consulter les logs pour le résumé final.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    if not dependencies:
        logger.warning("scan_all_vulnerabilities : liste vide reçue")
        return {}

    # Timeout global selon le mode (évite les blocages indéfinis)
    if timeout_seconds is None:
        timeout_seconds = SCAN_TIMEOUT_DEEP if scan_type == "deep" else SCAN_TIMEOUT_STANDARD
    scan_deadline = time.monotonic() + timeout_seconds

    # --- Limite de dépendances selon le mode ---
    deps_total = len(dependencies)
    max_deps = MAX_DEPS_DEEP if scan_type == "deep" else MAX_DEPS_STANDARD
    deps_truncated = deps_total > max_deps

    if deps_truncated:
        logger.warning(
            "Trop de dépendances (%d) — scan limité aux %d premières [mode %s]. "
            "Information disponible dans scan_meta['deps_truncated'].",
            deps_total, max_deps, scan_type,
        )
        dependencies = dependencies[:max_deps]

    deps_scanned = len(dependencies)

    # Filtrer les dépendances Docker (gérées par docker_scanner)
    deps_to_scan = [d for d in dependencies if d.ecosystem != "docker"]
    docker_skipped = len(dependencies) - len(deps_to_scan)
    if docker_skipped > 0:
        logger.debug("%d dépendances Docker ignorées (gérées par docker_scanner)", docker_skipped)

    results: dict[str, list[VulnerabilityResult]] = {}
    total_cve_found = 0
    failed_queries = 0
    timeout_reached = False

    logger.info(
        "Démarrage du scan CVE (%s) pour %d dépendance(s) [parallèle, timeout=%.0fs]...",
        scan_type.upper(),
        len(deps_to_scan),
        timeout_seconds,
    )

    # ---------------------------------------------------------------
    # SCAN PARALLÈLE via ThreadPoolExecutor
    # Avant : 100 deps × 0.2s = 20s minimum
    # Après : 100 deps / 10 workers × 0.2s = ~2s
    # ---------------------------------------------------------------

    def _scan_one_dep(dep: DependencyInfo) -> tuple[str, list[VulnerabilityResult], bool]:
        """Scanne une dépendance et retourne (dep_key, vulns, failed)."""
        dep_key = f"{dep.name}@{dep.version}"
        try:
            osv_results = query_osv(dep)

            enriched_results: list[VulnerabilityResult] = []
            for vuln in osv_results:
                # Enrichissement NVD si score inconnu (0.0) ET CVE-ID valide
                # Ceci s'applique en mode standard ET deep pour des scores précis
                if vuln.cvss_score == 0.0 and vuln.cve_id.startswith("CVE-"):
                    nvd_result = query_nvd_by_cve_id(vuln.cve_id)
                    if nvd_result:
                        if nvd_result.cvss_score > 0.0:
                            vuln.cvss_score = nvd_result.cvss_score
                            vuln.severity = cvss_to_severity(nvd_result.cvss_score)
                            vuln.source = "OSV+NVD"
                        if nvd_result.exploit_available:
                            vuln.exploit_available = True
                        if nvd_result.published_date and not vuln.published_date:
                            vuln.published_date = nvd_result.published_date

                # En mode deep : enrichissement NVD systématique même si on a déjà un score
                elif scan_type == "deep" and vuln.cve_id.startswith("CVE-"):
                    nvd_result = query_nvd_by_cve_id(vuln.cve_id)
                    if nvd_result:
                        # Préférer le score NVD car il est plus précis (CVSS officiel)
                        if nvd_result.cvss_score > 0.0:
                            vuln.cvss_score = nvd_result.cvss_score
                            vuln.severity = cvss_to_severity(nvd_result.cvss_score)
                        vuln.source = "OSV+NVD"
                        if nvd_result.exploit_available:
                            vuln.exploit_available = True
                        if nvd_result.published_date and not vuln.published_date:
                            vuln.published_date = nvd_result.published_date

                enriched_results.append(vuln)

            return dep_key, enriched_results, False

        except Exception as e:
            logger.error(
                "Erreur inattendue lors du scan de '%s' : %s — dépendance ignorée",
                dep_key, e,
            )
            return dep_key, [], True

    # Workers parallèles :
    # Standard : OSV uniquement (NVD seulement si cvss=0) → 15 workers car OSV très permissif
    #            Gain : 60 deps / 15 workers = ~4 batches → ~4 × 0.05s = ~0.2s (vs 60 × 0.2s = 12s)
    # Deep     : OSV + NVD systématique → 4 workers (respecter rate limit NVD 50 req/30s avec clé)
    max_workers = 4 if scan_type == "deep" else 15

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_scan_one_dep, dep): dep for dep in deps_to_scan}

        completed = 0
        for future in as_completed(futures):
            # Vérifier le timeout global
            if time.monotonic() > scan_deadline:
                timeout_reached = True
                logger.warning(
                    "Timeout global atteint (%.0fs) après %d/%d dépendances — "
                    "repli sur les résultats déjà obtenus.",
                    timeout_seconds, completed, len(deps_to_scan),
                )
                # Annuler les futures restants (ne bloque pas, les threads finiront)
                for remaining_future in futures:
                    remaining_future.cancel()
                break

            completed += 1
            dep_key, vulns, failed = future.result()
            results[dep_key] = vulns
            total_cve_found += len(vulns)
            if failed:
                failed_queries += 1
            if completed % 10 == 0 or completed == len(deps_to_scan):
                logger.info(
                    "Scan CVE : %d/%d dépendances traitées, %d CVE trouvées jusqu'ici",
                    completed, len(deps_to_scan), total_cve_found,
                )

    # Vérification : si TOUTES les requêtes ont échoué → service indisponible
    if not timeout_reached and failed_queries == len(deps_to_scan) and len(deps_to_scan) > 0:
        raise CVEServiceError(
            "Toutes les requêtes CVE ont échoué. "
            "Vérifiez votre connexion internet et la disponibilité des APIs OSV/NVD."
        )

    # Résumé
    deps_with_vulns = sum(1 for vulns in results.values() if vulns)
    logger.info(
        "Scan CVE terminé — %d dépendances analysées, %d avec des CVE, %d CVE au total%s",
        len(results), deps_with_vulns, total_cve_found,
        " [TIMEOUT — résultats partiels]" if timeout_reached else "",
    )

    # Métadonnées de troncature disponibles via les constantes du module
    # Pour les routes/services appelants : vérifier deps_truncated, deps_scanned, deps_total
    # Ces valeurs sont stockées dans scan_meta retourné par le service d'analyse
    results["__scan_meta__"] = {  # type: ignore[assignment]
        "deps_truncated": deps_truncated,
        "deps_scanned": deps_scanned,
        "deps_total": deps_total,
        "timeout_reached": timeout_reached,
    }

    return results


# ==============================================================
# FONCTION UTILITAIRE : RÉSUMÉ DU SCAN CVE
# ==============================================================

def get_cve_summary(scan_results: dict[str, list[VulnerabilityResult]]) -> dict:
    """
    Génère un résumé statistique du scan CVE pour les logs et les rapports.

    Paramètres :
        scan_results : dict retourné par scan_all_vulnerabilities()

    Retourne :
        dict avec :
            - total_vulnerabilities : nombre total de CVE
            - by_severity           : { "CRITICAL": 3, "HIGH": 7, ... }
            - affected_packages     : nombre de paquets touchés
            - clean_packages        : nombre de paquets sans CVE
            - highest_severity      : la sévérité maximale trouvée
    """
    by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    total_cve = 0
    affected_packages = 0

    # Exclure la clé meta interne
    actual_results = {k: v for k, v in scan_results.items() if k != "__scan_meta__"}

    for vulns in actual_results.values():
        if vulns:
            affected_packages += 1
            for vuln in vulns:
                total_cve += 1
                by_severity[vuln.severity.value] += 1

    highest_severity = Severity.NONE
    for severity_level in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        if by_severity[severity_level.value] > 0:
            highest_severity = severity_level
            break

    return {
        "total_vulnerabilities": total_cve,
        "by_severity":           by_severity,
        "affected_packages":     affected_packages,
        "clean_packages":        len(actual_results) - affected_packages,
        "highest_severity":      highest_severity.value,
    }

import requests
import time
import math
import logging
import threading
from cachetools import TTLCache

logger = logging.getLogger(__name__)

# Config
MAX_RETRY_ON_RATE_LIMIT = 3
RATE_LIMIT_PAUSE_SECONDS = 12.0
HTTP_TIMEOUT = 30  # Augmenté — les API OSV/NVD peuvent être lentes

class ThreadSafeCache:
    def __init__(self, maxsize: int = 10000, ttl_seconds: float = 86400.0) -> None:
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl_seconds)
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            return self._cache.get(key)

    def set(self, key: str, value) -> None:
        with self._lock:
            self._cache[key] = value

class _CISAKEVCache:
    def __init__(self) -> None:
        self._cve_ids = set()
        self._loaded_at = 0.0
        self._lock = threading.Lock()
        self._refresh_interval = 86400.0

    def ensure_loaded(self) -> None:
        if (time.monotonic() - self._loaded_at) > self._refresh_interval:
            try:
                response = requests.get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    new_ids = {vuln.get("cveID") for vuln in data.get("vulnerabilities", []) if vuln.get("cveID")}
                    with self._lock:
                        self._cve_ids = new_ids
                        self._loaded_at = time.monotonic()
            except Exception:
                pass

    def is_exploited(self, cve_id: str) -> bool:
        self.ensure_loaded()
        with self._lock:
            return cve_id in self._cve_ids

osv_cache  = ThreadSafeCache(maxsize=10000, ttl_seconds=86400.0)
nvd_cache  = ThreadSafeCache(maxsize=10000, ttl_seconds=86400.0)
epss_cache = ThreadSafeCache(maxsize=10000, ttl_seconds=86400.0)  # FIRST.org EPSS
cisa_kev   = _CISAKEVCache()

# ── EPSS (Exploit Prediction Scoring System) ────────────────────────────────
# Source : https://api.first.org/data/v1/epss
# Retourne la probabilité d'exploitation dans les 30 prochains jours (0.0–1.0)
# Appelé uniquement en mode `deep` (Q1 validé)

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    """
    Interroge l'API FIRST.org EPSS pour une liste de CVE-IDs.

    L'API accepte jusqu'à 30 CVE par requête via le paramètre `cve=CVE-A,CVE-B,...`.
    Résultats mis en cache (TTL 24h).

    Paramètres :
        cve_ids : liste de CVE-IDs à interroger (ex: ["CVE-2024-0001", ...])

    Retourne :
        dict { "CVE-2024-0001": 0.85, "CVE-2024-0002": 0.12, ... }
        Les CVE non trouvées ne sont pas incluses.
    """
    if not cve_ids:
        return {}

    results: dict[str, float] = {}

    # Séparer cache hits et misses
    to_fetch: list[str] = []
    for cve_id in cve_ids:
        cached = epss_cache.get(cve_id)
        if cached is not None:
            results[cve_id] = cached
        else:
            to_fetch.append(cve_id)

    if not to_fetch:
        return results

    # Batch par 30 (limite API FIRST.org)
    BATCH_SIZE = 30
    batches = [to_fetch[i: i + BATCH_SIZE] for i in range(0, len(to_fetch), BATCH_SIZE)]

    for batch in batches:
        try:
            cve_param = ",".join(batch)
            response = requests.get(
                EPSS_API_URL,
                params={"cve": cve_param},
                timeout=15,
            )
            if response.status_code != 200:
                logger.warning("[EPSS] API FIRST.org retourne %d pour le batch", response.status_code)
                continue

            data = response.json()
            for entry in data.get("data", []):
                cve_id = entry.get("cve", "")
                epss_val = entry.get("epss")
                if cve_id and epss_val is not None:
                    try:
                        score = float(epss_val)
                        results[cve_id] = score
                        epss_cache.set(cve_id, score)
                    except (ValueError, TypeError):
                        pass

        except requests.exceptions.Timeout:
            logger.warning("[EPSS] Timeout API FIRST.org — EPSS non disponible pour ce batch")
        except Exception as e:
            logger.debug("[EPSS] Erreur API FIRST.org : %s", e)

    logger.info(
        "[EPSS] %d/%d CVE enrichies avec le score EPSS",
        len([r for r in results if r in to_fetch]), len(to_fetch)
    )
    return results


def http_post_with_retry(url: str, payload: dict, headers: dict | None = None, delay_before: float = 0.0) -> dict | None:
    if delay_before > 0:
        time.sleep(delay_before)
    headers = headers or {"Content-Type": "application/json"}
    for attempt in range(1, MAX_RETRY_ON_RATE_LIMIT + 1):
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=HTTP_TIMEOUT)
            if response.status_code == 429:
                wait = RATE_LIMIT_PAUSE_SECONDS * attempt  # backoff progressif
                logger.warning("Rate limit OSV/NVD (429). Pause %ss avant retry %d/%d", wait, attempt, MAX_RETRY_ON_RATE_LIMIT)
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(wait)
                    continue
                return None
            if response.status_code >= 500:
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(2 ** attempt)  # backoff exponentiel : 2s, 4s
                    continue
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.warning("Timeout HTTP POST vers %s (tentative %d/%d)", url, attempt, MAX_RETRY_ON_RATE_LIMIT)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2 ** attempt)
        except requests.exceptions.ConnectionError:
            logger.warning("Erreur connexion HTTP POST vers %s (tentative %d/%d)", url, attempt, MAX_RETRY_ON_RATE_LIMIT)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            logger.warning("Erreur requête POST %s: %s", url, e)
            break  # Erreur non-retriable
    return None

def http_get_with_retry(url: str, params: dict | None = None, headers: dict | None = None, delay_before: float = 0.0) -> dict | None:
    if delay_before > 0:
        time.sleep(delay_before)
    headers = headers or {}
    for attempt in range(1, MAX_RETRY_ON_RATE_LIMIT + 1):
        try:
            response = requests.get(url, params=params, headers=headers, timeout=HTTP_TIMEOUT)
            if response.status_code == 429:
                wait = RATE_LIMIT_PAUSE_SECONDS * attempt
                logger.warning("Rate limit (429). Pause %ss avant retry %d/%d", wait, attempt, MAX_RETRY_ON_RATE_LIMIT)
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(wait)
                    continue
                return None
            if response.status_code == 404:
                return None
            if response.status_code >= 500:
                if attempt < MAX_RETRY_ON_RATE_LIMIT:
                    time.sleep(2 ** attempt)
                    continue
                return None
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.warning("Timeout HTTP GET vers %s (tentative %d/%d)", url, attempt, MAX_RETRY_ON_RATE_LIMIT)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2 ** attempt)
        except requests.exceptions.ConnectionError:
            logger.warning("Erreur connexion HTTP GET vers %s (tentative %d/%d)", url, attempt, MAX_RETRY_ON_RATE_LIMIT)
            if attempt < MAX_RETRY_ON_RATE_LIMIT:
                time.sleep(2 ** attempt)
        except requests.exceptions.RequestException as e:
            logger.warning("Erreur requête GET %s: %s", url, e)
            break
    return None

def parse_cvss_v3_base_score(vector_string: str) -> float:
    if not vector_string or 'AV:' not in vector_string:
        return 0.0
    try:
        metrics = {}
        for part in vector_string.split('/'):
            if ':' in part:
                k, v = part.split(':', 1)
                metrics[k] = v
        AV_vals = {'N': 0.85, 'A': 0.62, 'L': 0.55, 'P': 0.20}
        AC_vals = {'L': 0.77, 'H': 0.44}
        PR_U_vals = {'N': 0.85, 'L': 0.62, 'H': 0.27}
        PR_C_vals = {'N': 0.85, 'L': 0.68, 'H': 0.50}
        UI_vals   = {'N': 0.85, 'R': 0.62}
        CIA_vals  = {'H': 0.56, 'L': 0.22, 'N': 0.00}
        
        AV = AV_vals.get(metrics.get('AV', ''), 0.85)
        AC = AC_vals.get(metrics.get('AC', ''), 0.77)
        S  = metrics.get('S', 'U')
        PR = (PR_C_vals if S == 'C' else PR_U_vals).get(metrics.get('PR', ''), 0.85)
        UI = UI_vals.get(metrics.get('UI', ''), 0.85)
        C  = CIA_vals.get(metrics.get('C', ''), 0.00)
        I  = CIA_vals.get(metrics.get('I', ''), 0.00)
        A  = CIA_vals.get(metrics.get('A', ''), 0.00)

        ISCBase = 1.0 - (1.0 - C) * (1.0 - I) * (1.0 - A)
        if S == 'U':
            ISC = 6.42 * ISCBase
        else:
            ISC = 7.52 * (ISCBase - 0.029) - 3.25 * pow(ISCBase - 0.02, 15)

        if ISC <= 0:
            return 0.0

        ESC = 8.22 * AV * AC * PR * UI

        if S == 'U':
            raw = ISC + ESC
        else:
            raw = 1.08 * (ISC + ESC)
            
        raw = min(raw, 10.0)
        return round(min(math.ceil(raw * 10) / 10, 10.0), 1)
    except Exception:
        return 0.0

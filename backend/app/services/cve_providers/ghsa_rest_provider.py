"""
ghsa_rest_provider.py
---------------------
Provider GHSA via API REST publique (sans GITHUB_TOKEN).

Utilisé uniquement en mode deep pour enrichir les résultats OSV.
Endpoint : GET https://api.github.com/advisories
Documentation : https://docs.github.com/en/rest/security-advisories

Différences vs GHSAProvider (GraphQL) :
  - Pas de token requis (public, rate-limit 60 req/h sans token)
  - Recherche par CVE-ID ou par package/ecosystem
  - Utilisé en mode deep uniquement pour les CVE déjà trouvées par OSV
    → n'alourdit pas le mode standard

Rate-limit sans token : 60 req/h = 1 req/min → on limite à 1 appel/CVE max.
"""

import logging
import time
from typing import Optional

import requests
import requests.exceptions

from app.services.cve_providers.models import VulnerabilityResult, Severity, cvss_to_severity
from app.services.cve_providers.utils import ThreadSafeCache

logger = logging.getLogger(__name__)

# Cache TTL 6h (données moins fraîches que le mode authenticated)
_ghsa_rest_cache: ThreadSafeCache = ThreadSafeCache(maxsize=2000, ttl_seconds=21600.0)

GHSA_REST_URL = "https://api.github.com/advisories"


def fetch_ghsa_advisory_by_cve(
    cve_id: str,
    timeout: float = 8.0,
) -> Optional[VulnerabilityResult]:
    """
    Récupère un advisory GHSA par CVE-ID via l'API REST publique.

    Retourne le premier advisory correspondant, ou None si non trouvé.
    Ne lève jamais d'exception (toutes les erreurs retournent None).
    """
    if not cve_id.startswith("CVE-"):
        return None

    cache_key = f"ghsa_rest:{cve_id}"
    cached = _ghsa_rest_cache.get(cache_key)
    if cached is not None:
        return cached if cached != "MISS" else None

    try:
        response = requests.get(
            GHSA_REST_URL,
            params={"cve_id": cve_id, "per_page": 1},
            headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
            timeout=timeout,
        )

        if response.status_code == 403:
            logger.warning("[GHSA-REST] Rate-limit atteint (403). GHSA REST ignoré.")
            _ghsa_rest_cache.set(cache_key, "MISS")
            return None

        if response.status_code != 200:
            _ghsa_rest_cache.set(cache_key, "MISS")
            return None

        advisories = response.json()
        if not isinstance(advisories, list) or not advisories:
            _ghsa_rest_cache.set(cache_key, "MISS")
            return None

        adv = advisories[0]

        # Extraire le score CVSS depuis la structure REST
        cvss_score = 0.0
        cvss_vector = adv.get("cvss", {}) or {}
        if cvss_vector:
            cvss_score = float(cvss_vector.get("score", 0.0))

        # Extraire le EPSS si disponible
        epss_score = None
        epss_data = adv.get("epss", None)
        if epss_data and isinstance(epss_data, list) and epss_data:
            epss_score = float(epss_data[0].get("percentage", 0.0))

        # Trouver la version corrigée dans les packages vulnérables
        fixed_version = None
        vulnerabilities = adv.get("vulnerabilities", []) or []
        for vuln_entry in vulnerabilities[:1]:
            patched = (vuln_entry.get("patched_versions") or "").strip()
            if patched and patched != "None":
                fixed_version = patched.lstrip(">= ").strip()
                break

        result = VulnerabilityResult(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=cvss_to_severity(cvss_score),
            description=(adv.get("summary") or "")[:500],
            source="GHSA-REST",
            fixed_version=fixed_version,
            epss_score=epss_score,
        )

        _ghsa_rest_cache.set(cache_key, result)
        return result

    except requests.exceptions.Timeout:
        logger.debug("[GHSA-REST] Timeout pour %s", cve_id)
        _ghsa_rest_cache.set(cache_key, "MISS")
        return None
    except Exception as e:
        logger.debug("[GHSA-REST] Erreur pour %s : %s", cve_id, e)
        _ghsa_rest_cache.set(cache_key, "MISS")
        return None

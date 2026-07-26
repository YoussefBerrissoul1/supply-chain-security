"""
NVD Provider — National Vulnerability Database (NIST).

Rôle dans l'architecture :
  Enrichissement par CVE-ID uniquement (pas de scan par dépendance).
  Appelé APRÈS OSV+GHSA pour compléter/corriger les scores CVSS.

Endpoint : GET /rest/json/cves/2.0?cveId=CVE-XXXX-YYYY

Améliorations v2.0 (audit Phase 2+3) :
  - Extraction EPSS score (probabilité d'exploitation à 30 jours)
  - Extraction CWE (type de faiblesse : XSS, SQLi, etc.)
  - Description enrichie (préfère la description officielle NVD)
  - Gestion CISA KEV via champ cisaExploitAdd
"""

import logging
import time
from typing import Any

from app.core.config import settings
from app.services.cve_providers.models import VulnerabilityResult, Severity, cvss_to_severity
from app.services.cve_providers.utils import http_get_with_retry, nvd_cache, parse_cvss_v3_base_score

logger = logging.getLogger(__name__)

# Délais respectant les quotas NVD :
# Sans clé : 5 req / 30s → 6s entre requêtes
# Avec clé  : 50 req / 30s → 0.6s entre requêtes
NVD_DELAY_SECONDS = 6.0
NVD_DELAY_WITH_KEY = 0.6

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDProvider:
    """
    Provider NVD — enrichissement des CVE avec données officielles NIST.

    N'implémente pas `query(dep)` car NVD s'interroge par CVE-ID,
    pas par dépendance. Utilise `enrich(cve_id)` à la place.
    """

    @property
    def name(self) -> str:
        return "NVD"

    def enrich(self, cve_id: str) -> VulnerabilityResult | None:
        """
        Interroge l'API NVD pour enrichir un CVE avec :
          - Score CVSS officiel (v3.1 > v3.0 > v2)
          - Score EPSS (probabilité d'exploitation)
          - CWE (type de faiblesse)
          - Description officielle en anglais
          - Indicateur CISA KEV (exploit confirmé)

        Retourne None si le CVE n'est pas trouvé dans NVD.
        """
        # Cache HIT
        cached = nvd_cache.get(cve_id)
        if cached is not None:
            return cached

        # Choisir le délai selon la présence du token
        delay = NVD_DELAY_WITH_KEY if settings.NVD_API_KEY else NVD_DELAY_SECONDS
        headers: dict = {}
        if settings.NVD_API_KEY:
            headers["apiKey"] = settings.NVD_API_KEY

        response_data = http_get_with_retry(
            url=NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            delay_before=delay,
        )

        if response_data is None:
            logger.warning("[NVD] API inaccessible pour %s", cve_id)
            return None

        vulns = response_data.get("vulnerabilities", [])
        if not vulns:
            nvd_cache.set(cve_id, None)
            return None

        cve_data = vulns[0].get("cve", {})

        # ── Extraire les données NVD ────────────────────────────────────────
        cvss_score, severity = self._extract_nvd_score(cve_data)
        description         = self._extract_description(cve_data)
        published_date      = cve_data.get("published")
        epss_score          = self._extract_epss(cve_data)
        cwe                 = self._extract_cwe(cve_data)

        # Exploit confirmé via CISA KEV (champ propre à NVD 2.0)
        exploit_available = "cisaExploitAdd" in cve_data

        result = VulnerabilityResult(
            cve_id=cve_id,
            cvss_score=cvss_score,
            severity=severity,
            description=description,
            source="NVD",
            cvss_source="NVD",
            exploit_available=exploit_available,
            published_date=published_date,
            epss_score=epss_score,
            cwe=cwe,
        )

        nvd_cache.set(cve_id, result)
        logger.debug(
            "[NVD] %s enrichi : CVSS=%.1f, EPSS=%s, CWE=%s, exploit=%s",
            cve_id, cvss_score,
            f"{epss_score:.3f}" if epss_score is not None else "N/A",
            cwe or "N/A",
            exploit_available,
        )
        return result

    # ── Extracteurs internes ───────────────────────────────────────────────

    def _extract_nvd_score(self, cve_data: dict) -> tuple[float, Severity]:
        """
        Extrait le score CVSS en priorité :
        CVSSv3.1 → CVSSv3.0 → CVSSv2 (moins précis).
        """
        metrics = cve_data.get("metrics", {})

        for metric_key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            metric_list = metrics.get(metric_key, [])
            if not metric_list:
                continue

            cvss_data = metric_list[0].get("cvssData", {})
            score = float(cvss_data.get("baseScore", 0.0))
            vector = cvss_data.get("vectorString", "")

            # Préférer le calcul depuis le vector string (plus précis)
            if vector and "AV:" in vector and metric_key != "cvssMetricV2":
                computed = parse_cvss_v3_base_score(vector)
                if computed > 0:
                    return computed, cvss_to_severity(computed)

            return score, cvss_to_severity(score)

        return 0.0, Severity.NONE

    def _extract_description(self, cve_data: dict) -> str:
        """Extrait la description officielle NVD en anglais."""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                return str(desc.get("value", ""))[:500]
        return "Aucune description NVD disponible."

    def _extract_epss(self, cve_data: dict) -> float | None:
        """
        Extrait le score EPSS (Exploit Prediction Scoring System).
        
        EPSS indique la probabilité qu'une CVE soit exploitée dans les 30 prochains jours.
        Valeur entre 0.0 (très peu probable) et 1.0 (quasi-certain).
        
        Note : NVD 2.0 inclut EPSS dans le champ `metrics.epss[0].epssScore`.
        """
        metrics = cve_data.get("metrics", {})
        epss_list = metrics.get("epss", [])
        if epss_list:
            try:
                score = float(epss_list[0].get("epssScore", 0.0))
                return score if score > 0.0 else None
            except (ValueError, TypeError, IndexError):
                pass
        return None

    def _extract_cwe(self, cve_data: dict) -> str | None:
        """
        Extrait l'identifiant CWE principal (Common Weakness Enumeration).

        Ex: "CWE-79"  → Cross-Site Scripting (XSS)
            "CWE-89"  → SQL Injection
            "CWE-22"  → Path Traversal
            "CWE-787" → Out-of-bounds Write

        NVD stocke les CWE dans : cve.weaknesses[].description[].value
        """
        weaknesses = cve_data.get("weaknesses", [])
        for weakness in weaknesses:
            for desc_entry in weakness.get("description", []):
                value = desc_entry.get("value", "")
                if value.startswith("CWE-") and value != "CWE-noinfo" and value != "CWE-Other":
                    return value
        return None

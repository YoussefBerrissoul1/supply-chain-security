"""
GHSA Provider — GitHub Security Advisories.

Interroge l'API GraphQL GitHub pour récupérer les vulnérabilités de sécurité.

Corrections v2.0 (audit Phase 1) :
  - Filtrage par version via packaging.specifiers.SpecifierSet
    → Élimine les faux positifs (GHSA retournait TOUTES les CVE du package)
  - Cache TTL 24h (identique à OSV/NVD)
  - Retry via http_post_with_retry (robustesse réseau)
"""

import logging
import time
from packaging.version import Version, InvalidVersion
from packaging.specifiers import SpecifierSet, InvalidSpecifier

from app.core.config import settings
from app.services.dependency_scanner import DependencyInfo
from app.services.cve_providers.base_provider import BaseCVEProvider
from app.services.cve_providers.models import VulnerabilityResult, cvss_to_severity
from app.services.cve_providers.utils import ThreadSafeCache

logger = logging.getLogger(__name__)

# ── Cache GHSA (TTL 24h, 5000 entrées) ─────────────────────────────────────
ghsa_cache: ThreadSafeCache = ThreadSafeCache(maxsize=5000, ttl_seconds=86400.0)

GHSA_API_URL = "https://api.github.com/graphql"

GHSA_ECOSYSTEM_MAP: dict[str, str] = {
    "python": "PIP",
    "nodejs": "NPM",
    "java":   "MAVEN",
    "ruby":   "RUBYGEMS",
    "php":    "COMPOSER",
    "rust":   "RUST",
    "go":     "GO",
    "nuget":  "NUGET",
}

# Query GraphQL — récupère les 100 premières vulnérabilités avec toutes les métadonnées
_GHSA_GRAPHQL_QUERY = """
query($package: String!, $ecosystem: SecurityAdvisoryEcosystem!) {
  securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 100) {
    nodes {
      advisory {
        ghsaId
        summary
        description
        cvss {
          score
          vectorString
        }
        publishedAt
        identifiers {
          type
          value
        }
        references {
          url
        }
      }
      vulnerableVersionRange
      firstPatchedVersion {
        identifier
      }
    }
    pageInfo {
      hasNextPage
    }
  }
}
"""


def _version_is_affected(dep_version: str, vulnerable_range: str | None) -> bool:
    """
    Vérifie si la version installée est dans la plage vulnérable GHSA.

    GHSA utilise un format compatible avec PEP 440 :
    ex: ">= 2.0.1, < 2.3.2"  →  SpecifierSet(">= 2.0.1, < 2.3.2")

    Retourne True si la version est affectée (ou si on ne peut pas déterminer).
    L'approche "fail-open" évite les faux négatifs :
    si la plage ne peut pas être parsée, on inclut la vulnérabilité.
    """
    if not vulnerable_range or not dep_version or dep_version in ("unknown", "latest", ""):
        # Pas assez d'info pour filtrer → on inclut (fail-open)
        return True

    try:
        installed = Version(dep_version)
    except InvalidVersion:
        # Version non-standard (ex: "2.0.0rc1", "dev" ...) → fail-open
        logger.debug("[GHSA] Version non-parseable '%s' — inclusion par défaut", dep_version)
        return True

    try:
        spec = SpecifierSet(vulnerable_range)
        affected = installed in spec
        logger.debug(
            "[GHSA] Version %s dans la plage '%s' → %s",
            dep_version, vulnerable_range, "AFFECTÉE" if affected else "non affectée"
        )
        return affected
    except InvalidSpecifier:
        # Plage non-standard (ex: "All versions") → fail-open
        logger.debug("[GHSA] Plage non-parseable '%s' — inclusion par défaut", vulnerable_range)
        return True


class GHSAProvider(BaseCVEProvider):
    """
    Provider GitHub Security Advisories (GHSA).

    Utilise l'API GraphQL GitHub pour récupérer les CVE par package.
    Filtre les résultats par version installée pour éviter les faux positifs.
    """

    @property
    def name(self) -> str:
        return "GHSA"

    def query(self, dep: DependencyInfo) -> list[VulnerabilityResult]:
        """
        Interroge GHSA pour une dépendance et filtre par version.

        Retourne uniquement les CVE où la version installée est dans
        la plage `vulnerableVersionRange` de l'advisory.
        """
        if not settings.GITHUB_TOKEN:
            logger.debug("[GHSA] GITHUB_TOKEN non configuré — skipped")
            return []

        ghsa_ecosystem = GHSA_ECOSYSTEM_MAP.get(dep.ecosystem)
        if not ghsa_ecosystem:
            return []

        # Cache key : nom@version@ecosystem
        cache_key = f"{dep.name}@{dep.version}@{ghsa_ecosystem}"
        cached = ghsa_cache.get(cache_key)
        if cached is not None:
            return cached

        # Construire les headers d'authentification
        headers = {
            "Authorization": f"bearer {settings.GITHUB_TOKEN}",
            "Content-Type": "application/json",
        }

        import requests
        import requests.exceptions

        for attempt in range(1, 4):
            try:
                response = requests.post(
                    GHSA_API_URL,
                    json={
                        "query": _GHSA_GRAPHQL_QUERY,
                        "variables": {
                            "package": dep.name,
                            "ecosystem": ghsa_ecosystem,
                        },
                    },
                    headers=headers,
                    timeout=30,
                )

                if response.status_code == 429:
                    wait = 12.0 * attempt
                    logger.warning("[GHSA] Rate limit (429). Pause %.0fs avant retry %d/3", wait, attempt)
                    if attempt < 3:
                        time.sleep(wait)
                        continue
                    ghsa_cache.set(cache_key, [])
                    return []

                if response.status_code >= 500:
                    if attempt < 3:
                        time.sleep(2 ** attempt)
                        continue
                    ghsa_cache.set(cache_key, [])
                    return []

                response.raise_for_status()
                data = response.json()

                if "errors" in data:
                    logger.warning("[GHSA] Erreurs GraphQL pour %s : %s", dep.name, data["errors"])
                    ghsa_cache.set(cache_key, [])
                    return []

                nodes = (
                    data.get("data", {})
                        .get("securityVulnerabilities", {})
                        .get("nodes", [])
                )

                # Log pagination warning si plus de 100 résultats
                page_info = (
                    data.get("data", {})
                        .get("securityVulnerabilities", {})
                        .get("pageInfo", {})
                )
                if page_info.get("hasNextPage"):
                    logger.warning(
                        "[GHSA] Package '%s' a plus de 100 advisories — "
                        "seuls les 100 premiers sont analysés.",
                        dep.name
                    )

                break  # Succès

            except requests.exceptions.Timeout:
                logger.warning("[GHSA] Timeout pour %s (tentative %d/3)", dep.name, attempt)
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                ghsa_cache.set(cache_key, [])
                return []
            except requests.exceptions.ConnectionError:
                logger.warning("[GHSA] Erreur réseau pour %s (tentative %d/3)", dep.name, attempt)
                if attempt < 3:
                    time.sleep(2 ** attempt)
                    continue
                ghsa_cache.set(cache_key, [])
                return []
            except requests.exceptions.RequestException as e:
                logger.error("[GHSA] Erreur non-retriable pour %s : %s", dep.name, e)
                ghsa_cache.set(cache_key, [])
                return []
        else:
            # Toutes les tentatives ont échoué
            ghsa_cache.set(cache_key, [])
            return []

        # ── Parser et filtrer les résultats ──────────────────────────────────
        results: list[VulnerabilityResult] = []
        filtered_out = 0

        for node in nodes:
            advisory = node.get("advisory", {})
            ghsa_id = advisory.get("ghsaId")
            if not ghsa_id:
                continue

            vulnerable_range = node.get("vulnerableVersionRange")

            # ★ CORRECTION CRITIQUE : Filtrer par version installée
            if not _version_is_affected(dep.version, vulnerable_range):
                filtered_out += 1
                logger.debug(
                    "[GHSA] '%s@%s' NON affecté par %s (plage: %s) — exclu",
                    dep.name, dep.version, ghsa_id, vulnerable_range
                )
                continue

            # Extraire le CVE-ID (préféré) ou garder le GHSA-ID
            cve_id = ghsa_id
            for ident in advisory.get("identifiers", []):
                if ident.get("type") == "CVE":
                    cve_id = ident.get("value", ghsa_id)
                    break

            # Score CVSS
            cvss_info = advisory.get("cvss") or {}
            score = float(cvss_info.get("score", 0.0))

            # Version corrigée
            patched = node.get("firstPatchedVersion")
            fixed_version = patched.get("identifier") if patched else None

            result = VulnerabilityResult(
                cve_id=cve_id,
                cvss_score=score,
                severity=cvss_to_severity(score),
                description=(advisory.get("summary") or "")[:500],
                source="GHSA",
                cvss_source="GHSA",
                fixed_version=fixed_version,
                published_date=advisory.get("publishedAt"),
            )
            results.append(result)

        if filtered_out > 0:
            logger.info(
                "[GHSA] %s@%s : %d advisory(s) non applicables filtrés "
                "(version hors plage vulnérable)",
                dep.name, dep.version, filtered_out
            )

        if results:
            logger.info(
                "[GHSA] %s@%s : %d CVE confirmées dans la version installée",
                dep.name, dep.version, len(results)
            )

        # Mettre en cache
        ghsa_cache.set(cache_key, results)
        return results

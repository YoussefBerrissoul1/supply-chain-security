"""
OSV Provider — utilise l'API Google Open Source Vulnerabilities.

Optimisation clé : utilise /v1/querybatch au lieu de /v1/query
→ 1 requête HTTP pour N dépendances (au lieu de N requêtes)
→ Gain de 10x à 100x en vitesse selon la taille du repo

Endpoints utilisés :
  - POST /v1/querybatch  ← méthode principale (batch)
  - POST /v1/query       ← fallback par dépendance unique (méthode query())

Documentation officielle OSV :
  https://google.github.io/osv.dev/post-v1-querybatch/
"""

import logging
import time
from typing import Any

from app.core.config import settings
from app.services.dependency_scanner import DependencyInfo
from app.services.cve_providers.base_provider import BaseCVEProvider
from app.services.cve_providers.models import VulnerabilityResult, cvss_to_severity
from app.services.cve_providers.utils import (
    http_post_with_retry,
    http_get_with_retry,
    parse_cvss_v3_base_score,
    cisa_kev,
    osv_cache,
)

logger = logging.getLogger(__name__)

# URLs officiels OSV API
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_QUERYBATCH_URL = "https://api.osv.dev/v1/querybatch"

# Taille maximale d'un batch (recommandation OSV : max 1000, on reste conservateur)
OSV_MAX_BATCH_SIZE = 100

# Mapping écosystème interne → format OSV API
OSV_ECOSYSTEM_MAP: dict[str, str] = {
    "python": "PyPI",
    "nodejs": "npm",
    "java":   "Maven",
    "ruby":   "RubyGems",
    "php":    "Packagist",
    "rust":   "crates.io",
    "go":     "Go",
}


class OSVProvider(BaseCVEProvider):
    """
    Provider OSV (Open Source Vulnerabilities) de Google.
    
    Méthode principale : query_batch() — une seule requête HTTP pour tout le repo.
    Méthode fallback   : query()       — une requête par dépendance (héritage).
    """

    @property
    def name(self) -> str:
        return "OSV"

    # ─────────────────────────────────────────────────────────────────────────
    # MÉTHODE PRINCIPALE : Batch (1 requête HTTP pour N dépendances)
    # ─────────────────────────────────────────────────────────────────────────

    def query_batch(
        self, deps: list[DependencyInfo]
    ) -> dict[str, list[VulnerabilityResult]]:
        """
        Interroge OSV /v1/querybatch pour plusieurs dépendances en une seule requête.

        Format de la requête :
            POST /v1/querybatch
            { "queries": [ {package: {...}, version: "x.y.z"}, ... ] }

        Format de la réponse :
            { "results": [ {"vulns": [...]}, {"vulns": []}, ... ] }
            → results[i] correspond à queries[i]

        Retourne : dict["{name}@{version}" -> list[VulnerabilityResult]]
        """
        if not deps:
            return {}

        final_results: dict[str, list[VulnerabilityResult]] = {}

        # 1) Séparer les dépendances en cache vs à interroger
        to_query: list[tuple[DependencyInfo, str, str]] = []  # (dep, dep_key, cache_key)

        for dep in deps:
            dep_key = f"{dep.name}@{dep.version}"
            osv_ecosystem = OSV_ECOSYSTEM_MAP.get(dep.ecosystem)

            if not osv_ecosystem:
                # Écosystème non supporté par OSV (ex: docker, autres)
                final_results[dep_key] = []
                continue

            cache_key = f"{dep.name}@{dep.version}@{osv_ecosystem}"
            cached = osv_cache.get(cache_key)
            if cached is not None:
                # Cache HIT
                final_results[dep_key] = cached
            else:
                # Cache MISS → à interroger
                to_query.append((dep, dep_key, cache_key))

        cache_hits = len(final_results)
        logger.info(
            "[OSV Batch] %d dépendances total — %d en cache, %d à interroger via querybatch",
            len(deps), cache_hits, len(to_query)
        )

        if not to_query:
            return final_results

        # 2) Découper en sous-batches si nécessaire (max OSV_MAX_BATCH_SIZE)
        batches = [
            to_query[i: i + OSV_MAX_BATCH_SIZE]
            for i in range(0, len(to_query), OSV_MAX_BATCH_SIZE)
        ]

        total_vulns_found = 0

        for batch_idx, batch in enumerate(batches, start=1):
            logger.debug(
                "[OSV Batch %d/%d] Envoi de %d requêtes vers %s",
                batch_idx, len(batches), len(batch), OSV_QUERYBATCH_URL
            )

            # Construire le payload querybatch
            queries_payload: list[dict] = []
            for dep, dep_key, cache_key in batch:
                osv_ecosystem = OSV_ECOSYSTEM_MAP[dep.ecosystem]
                q: dict = {
                    "package": {
                        "name": dep.name,
                        "ecosystem": osv_ecosystem,
                    }
                }
                if dep.version and dep.version not in ("unknown", "latest", ""):
                    q["version"] = dep.version
                queries_payload.append(q)

            payload = {"queries": queries_payload}

            # 3) Envoyer le batch
            start_time = time.monotonic()
            response_data = http_post_with_retry(
                url=OSV_QUERYBATCH_URL,
                payload=payload,
            )
            elapsed = time.monotonic() - start_time

            if response_data is None:
                # Échec réseau pour ce batch → on marque toutes les deps comme vides
                logger.warning(
                    "[OSV Batch %d/%d] Échec réseau (timeout ou 5xx). "
                    "%d dépendances non scannées. Durée : %.2fs",
                    batch_idx, len(batches), len(batch), elapsed
                )
                for dep, dep_key, cache_key in batch:
                    final_results[dep_key] = []
                continue

            # 4) Parser la réponse
            batch_results: list[dict] = response_data.get("results", [])

            if len(batch_results) != len(batch):
                logger.warning(
                    "[OSV Batch %d/%d] Réponse incomplète : attendu %d résultats, reçu %d",
                    batch_idx, len(batches), len(batch), len(batch_results)
                )

            batch_vulns = 0

            for i, (dep, dep_key, cache_key) in enumerate(batch):
                if i >= len(batch_results):
                    # Réponse partielle — on considère vide
                    final_results[dep_key] = []
                    osv_cache.set(cache_key, [])
                    continue

                osv_ecosystem = OSV_ECOSYSTEM_MAP[dep.ecosystem]
                raw_result = batch_results[i]
                vulns_data: list[dict] = raw_result.get("vulns", [])

                parsed = self._parse_vulns(vulns_data, osv_ecosystem, dep.name)
                osv_cache.set(cache_key, parsed)
                final_results[dep_key] = parsed
                batch_vulns += len(parsed)

            total_vulns_found += batch_vulns
            logger.info(
                "[OSV Batch %d/%d] ✓ %d dépendances scannées — %d CVE trouvées — %.2fs",
                batch_idx, len(batches), len(batch), batch_vulns, elapsed
            )

        logger.info(
            "[OSV Batch] Terminé : %d dépendances scannées, %d CVE totales",
            len(to_query), total_vulns_found
        )

        return final_results

    # ─────────────────────────────────────────────────────────────────────────
    # MÉTHODE FALLBACK : Query individuel (rétrocompatibilité)
    # ─────────────────────────────────────────────────────────────────────────

    def query(self, dep: DependencyInfo) -> list[VulnerabilityResult]:
        """
        Interroge OSV /v1/query pour une seule dépendance.
        Utilisé en fallback ou pour les tests unitaires.
        """
        osv_ecosystem = OSV_ECOSYSTEM_MAP.get(dep.ecosystem)
        if not osv_ecosystem:
            return []

        cache_key = f"{dep.name}@{dep.version}@{osv_ecosystem}"
        cached = osv_cache.get(cache_key)
        if cached is not None:
            return cached

        payload: dict = {
            "package": {
                "name": dep.name,
                "ecosystem": osv_ecosystem,
            }
        }
        if dep.version and dep.version not in ("unknown", "latest", ""):
            payload["version"] = dep.version

        response_data = http_post_with_retry(
            url=OSV_QUERY_URL,
            payload=payload,
        )

        if response_data is None:
            raise Exception(f"OSV /v1/query inaccessible pour {dep.name}@{dep.version}")

        vulns_data = response_data.get("vulns", [])
        results = self._parse_vulns(vulns_data, osv_ecosystem, dep.name)
        osv_cache.set(cache_key, results)
        return results

    # ─────────────────────────────────────────────────────────────────────────
    # PARSERS INTERNES (communs à query et query_batch)
    # ─────────────────────────────────────────────────────────────────────────

    def _parse_vulns(
        self,
        vulns_data: list[dict],
        osv_ecosystem: str,
        package_name: str,
    ) -> list[VulnerabilityResult]:
        """Parse une liste de vulnérabilités OSV brutes en VulnerabilityResult."""
        results: list[VulnerabilityResult] = []

        for vuln in vulns_data:
            cve_id = self._extract_cve_id(vuln)
            cvss_score = self._extract_cvss(vuln)
            description = self._extract_description(vuln)
            fixed_version = self._extract_fixed_version(vuln, osv_ecosystem, package_name)
            published_date = vuln.get("published")
            exploit_available = self._detect_exploit(vuln)

            # Vérification CISA KEV (exploits connus publiquement)
            if not exploit_available and cve_id.startswith("CVE-"):
                if cisa_kev.is_exploited(cve_id):
                    exploit_available = True

            result = VulnerabilityResult(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=cvss_to_severity(cvss_score),
                description=description,
                source="OSV",
                cvss_source="OSV",
                fixed_version=fixed_version,
                exploit_available=exploit_available,
                published_date=published_date,
            )
            results.append(result)

        # Enrichissement CVSS + description depuis les aliases GHSA (ou l'ID lui-même si GHSA-*)
        # (les entrées PYSEC n'ont souvent pas de severity[] ni de summary contrairement aux GHSA)
        self._enrich_from_ghsa_aliases(results, vulns_data)

        return results

    def _enrich_from_ghsa_aliases(
        self,
        results: list[VulnerabilityResult],
        vulns_data: list[dict],
    ) -> None:
        """
        Pour les vulnérabilités sans score (0.0) OU sans description
        ("Aucune description OSV disponible."), tente de récupérer les deux
        depuis GET /v1/vulns/{id} — via alias GHSA, ID GHSA, ou ID brut OSV (PYSEC-*, etc.).
        """
        OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
        PLACEHOLDER_DESC = "Aucune description OSV disponible."

        for result, vuln_raw in zip(results, vulns_data):
            needs_score = result.cvss_score <= 0.0
            needs_desc = not result.description or result.description == PLACEHOLDER_DESC

            if not needs_score and not needs_desc:
                continue

            # Déterminer l'ID à interroger : alias GHSA, ID GHSA, ou ID brut OSV (PYSEC-*, etc.)
            aliases = vuln_raw.get("aliases", [])
            fetch_id = next((a for a in aliases if a.startswith("GHSA-")), None)
            if not fetch_id and result.cve_id.startswith("GHSA-"):
                fetch_id = result.cve_id
            if not fetch_id:
                fetch_id = vuln_raw.get("id")
            if not fetch_id or fetch_id == "UNKNOWN":
                continue

            cache_key = f"osv_full_{fetch_id}"
            cached = osv_cache.get(cache_key)
            if cached is None:
                vuln_full_data = http_get_with_retry(f"{OSV_VULN_URL}{fetch_id}")
                if not vuln_full_data:
                    osv_cache.set(cache_key, {"score": 0.0, "desc": ""})
                    continue
                cached = {
                    "score": self._extract_cvss(vuln_full_data),
                    "desc": vuln_full_data.get("summary") or vuln_full_data.get("details", ""),
                }
                osv_cache.set(cache_key, cached)

            if needs_score and cached["score"] > 0.0:
                from app.services.cve_providers.models import cvss_to_severity
                result.cvss_score = cached["score"]
                result.severity = cvss_to_severity(cached["score"])

            if needs_desc and cached["desc"]:
                result.description = cached["desc"]

            if needs_score or needs_desc:
                logger.debug(
                    "[OSV enrichissement] %s : backfill depuis %s (score=%s, desc=%s)",
                    result.cve_id, fetch_id, needs_score, needs_desc
                )

    def _extract_cve_id(self, vuln: dict) -> str:
        """Préfère l'alias CVE-XXXX-YYYY au GHSA ou OSV-ID."""
        osv_id = vuln.get("id", "UNKNOWN")
        aliases = vuln.get("aliases", [])
        for alias in aliases:
            if alias.startswith("CVE-"):
                return alias
        return osv_id

    def _extract_cvss(self, vuln: dict) -> float:
        """Extrait le score CVSS v3 en priorité, depuis plusieurs champs OSV possibles."""
        # Champ severity[] au niveau racine
        for sev_entry in vuln.get("severity", []):
            if "CVSS_V3" in sev_entry.get("type", ""):
                score_str = sev_entry.get("score", "")
                if score_str and "AV:" in score_str:
                    computed = parse_cvss_v3_base_score(score_str)
                    if computed > 0.0:
                        return computed

        # Champ database_specific.cvss
        db_specific = vuln.get("database_specific", {})
        cvss_info = db_specific.get("cvss", {})
        if isinstance(cvss_info, dict):
            vector_str = cvss_info.get("vectorString", "")
            if vector_str and "AV:" in vector_str:
                computed = parse_cvss_v3_base_score(vector_str)
                if computed > 0.0:
                    return computed
            score = cvss_info.get("score")
            if score is not None:
                try:
                    s = float(score)
                    if s > 0:
                        return s
                except (ValueError, TypeError):
                    pass

        # Champ severity[] dans affected[]
        for affected in vuln.get("affected", []):
            for sev_entry in affected.get("severity", []):
                if "CVSS_V3" in sev_entry.get("type", ""):
                    score_str = sev_entry.get("score", "")
                    if score_str and "AV:" in score_str:
                        computed = parse_cvss_v3_base_score(score_str)
                        if computed > 0.0:
                            return computed
                try:
                    s = float(sev_entry.get("score", 0))
                    if 0 < s <= 10:
                        return s
                except (ValueError, TypeError):
                    pass

        return 0.0

    def _detect_exploit(self, vuln: dict) -> bool:
        """Détecte si une référence de type EXPLOIT est présente dans OSV."""
        for ref in vuln.get("references", []):
            if ref.get("type", "").upper() == "EXPLOIT":
                return True
        return False

    def _extract_description(self, vuln: dict) -> str:
        """Extrait la description OSV (summary > details)."""
        desc = vuln.get("summary") or vuln.get("details", "Aucune description OSV disponible.")
        return str(desc)[:500]

    def _extract_fixed_version(
        self, vuln: dict, ecosystem: str, package_name: str
    ) -> str | None:
        """Extrait la version corrigée depuis les ranges ECOSYSTEM d'OSV."""
        for affected in vuln.get("affected", []):
            pkg = affected.get("package", {})
            if pkg.get("name") == package_name and pkg.get("ecosystem") == ecosystem:
                for r in affected.get("ranges", []):
                    if r.get("type") == "ECOSYSTEM":
                        for event in r.get("events", []):
                            if "fixed" in event:
                                return event["fixed"]
        return None

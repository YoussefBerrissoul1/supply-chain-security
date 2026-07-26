"""
Tests du moteur CVE — OSVProvider querybatch + cve_service.

Lancez avec : 
    cd backend
    venv\\Scripts\\activate
    pytest tests/test_cve_service.py -v
"""

import pytest
from unittest.mock import patch, MagicMock
from app.services.dependency_scanner import DependencyInfo
from app.services.cve_providers.osv_provider import OSVProvider
from app.services.cve_providers.models import VulnerabilityResult, Severity


# ──────────────────────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────────────────────

def make_dep(name: str, version: str = "1.0.0", ecosystem: str = "python") -> DependencyInfo:
    return DependencyInfo(name=name, version=version, ecosystem=ecosystem, source_file="requirements.txt")


# ──────────────────────────────────────────────────────────────────────────────
# Tests OSVProvider.query_batch
# ──────────────────────────────────────────────────────────────────────────────

class TestOSVProviderQueryBatch:

    def test_empty_deps_returns_empty_dict(self):
        """query_batch([]) doit retourner {} sans appel réseau."""
        osv = OSVProvider()
        result = osv.query_batch([])
        assert result == {}

    def test_unsupported_ecosystem_returns_empty(self):
        """Un écosystème non supporté (ex: 'docker') doit retourner []."""
        osv = OSVProvider()
        dep = make_dep("nginx", "1.21", ecosystem="docker")
        result = osv.query_batch([dep])
        assert result.get("nginx@1.21") == []

    def test_batch_uses_single_http_request(self):
        """
        query_batch pour N dépendances doit appeler http_post_with_retry UNE SEULE FOIS
        (et non N fois comme l'ancienne implémentation).
        """
        osv = OSVProvider()
        deps = [
            make_dep("requests", "2.25.1"),
            make_dep("flask", "2.0.1"),
            make_dep("django", "3.2.0"),
        ]

        fake_response = {
            "results": [
                {"vulns": [{"id": "CVE-2023-0001", "aliases": ["CVE-2023-0001"]}]},
                {"vulns": []},
                {"vulns": [{"id": "CVE-2023-0002", "aliases": ["CVE-2023-0002"]}]},
            ]
        }

        with patch(
            "app.services.cve_providers.osv_provider.http_post_with_retry",
            return_value=fake_response
        ) as mock_http:
            result = osv.query_batch(deps)

        # 1 seul appel HTTP pour 3 dépendances
        assert mock_http.call_count == 1

        # Vérifier l'URL utilisée
        call_args = mock_http.call_args
        assert "querybatch" in call_args.kwargs.get("url", call_args.args[0] if call_args.args else "")

        # Vérifier les résultats
        assert "requests@2.25.1" in result
        assert "flask@2.0.1" in result
        assert "django@3.2.0" in result

    def test_batch_correct_payload_structure(self):
        """La requête batch doit avoir la bonne structure JSON."""
        osv = OSVProvider()
        deps = [make_dep("pillow", "8.3.0")]

        fake_response = {"results": [{"vulns": []}]}

        with patch(
            "app.services.cve_providers.osv_provider.http_post_with_retry",
            return_value=fake_response
        ) as mock_http:
            osv.query_batch(deps)

        payload = mock_http.call_args.kwargs.get("payload", {})
        assert "queries" in payload
        assert len(payload["queries"]) == 1
        query = payload["queries"][0]
        assert query["package"]["name"] == "pillow"
        assert query["package"]["ecosystem"] == "PyPI"
        assert query["version"] == "8.3.0"

    def test_partial_response_handled_gracefully(self):
        """Si OSV retourne moins de résultats que de requêtes, on gère sans crash."""
        osv = OSVProvider()
        deps = [make_dep("a", "1.0"), make_dep("b", "2.0"), make_dep("c", "3.0")]

        # Réponse partielle : seulement 2 résultats pour 3 requêtes
        fake_response = {
            "results": [
                {"vulns": []},
                {"vulns": []},
                # manquant pour 'c'
            ]
        }

        with patch(
            "app.services.cve_providers.osv_provider.http_post_with_retry",
            return_value=fake_response
        ):
            result = osv.query_batch(deps)

        # Doit retourner sans crash, même si 'c' manque
        assert "a@1.0" in result
        assert "b@2.0" in result
        assert "c@3.0" in result  # Doit être dans les résultats même si vide

    def test_network_failure_returns_empty_not_exception(self):
        """
        En cas d'échec réseau (http_post_with_retry retourne None),
        query_batch doit retourner un dict avec des listes vides — sans lever d'exception.

        Note : on utilise un paquet unique (never-seen-lib) pour éviter les
        faux positifs dus au cache TTL partagé entre tests.
        """
        from app.services.cve_providers.utils import osv_cache
        osv = OSVProvider()
        dep = make_dep("never-seen-lib-xyz", "99.99.99")
        dep_key = "never-seen-lib-xyz@99.99.99"
        # Garantir que la clé n'est pas en cache
        cache_key = "never-seen-lib-xyz@99.99.99@PyPI"
        osv_cache.set(cache_key, None)  # invalide le cache pour cette clé

        with patch(
            "app.services.cve_providers.osv_provider.http_post_with_retry",
            return_value=None
        ):
            result = osv.query_batch([dep])

        assert isinstance(result, dict)
        # La dep doit figurer dans les résultats mais avec une liste vide
        assert dep_key in result
        assert result[dep_key] == []

    def test_cache_is_used_for_repeated_deps(self):
        """Les dépendances déjà en cache ne doivent pas déclencher de requête HTTP."""
        from app.services.cve_providers.utils import osv_cache
        
        osv = OSVProvider()
        dep = make_dep("cached-lib", "1.0.0")
        dep_key = "cached-lib@1.0.0"
        cache_key = "cached-lib@1.0.0@PyPI"
        
        # Pré-remplir le cache
        cached_result = [VulnerabilityResult(
            cve_id="CVE-2023-CACHED",
            cvss_score=7.5,
            severity=Severity.HIGH,
            description="Vulnérabilité pré-cachée",
        )]
        osv_cache.set(cache_key, cached_result)
        
        with patch(
            "app.services.cve_providers.osv_provider.http_post_with_retry"
        ) as mock_http:
            result = osv.query_batch([dep])
        
        # Aucun appel HTTP — tout vient du cache
        assert mock_http.call_count == 0
        assert result[dep_key] == cached_result


# ──────────────────────────────────────────────────────────────────────────────
# Tests scan_all_vulnerabilities
# ──────────────────────────────────────────────────────────────────────────────

class TestScanAllVulnerabilities:

    def test_empty_dependencies_returns_empty(self):
        """scan_all_vulnerabilities([]) doit retourner {} immédiatement."""
        from app.services.cve_service import scan_all_vulnerabilities
        result = scan_all_vulnerabilities([])
        assert result == {}

    def test_scan_meta_always_present(self):
        """Le résultat doit toujours contenir __scan_meta__."""
        from app.services.cve_service import scan_all_vulnerabilities
        deps = [make_dep("requests", "2.25.1")]

        with patch.object(OSVProvider, "query_batch", return_value={"requests@2.25.1": []}):
            result = scan_all_vulnerabilities(deps)

        assert "__scan_meta__" in result
        meta = result["__scan_meta__"]
        assert "deps_scanned" in meta
        assert "deps_total" in meta

    def test_truncation_applied_in_standard_mode(self):
        """En mode standard, seules MAX_DEPS_STANDARD (60) deps doivent être scannées."""
        from app.services.cve_service import scan_all_vulnerabilities, MAX_DEPS_STANDARD
        # Créer 80 dépendances
        deps = [make_dep(f"lib{i}", "1.0") for i in range(80)]

        captured_deps = []

        def fake_query_batch(self_deps):
            captured_deps.extend(self_deps)
            return {}

        with patch.object(OSVProvider, "query_batch", side_effect=fake_query_batch):
            result = scan_all_vulnerabilities(deps, scan_type="standard")

        meta = result.get("__scan_meta__", {})
        assert meta.get("deps_truncated") is True
        assert meta.get("deps_total") == 80
        assert meta.get("deps_scanned") == MAX_DEPS_STANDARD


# ──────────────────────────────────────────────────────────────────────────────
# Tests get_cve_summary
# ──────────────────────────────────────────────────────────────────────────────

class TestGetCVESummary:

    def test_empty_results(self):
        from app.services.cve_service import get_cve_summary
        result = get_cve_summary({})
        assert result["total_vulnerabilities"] == 0
        assert result["affected_packages"] == 0

    def test_counts_correctly(self):
        from app.services.cve_service import get_cve_summary

        scan_results = {
            "requests@2.25.1": [
                VulnerabilityResult("CVE-A", 9.8, Severity.CRITICAL, "desc"),
                VulnerabilityResult("CVE-B", 7.5, Severity.HIGH, "desc"),
            ],
            "flask@2.0.1": [
                VulnerabilityResult("CVE-C", 5.0, Severity.MEDIUM, "desc"),
            ],
            "safe-lib@3.0": [],
            "__scan_meta__": {},  # type: ignore
        }

        summary = get_cve_summary(scan_results)
        assert summary["total_vulnerabilities"] == 3
        assert summary["affected_packages"] == 2
        assert summary["clean_packages"] == 1
        assert summary["highest_severity"] == "CRITICAL"
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["by_severity"]["HIGH"] == 1
        assert summary["by_severity"]["MEDIUM"] == 1

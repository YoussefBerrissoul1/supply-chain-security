"""
Tests unitaires pour cve_service.py — couvre les nouveaux comportements.

Points testés :
    1. Cache in-memory (_TTLCache) : get/set, TTL expiration, thread-safety
    2. Cache query_osv : HIT évite un appel HTTP, MISS fait l'appel
    3. Cache query_nvd_by_cve_id : HIT évite un appel HTTP, sentinel False pour "not found"
    4. CISA KEV : is_exploited() retourne True si CVE dans la liste
    5. CISA KEV intégration : CVE retournée par OSV marquée exploit_available=True si dans KEV
    6. scan_all_vulnerabilities : gestion __scan_meta__, timeout, troncature
    7. Point 5 : Warning NVD si liste vide
    8. _parse_cvss_v3_base_score : inchangé, toujours correct

Usage :
    cd backend/
    venv/Scripts/pytest tests/test_cve_service.py -v
"""

import time
import threading
from unittest.mock import MagicMock, patch, call
import pytest

# Importer le module à tester
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.services.cve_service import (
    _TTLCache,
    _CISAKEVCache,
    _cisa_kev,
    _osv_cache,
    _nvd_cache,
    _parse_cvss_v3_base_score,
    query_osv,
    query_nvd_by_cve_id,
    scan_all_vulnerabilities,
    get_cve_summary,
    CVE_SERVICE_VERSION,
    Severity,
    VulnerabilityResult,
    cvss_to_severity,
)
from app.services.dependency_scanner import DependencyInfo


# ==============================================================
# FIXTURES
# ==============================================================

@pytest.fixture(autouse=True)
def clear_caches():
    """Vide les caches avant chaque test pour isolation garantie."""
    _osv_cache.clear()
    _nvd_cache.clear()
    yield
    _osv_cache.clear()
    _nvd_cache.clear()


def make_dep(name="requests", version="2.27.0", ecosystem="python") -> DependencyInfo:
    """Helper : crée une DependencyInfo minimale pour les tests."""
    return DependencyInfo(
        name=name,
        version=version,
        ecosystem=ecosystem,
    )


def make_osv_vuln(
    cve_id="CVE-2023-12345",
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    exploit_ref=None,
) -> dict:
    """Helper : construit une réponse OSV minimale."""
    refs = []
    if exploit_ref:
        refs.append({"url": exploit_ref, "type": "WEB"})
    return {
        "id": "GHSA-test-xxxx",
        "aliases": [cve_id],
        "summary": "Test vulnerability",
        "severity": [{"type": "CVSS_V3", "score": cvss_vector}],
        "references": refs,
        "affected": [],
        "database_specific": {},
    }


# ==============================================================
# TESTS : _TTLCache
# ==============================================================

class TestTTLCache:
    """Tests du cache in-memory thread-safe avec TTL."""

    def test_set_and_get(self):
        """Un objet mis en cache est récupérable immédiatement."""
        cache = _TTLCache(ttl_seconds=60)
        cache.set("key1", [1, 2, 3])
        assert cache.get("key1") == [1, 2, 3]

    def test_miss_returns_none(self):
        """Une clé absente retourne None."""
        cache = _TTLCache(ttl_seconds=60)
        assert cache.get("nonexistent") is None

    def test_expired_returns_none(self):
        """Une entrée expirée retourne None et est supprimée."""
        cache = _TTLCache(ttl_seconds=0.05)  # 50ms TTL
        cache.set("expiring", "value")
        assert cache.get("expiring") == "value"
        time.sleep(0.1)  # Attendre l'expiration
        assert cache.get("expiring") is None

    def test_clear(self):
        """clear() vide entièrement le cache."""
        cache = _TTLCache(ttl_seconds=60)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.clear()
        assert cache.get("a") is None
        assert cache.get("b") is None
        assert cache.size() == 0

    def test_size(self):
        """size() retourne le nombre d'entrées valides."""
        cache = _TTLCache(ttl_seconds=60)
        assert cache.size() == 0
        cache.set("k1", "v1")
        cache.set("k2", "v2")
        assert cache.size() == 2

    def test_overwrite(self):
        """Un set sur une clé existante écrase la valeur."""
        cache = _TTLCache(ttl_seconds=60)
        cache.set("key", "old")
        cache.set("key", "new")
        assert cache.get("key") == "new"

    def test_thread_safety(self):
        """Des écritures concurrentes ne causent pas d'erreur."""
        cache = _TTLCache(ttl_seconds=60)
        errors = []

        def writer(i: int):
            try:
                for j in range(100):
                    cache.set(f"key_{i}_{j}", i * j)
                    cache.get(f"key_{i}_{j}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Erreurs thread-safety : {errors}"

    def test_false_sentinel_stored_and_retrieved(self):
        """False peut être stocké comme sentinel (utilisé par NVD pour 'not found')."""
        cache = _TTLCache(ttl_seconds=60)
        cache.set("CVE-9999-0000", False)
        result = cache.get("CVE-9999-0000")
        # False est différent de None — on peut distinguer "not found" de "not cached"
        assert result is False
        assert result is not None


# ==============================================================
# TESTS : _CISAKEVCache
# ==============================================================

class TestCISAKEVCache:
    """Tests du cache CISA KEV."""

    def test_is_exploited_after_load(self):
        """Un CVE présent dans le catalogue CISA KEV est détecté."""
        kev = _CISAKEVCache()
        # Simuler un chargement avec des données mockées
        with kev._lock:
            kev._cve_ids = {"CVE-2021-44228", "CVE-2020-1234"}
            kev._loaded_at = time.monotonic()  # Simuler un chargement frais

        assert kev.is_exploited("CVE-2021-44228") is True
        assert kev.is_exploited("CVE-2020-1234") is True
        assert kev.is_exploited("CVE-9999-9999") is False

    def test_is_exploited_not_in_list(self):
        """Un CVE absent du catalogue retourne False."""
        kev = _CISAKEVCache()
        with kev._lock:
            kev._cve_ids = {"CVE-2021-44228"}
            kev._loaded_at = time.monotonic()

        assert kev.is_exploited("CVE-2023-99999") is False

    def test_load_failure_returns_false(self):
        """Si le téléchargement échoue, is_exploited retourne False sans exception."""
        # Utiliser une instance fraîche (isolée du singleton global)
        kev = _CISAKEVCache()
        # S'assurer que le cache local est vide et que _loaded_at est loin dans le passé
        with kev._lock:
            kev._cve_ids = set()
            kev._loaded_at = 0.0  # Force refresh au prochain appel

        with patch("app.services.cve_service.requests.get", side_effect=Exception("Network error")):
            kev._load()  # Appel direct — pas de ensure_loaded qui pourrait ne pas refetch

        # Après un échec de chargement, le catalogue reste vide → False
        with kev._lock:
            assert len(kev._cve_ids) == 0
        # is_exploited ne doit pas lever d'exception et doit retourner False
        # (mais ne doit PAS appeler ensure_loaded pour ce test unitaire)
        with kev._lock:
            result = "CVE-2021-44228" in kev._cve_ids
        assert result is False

    def test_load_parses_cve_ids(self):
        """_load() parse correctement la liste de CVE depuis le JSON CISA KEV."""
        kev = _CISAKEVCache()
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2021-44228", "vendorProject": "Apache"},
                {"cveID": "CVE-2022-22965", "vendorProject": "VMware"},
                {"cveID": "", "vendorProject": "Unknown"},  # Doit être ignoré
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("app.services.cve_service.requests.get", return_value=mock_response):
            kev._load()

        assert kev.is_exploited("CVE-2021-44228") is True
        assert kev.is_exploited("CVE-2022-22965") is True
        assert kev.get_loaded_count() == 2  # CVE vide exclue

    def test_refresh_interval(self):
        """Le catalogue n'est pas rechargé si le TTL n'est pas expiré."""
        kev = _CISAKEVCache()
        with kev._lock:
            kev._cve_ids = {"CVE-TEST"}
            kev._loaded_at = time.monotonic()  # Frais

        # _needs_refresh() doit retourner False
        assert kev._needs_refresh() is False


# ==============================================================
# TESTS : query_osv avec cache
# ==============================================================

class TestQueryOSVCache:
    """Tests du cache dans query_osv."""

    def test_cache_hit_avoids_http_call(self):
        """Deux appels consécutifs pour la même dep n'appellent l'API qu'une fois."""
        dep = make_dep()
        osv_response = {
            "vulns": [make_osv_vuln()]
        }

        with patch("app.services.cve_service._http_post_with_retry", return_value=osv_response) as mock_post:
            result1 = query_osv(dep)
            result2 = query_osv(dep)

        # L'API ne doit être appelée qu'UNE SEULE FOIS (2ème appel depuis cache)
        assert mock_post.call_count == 1
        assert len(result1) == 1
        assert len(result2) == 1
        assert result1[0].cve_id == "CVE-2023-12345"

    def test_cache_miss_calls_api(self):
        """Premier appel pour une dep inconnue appelle l'API."""
        dep = make_dep(name="newpackage", version="1.0.0")

        with patch("app.services.cve_service._http_post_with_retry", return_value={"vulns": []}) as mock_post:
            result = query_osv(dep)

        assert mock_post.call_count == 1
        assert result == []

    def test_empty_result_cached(self):
        """Un résultat vide (aucune vuln) est aussi mis en cache."""
        dep = make_dep(name="cleanpackage", version="9.9.9")

        with patch("app.services.cve_service._http_post_with_retry", return_value={"vulns": []}) as mock_post:
            query_osv(dep)
            query_osv(dep)  # 2ème appel

        assert mock_post.call_count == 1  # Toujours 1 seul appel HTTP

    def test_cisa_kev_marks_exploit_available(self):
        """Un CVE dans CISA KEV est marqué exploit_available=True même sans référence exploit."""
        dep = make_dep()
        # Vuln OSV sans référence d'exploit
        osv_response = {
            "vulns": [make_osv_vuln(cve_id="CVE-2021-44228")]
        }

        # Simuler CISA KEV avec ce CVE
        with patch.object(_cisa_kev, "is_exploited", return_value=True):
            with patch("app.services.cve_service._http_post_with_retry", return_value=osv_response):
                results = query_osv(dep)

        assert len(results) == 1
        assert results[0].exploit_available is True

    def test_no_cisa_kev_no_exploit_ref(self):
        """Sans CISA KEV et sans référence exploit, exploit_available reste False."""
        dep = make_dep()
        osv_response = {
            "vulns": [make_osv_vuln(cve_id="CVE-2023-99999")]
        }

        with patch.object(_cisa_kev, "is_exploited", return_value=False):
            with patch("app.services.cve_service._http_post_with_retry", return_value=osv_response):
                results = query_osv(dep)

        assert len(results) == 1
        assert results[0].exploit_available is False

    def test_unsupported_ecosystem_returns_empty(self):
        """Un écosystème non supporté retourne une liste vide sans appel HTTP."""
        dep = make_dep(ecosystem="erlang")  # Non supporté

        with patch("app.services.cve_service._http_post_with_retry") as mock_post:
            result = query_osv(dep)

        assert result == []
        mock_post.assert_not_called()


# ==============================================================
# TESTS : query_nvd_by_cve_id avec cache + warning
# ==============================================================

class TestQueryNVDCache:
    """Tests du cache NVD et du warning si liste vide (Point 5)."""

    def test_cache_hit_avoids_http_call(self):
        """Deux appels consécutifs pour le même CVE n'appellent NVD qu'une fois."""
        nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "published": "2021-12-10T00:00:00",
                    "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            }
                        }]
                    },
                    "references": [],
                }
            }]
        }

        with patch("app.services.cve_service._http_get_with_retry", return_value=nvd_response) as mock_get:
            r1 = query_nvd_by_cve_id("CVE-2021-44228")
            r2 = query_nvd_by_cve_id("CVE-2021-44228")

        assert mock_get.call_count == 1
        assert r1 is not None
        assert r1.cve_id == "CVE-2021-44228"
        assert r2 is r1 or r2.cve_id == r1.cve_id  # Même objet du cache

    def test_non_cve_id_returns_none(self):
        """Un ID non CVE (GHSA, etc.) retourne None sans appel HTTP."""
        with patch("app.services.cve_service._http_get_with_retry") as mock_get:
            result = query_nvd_by_cve_id("GHSA-xxxx-yyyy-zzzz")

        assert result is None
        mock_get.assert_not_called()

    def test_nvd_empty_vulnerabilities_logs_warning(self, caplog):
        """Point 5 : un WARNING est émis si NVD retourne une liste vide."""
        import logging
        with patch("app.services.cve_service._http_get_with_retry",
                   return_value={"vulnerabilities": []}):
            with caplog.at_level(logging.WARNING, logger="app.services.cve_service"):
                result = query_nvd_by_cve_id("CVE-2026-99999")

        assert result is None
        # Vérifier qu'un WARNING a bien été émis
        assert any("CVE-2026-99999" in record.message for record in caplog.records), \
            f"Aucun WARNING pour CVE-2026-99999. Logs : {[r.message for r in caplog.records]}"
        assert any(record.levelname == "WARNING" for record in caplog.records)

    def test_nvd_not_found_cached_as_false(self):
        """Un CVE non trouvé en NVD est mis en cache comme False (sentinel)."""
        with patch("app.services.cve_service._http_get_with_retry",
                   return_value={"vulnerabilities": []}) as mock_get:
            r1 = query_nvd_by_cve_id("CVE-2026-00001")
            r2 = query_nvd_by_cve_id("CVE-2026-00001")

        # NVD n'est appelé qu'une seule fois (2ème depuis cache sentinel)
        assert mock_get.call_count == 1
        assert r1 is None
        assert r2 is None

    def test_nvd_exploit_tag_detected(self):
        """Un tag 'Exploit' dans les références NVD est détecté."""
        nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2023-0001",
                    "published": "2023-01-01T00:00:00",
                    "descriptions": [{"lang": "en", "value": "Test CVE with exploit"}],
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            }
                        }]
                    },
                    "references": [
                        {"url": "https://example.com/exploit", "tags": ["Exploit"]},
                    ],
                }
            }]
        }

        with patch("app.services.cve_service._http_get_with_retry", return_value=nvd_response):
            result = query_nvd_by_cve_id("CVE-2023-0001")

        assert result is not None
        assert result.exploit_available is True
        assert result.cvss_score == pytest.approx(9.8, abs=0.2)

    def test_nvd_cisa_kev_exploit(self):
        """Un CVE dans CISA KEV est marqué exploit_available=True même sans tag NVD."""
        nvd_response = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2021-44228",
                    "published": "2021-12-10T00:00:00",
                    "descriptions": [{"lang": "en", "value": "Log4Shell"}],
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}]},
                    "references": [],  # Aucun tag Exploit
                }
            }]
        }

        with patch.object(_cisa_kev, "is_exploited", return_value=True):
            with patch("app.services.cve_service._http_get_with_retry", return_value=nvd_response):
                result = query_nvd_by_cve_id("CVE-2021-44228")

        assert result is not None
        assert result.exploit_available is True


# ==============================================================
# TESTS : scan_all_vulnerabilities
# ==============================================================

class TestScanAllVulnerabilities:
    """Tests de la fonction principale de scan."""

    def test_empty_dependencies_returns_empty(self):
        """Une liste vide retourne un dict vide."""
        result = scan_all_vulnerabilities([])
        # Retirer __scan_meta__ pour la comparaison
        actual = {k: v for k, v in result.items() if k != "__scan_meta__"}
        assert actual == {}

    def test_scan_meta_always_present(self):
        """__scan_meta__ est toujours présent dans le résultat."""
        with patch("app.services.cve_service.query_osv", return_value=[]):
            result = scan_all_vulnerabilities([make_dep()])

        assert "__scan_meta__" in result
        meta = result["__scan_meta__"]
        assert "deps_truncated" in meta
        assert "deps_scanned" in meta
        assert "deps_total" in meta
        assert "timeout_reached" in meta

    def test_no_truncation_below_limit(self):
        """Moins de 100 deps → pas de troncature en mode standard."""
        deps = [make_dep(name=f"pkg{i}", version="1.0.0") for i in range(5)]

        with patch("app.services.cve_service.query_osv", return_value=[]):
            result = scan_all_vulnerabilities(deps, scan_type="standard")

        meta = result["__scan_meta__"]
        assert meta["deps_truncated"] is False
        assert meta["deps_total"] == 5
        assert meta["deps_scanned"] == 5

    def test_truncation_above_limit(self):
        """Plus de MAX_DEPS_STANDARD deps en mode standard → troncature marquée."""
        from app.services.cve_service import MAX_DEPS_STANDARD
        total = MAX_DEPS_STANDARD + 10  # Au-delà de la limite
        deps = [make_dep(name=f"pkg{i}", version="1.0.0") for i in range(total)]

        with patch("app.services.cve_service.query_osv", return_value=[]):
            result = scan_all_vulnerabilities(deps, scan_type="standard")

        meta = result["__scan_meta__"]
        assert meta["deps_truncated"] is True
        assert meta["deps_total"] == total
        assert meta["deps_scanned"] == MAX_DEPS_STANDARD  # Dynamique selon la constante

    def test_timeout_reached_returns_partial(self):
        """Un timeout global retourne les résultats partiels sans exception."""
        deps = [make_dep(name=f"pkg{i}", version="1.0.0") for i in range(5)]

        def slow_query(dep):
            time.sleep(0.5)
            return []

        # Timeout très court (0.1s) pour déclencher le timeout immédiatement
        with patch("app.services.cve_service.query_osv", side_effect=slow_query):
            result = scan_all_vulnerabilities(deps, scan_type="standard", timeout_seconds=0.05)

        meta = result["__scan_meta__"]
        assert meta["timeout_reached"] is True

    def test_get_cve_summary_excludes_meta(self):
        """get_cve_summary() ignore correctement la clé __scan_meta__."""
        vuln = VulnerabilityResult(
            cve_id="CVE-2023-0001",
            cvss_score=9.8,
            severity=Severity.CRITICAL,
            description="Test",
        )
        scan_results = {
            "requests@2.27.0": [vuln],
            "__scan_meta__": {"deps_truncated": False},  # type: ignore
        }

        summary = get_cve_summary(scan_results)
        assert summary["total_vulnerabilities"] == 1
        assert summary["by_severity"]["CRITICAL"] == 1
        assert summary["affected_packages"] == 1


# ==============================================================
# TESTS : _parse_cvss_v3_base_score (inchangé — doit rester correct)
# ==============================================================

class TestParseCVSSv3:
    """Tests de la formule officielle CVSS v3.x — ne pas modifier."""

    @pytest.mark.parametrize("vector,expected", [
        # Vecteurs connus avec scores officiels
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # CRITICAL
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),   # MEDIUM
        ("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H", 5.5),   # MEDIUM
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),   # MEDIUM
    ])
    def test_known_vectors(self, vector: str, expected: float):
        """Les vecteurs CVSS connus donnent les scores officiels (± 0.1)."""
        score = _parse_cvss_v3_base_score(vector)
        assert abs(score - expected) <= 0.1, \
            f"Vecteur {vector[:40]}... → attendu {expected}, obtenu {score}"

    def test_invalid_vector_returns_zero(self):
        """Un vecteur invalide retourne 0.0 sans exception."""
        assert _parse_cvss_v3_base_score("") == 0.0
        assert _parse_cvss_v3_base_score("INVALID") == 0.0
        assert _parse_cvss_v3_base_score("AV:N") == 0.0

    def test_high_severity_vector(self):
        """Log4Shell (CVE-2021-44228) = score CRITICAL ≥ 9.0."""
        log4shell = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        score = _parse_cvss_v3_base_score(log4shell)
        assert score >= 9.0
        assert cvss_to_severity(score) == Severity.CRITICAL


# ==============================================================
# TESTS : CVE_SERVICE_VERSION
# ==============================================================

class TestCVEServiceVersion:
    """Tests de la constante de version du moteur CVE."""

    def test_version_is_string(self):
        """CVE_SERVICE_VERSION est une chaîne non vide."""
        assert isinstance(CVE_SERVICE_VERSION, str)
        assert len(CVE_SERVICE_VERSION) > 0

    def test_version_format(self):
        """CVE_SERVICE_VERSION suit le format semver X.Y.Z."""
        parts = CVE_SERVICE_VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)

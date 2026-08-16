"""
Tests de différenciation scan_type standard vs deep.

Valide que les deux modes font réellement des appels différents :
  - Standard : NVD partiel (top 20 + CVE sans score)
  - Deep     : NVD complet + EPSS FIRST.org + GHSA REST (sans token)
"""
import pytest
from unittest.mock import patch, MagicMock, call
from app.services.cve_service import (
    scan_all_vulnerabilities,
    SCAN_TIMEOUT_STANDARD, SCAN_TIMEOUT_DEEP,
    MAX_DEPS_STANDARD, MAX_DEPS_DEEP,
)
from app.services.dependency_scanner import DependencyInfo
from app.services.cve_providers.models import VulnerabilityResult, Severity


def make_dep(name: str, version: str = "1.0.0") -> DependencyInfo:
    return DependencyInfo(name=name, version=version, ecosystem="python", source_file="requirements.txt")


def make_vuln(cve_id: str, cvss: float = 0.0, severity: Severity = Severity.HIGH) -> VulnerabilityResult:
    return VulnerabilityResult(
        cve_id=cve_id,
        cvss_score=cvss,
        severity=severity,
        description=f"Test {cve_id}",
    )


class TestScanTypeLimits:
    """Valide les différences de limites entre standard et deep."""

    def test_deep_allows_more_deps_than_standard(self):
        """MAX_DEPS_DEEP > MAX_DEPS_STANDARD."""
        assert MAX_DEPS_DEEP > MAX_DEPS_STANDARD

    def test_deep_has_longer_timeout_than_standard(self):
        """SCAN_TIMEOUT_DEEP > SCAN_TIMEOUT_STANDARD."""
        assert SCAN_TIMEOUT_DEEP > SCAN_TIMEOUT_STANDARD

    def test_standard_truncates_at_60(self):
        """En mode standard, max MAX_DEPS_STANDARD deps analysées."""
        deps = [make_dep(f"lib{i}", "1.0") for i in range(MAX_DEPS_STANDARD + 20)]

        captured_deps = []
        def fake_batch(self_deps):
            captured_deps.extend(self_deps)
            return {}

        with patch("app.services.cve_service.OSVProvider") as MockOSV:
            MockOSV.return_value.query_batch.side_effect = fake_batch
            result = scan_all_vulnerabilities(deps, scan_type="standard")

        meta = result.get("__scan_meta__", {})
        assert meta.get("deps_truncated") is True
        assert meta.get("deps_scanned") == MAX_DEPS_STANDARD

    def test_deep_allows_more_deps(self):
        """En mode deep, la limite est MAX_DEPS_DEEP (plus grande)."""
        deps = [make_dep(f"lib{i}", "1.0") for i in range(MAX_DEPS_STANDARD + 5)]

        def fake_batch(self_deps):
            return {}

        with patch("app.services.cve_service.OSVProvider") as MockOSV:
            MockOSV.return_value.query_batch.side_effect = fake_batch
            result = scan_all_vulnerabilities(deps, scan_type="deep")

        meta = result.get("__scan_meta__", {})
        # Si on a envoyé MAX_DEPS_STANDARD+5 et que deep tolère MAX_DEPS_DEEP,
        # la troncature ne doit PAS s'être déclenchée
        assert meta.get("deps_truncated") is False
        assert meta.get("deps_scanned") == MAX_DEPS_STANDARD + 5


class TestNVDDifferentiation:
    """Valide que le mode deep enrichit plus de CVE via NVD."""

    def test_standard_nvd_limits_to_top20(self):
        """
        En mode standard, NVD n'enrichit que les CVE sans score + top 20.
        Avec 30 CVE connues (score > 0), standard en enrichit au max 20.
        """
        # Simuler 30 CVE avec scores différents
        cve_vulns = {}
        for i in range(30):
            cve_id = f"CVE-2023-{i:04d}"
            vuln = make_vuln(cve_id, cvss=float(i) / 3.0 + 1.0, severity=Severity.MEDIUM)
            cve_vulns[f"pkg{i}@1.0"] = [vuln]

        osv_results = {k: v for k, v in cve_vulns.items()}

        enrich_calls = []

        def fake_nvd_enrich(cve_id):
            enrich_calls.append(cve_id)
            return None  # Pas d'enrichissement, on veut juste compter les appels

        with patch("app.services.cve_service.OSVProvider") as MockOSV, \
             patch("app.services.cve_service.NVDProvider") as MockNVD, \
             patch("app.services.cve_service.GHSAProvider"), \
             patch("app.services.cve_service.fetch_ghsa_advisory_by_cve", return_value=None), \
             patch("app.services.cve_service.fetch_epss_scores", return_value={}):

            MockOSV.return_value.query_batch.return_value = osv_results
            MockNVD.return_value.enrich.side_effect = fake_nvd_enrich

            scan_all_vulnerabilities(
                [make_dep(f"pkg{i}", "1.0") for i in range(30)],
                scan_type="standard"
            )

        # En mode standard, max 20 CVE enrichies via NVD (top 20 CVSS)
        assert len(enrich_calls) <= 20, (
            f"Standard mode: {len(enrich_calls)} appels NVD > 20 attendus"
        )

    def test_deep_nvd_enriches_all_cves(self):
        """En mode deep, NVD enrichit TOUTES les CVE (pas de limite à 20)."""
        # Simuler 25 CVE avec scores différents
        cve_vulns = {}
        for i in range(25):
            cve_id = f"CVE-2024-{i:04d}"
            vuln = make_vuln(cve_id, cvss=5.0, severity=Severity.MEDIUM)
            cve_vulns[f"pkg{i}@1.0"] = [vuln]

        osv_results = {k: v for k, v in cve_vulns.items()}
        enrich_calls = []

        def fake_nvd_enrich(cve_id):
            enrich_calls.append(cve_id)
            return None

        with patch("app.services.cve_service.OSVProvider") as MockOSV, \
             patch("app.services.cve_service.NVDProvider") as MockNVD, \
             patch("app.services.cve_service.GHSAProvider"), \
             patch("app.services.cve_service.fetch_ghsa_advisory_by_cve", return_value=None), \
             patch("app.services.cve_service.fetch_epss_scores", return_value={}):

            MockOSV.return_value.query_batch.return_value = osv_results
            MockNVD.return_value.enrich.side_effect = fake_nvd_enrich

            scan_all_vulnerabilities(
                [make_dep(f"pkg{i}", "1.0") for i in range(25)],
                scan_type="deep"
            )

        # En mode deep, TOUTES les 25 CVE doivent être enrichies
        assert len(enrich_calls) == 25, (
            f"Deep mode: {len(enrich_calls)} appels NVD au lieu de 25"
        )

    def test_deep_enriches_more_cves_than_standard(self):
        """Deep enrichit toujours plus de CVE que standard (avec >20 CVE)."""
        cve_vulns = {}
        for i in range(25):
            vuln = make_vuln(f"CVE-2024-{i:04d}", cvss=5.0)
            cve_vulns[f"pkg{i}@1.0"] = [vuln]

        osv_results = dict(cve_vulns)
        standard_calls = []
        deep_calls = []

        def make_fake_enrich(calls_list):
            def fake(cve_id):
                calls_list.append(cve_id)
                return None
            return fake

        def run_scan(scan_type, calls_list):
            with patch("app.services.cve_service.OSVProvider") as MockOSV, \
                 patch("app.services.cve_service.NVDProvider") as MockNVD, \
                 patch("app.services.cve_service.GHSAProvider"), \
                 patch("app.services.cve_service.fetch_ghsa_advisory_by_cve", return_value=None), \
                 patch("app.services.cve_service.fetch_epss_scores", return_value={}):
                MockOSV.return_value.query_batch.return_value = dict(osv_results)
                MockNVD.return_value.enrich.side_effect = make_fake_enrich(calls_list)
                scan_all_vulnerabilities(
                    [make_dep(f"pkg{i}", "1.0") for i in range(25)],
                    scan_type=scan_type
                )

        run_scan("standard", standard_calls)
        run_scan("deep", deep_calls)

        assert len(deep_calls) > len(standard_calls), (
            f"Deep ({len(deep_calls)}) doit enrichir plus que standard ({len(standard_calls)})"
        )


class TestDeepModeEPSS:
    """Valide que l'étape EPSS est activée uniquement en mode deep."""

    def test_epss_called_in_deep_mode(self):
        """EPSS fetch_epss_scores est appelé en mode deep."""
        cve_vulns = {"pkg@1.0": [make_vuln("CVE-2024-0001", cvss=9.0, severity=Severity.CRITICAL)]}

        with patch("app.services.cve_service.OSVProvider") as MockOSV, \
             patch("app.services.cve_service.NVDProvider") as MockNVD, \
             patch("app.services.cve_service.GHSAProvider"), \
             patch("app.services.cve_service.fetch_ghsa_advisory_by_cve", return_value=None), \
             patch("app.services.cve_service.fetch_epss_scores") as mock_epss:

            MockOSV.return_value.query_batch.return_value = cve_vulns
            MockNVD.return_value.enrich.return_value = None
            mock_epss.return_value = {}

            scan_all_vulnerabilities([make_dep("pkg", "1.0")], scan_type="deep")

        mock_epss.assert_called_once()

    def test_epss_not_called_in_standard_mode(self):
        """EPSS fetch_epss_scores N'est PAS appelé en mode standard."""
        cve_vulns = {"pkg@1.0": [make_vuln("CVE-2024-0001", cvss=9.0, severity=Severity.CRITICAL)]}

        with patch("app.services.cve_service.OSVProvider") as MockOSV, \
             patch("app.services.cve_service.NVDProvider") as MockNVD, \
             patch("app.services.cve_service.GHSAProvider"), \
             patch("app.services.cve_service.fetch_epss_scores") as mock_epss:

            MockOSV.return_value.query_batch.return_value = cve_vulns
            MockNVD.return_value.enrich.return_value = None

            scan_all_vulnerabilities([make_dep("pkg", "1.0")], scan_type="standard")

        mock_epss.assert_not_called()


class TestDeepModeGHSARest:
    """Valide que GHSA REST est appelé uniquement en mode deep."""

    def test_ghsa_rest_called_for_incomplete_cves_in_deep(self):
        """GHSA REST est appelé en mode deep pour les CVE sans fixed_version."""
        # CVE sans fixed_version (eligible GHSA REST)
        vuln = make_vuln("CVE-2024-0001", cvss=7.5, severity=Severity.HIGH)
        vuln.fixed_version = None
        cve_vulns = {"pkg@1.0": [vuln]}

        with patch("app.services.cve_service.OSVProvider") as MockOSV, \
             patch("app.services.cve_service.NVDProvider") as MockNVD, \
             patch("app.services.cve_service.GHSAProvider"), \
             patch("app.services.cve_service.fetch_epss_scores", return_value={}), \
             patch("app.services.cve_service.fetch_ghsa_advisory_by_cve") as mock_ghsa_rest:

            MockOSV.return_value.query_batch.return_value = cve_vulns
            MockNVD.return_value.enrich.return_value = None
            mock_ghsa_rest.return_value = None  # Pas de résultat, mais l appel doit avoir lieu

            scan_all_vulnerabilities([make_dep("pkg", "1.0")], scan_type="deep")

        mock_ghsa_rest.assert_called_once_with("CVE-2024-0001", timeout=8.0)

    def test_ghsa_rest_not_called_in_standard_mode(self):
        """GHSA REST n'est PAS appelé en mode standard."""
        vuln = make_vuln("CVE-2024-0001", cvss=7.5, severity=Severity.HIGH)
        vuln.fixed_version = None
        cve_vulns = {"pkg@1.0": [vuln]}

        with patch("app.services.cve_service.OSVProvider") as MockOSV, \
             patch("app.services.cve_service.NVDProvider") as MockNVD, \
             patch("app.services.cve_service.GHSAProvider"), \
             patch("app.services.cve_service.fetch_ghsa_advisory_by_cve") as mock_ghsa_rest:

            MockOSV.return_value.query_batch.return_value = cve_vulns
            MockNVD.return_value.enrich.return_value = None

            scan_all_vulnerabilities([make_dep("pkg", "1.0")], scan_type="standard")

        mock_ghsa_rest.assert_not_called()

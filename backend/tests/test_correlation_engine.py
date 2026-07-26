"""
Tests unitaires — Correlation Engine.

Valide la fusion, déduplication et enrichissement des vulnérabilités multi-sources.
"""
import pytest

from app.services.cve_providers.models import VulnerabilityResult, Severity
from app.services.cve_providers.correlation_engine import correlate_vulnerabilities


def _vuln(cve_id: str, score: float, source: str, **kwargs) -> VulnerabilityResult:
    return VulnerabilityResult(
        cve_id=cve_id,
        cvss_score=score,
        severity=Severity.HIGH if score >= 7.0 else Severity.MEDIUM,
        description=f"Test {cve_id}",
        source=source,
        cvss_source=source,
        **kwargs,
    )


class TestCorrelateVulnerabilities:

    def test_empty_input(self):
        assert correlate_vulnerabilities([]) == []

    def test_single_source_passthrough(self):
        """Une seule source doit retourner les résultats tels quels."""
        vulns = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        result = correlate_vulnerabilities([vulns])
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2024-0001"

    def test_deduplication_same_cve(self):
        """Même CVE de 2 sources → 1 seul résultat fusionné."""
        osv_list = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        ghsa_list = [_vuln("CVE-2024-0001", 8.0, "GHSA")]
        result = correlate_vulnerabilities([osv_list, ghsa_list])
        assert len(result) == 1

    def test_higher_priority_source_wins_cvss(self):
        """GHSA (priorité 2) doit remporter le score sur OSV (priorité 1)."""
        osv_list = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        ghsa_list = [_vuln("CVE-2024-0001", 8.0, "GHSA")]
        result = correlate_vulnerabilities([osv_list, ghsa_list])
        assert result[0].cvss_score == 8.0
        assert result[0].cvss_source == "GHSA"

    def test_nvd_highest_priority(self):
        """NVD (priorité 3) doit être préféré à GHSA et OSV."""
        osv = [_vuln("CVE-2024-0001", 9.0, "OSV")]
        ghsa = [_vuln("CVE-2024-0001", 8.5, "GHSA")]
        nvd = [_vuln("CVE-2024-0001", 7.0, "NVD")]
        result = correlate_vulnerabilities([osv, ghsa, nvd])
        # NVD a priorité 3 même si score inférieur
        assert result[0].cvss_source == "NVD"
        assert result[0].cvss_score == 7.0

    def test_sources_concatenated(self):
        """Les sources doivent être concaténées (ex: OSV+GHSA)."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        ghsa = [_vuln("CVE-2024-0001", 8.0, "GHSA")]
        result = correlate_vulnerabilities([osv, ghsa])
        assert "OSV" in result[0].source
        assert "GHSA" in result[0].source

    def test_exploit_or_logic(self):
        """exploit_available = OR logique de toutes les sources."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV", exploit_available=False)]
        ghsa = [_vuln("CVE-2024-0001", 7.5, "GHSA", exploit_available=True)]
        result = correlate_vulnerabilities([osv, ghsa])
        assert result[0].exploit_available is True

    def test_fixed_version_first_available(self):
        """fixed_version prend la première valeur disponible."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV", fixed_version=None)]
        ghsa = [_vuln("CVE-2024-0001", 7.5, "GHSA", fixed_version="2.3.1")]
        result = correlate_vulnerabilities([osv, ghsa])
        assert result[0].fixed_version == "2.3.1"

    def test_epss_preserved(self):
        """EPSS score est conservé lors de la fusion."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        nvd = [_vuln("CVE-2024-0001", 7.5, "NVD", epss_score=0.85)]
        result = correlate_vulnerabilities([osv, nvd])
        assert result[0].epss_score == 0.85

    def test_cwe_preserved(self):
        """CWE est conservé lors de la fusion."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        nvd = [_vuln("CVE-2024-0001", 7.5, "NVD", cwe="CWE-79")]
        result = correlate_vulnerabilities([osv, nvd])
        assert result[0].cwe == "CWE-79"

    def test_different_cves_not_merged(self):
        """2 CVE différentes ne doivent PAS être fusionnées."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV")]
        ghsa = [_vuln("CVE-2024-0002", 8.0, "GHSA")]
        result = correlate_vulnerabilities([osv, ghsa])
        assert len(result) == 2

    def test_published_date_first_available(self):
        """published_date prend la première valeur disponible."""
        osv = [_vuln("CVE-2024-0001", 7.5, "OSV", published_date=None)]
        ghsa = [_vuln("CVE-2024-0001", 7.5, "GHSA", published_date="2024-01-15")]
        result = correlate_vulnerabilities([osv, ghsa])
        assert result[0].published_date == "2024-01-15"

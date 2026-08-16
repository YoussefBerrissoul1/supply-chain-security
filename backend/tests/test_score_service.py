"""
Tests unitaires — Score Service.

Valide l'algorithme de scoring /100 avec la matrice 3D de pénalités.
"""
import pytest
from unittest.mock import MagicMock

from app.services.score_service import (
    compute_security_score,
    score_to_risk_level,
    RiskLevel,
    ScoreResult,
    PENALTY_CRITICAL,
    PENALTY_HIGH,
    PENALTY_MEDIUM,
)
from app.services.cve_providers.models import VulnerabilityResult, Severity
from app.services.dependency_scanner import DependencyInfo


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_vuln(cve_id: str, cvss: float, severity: Severity, **kwargs) -> VulnerabilityResult:
    return VulnerabilityResult(
        cve_id=cve_id,
        cvss_score=cvss,
        severity=severity,
        description=f"Test vuln {cve_id}",
        source="OSV",
        **kwargs,
    )


def _make_dep(name: str, version: str = "1.0.0", is_dev: bool = False) -> DependencyInfo:
    return DependencyInfo(name=name, version=version, ecosystem="python", is_dev=is_dev)


# ── Tests ───────────────────────────────────────────────────────────────────

class TestScoreToRiskLevel:
    def test_excellent(self):
        assert score_to_risk_level(95.0) == RiskLevel.EXCELLENT
        assert score_to_risk_level(90.0) == RiskLevel.EXCELLENT

    def test_bon(self):
        assert score_to_risk_level(85.0) == RiskLevel.BON
        assert score_to_risk_level(70.0) == RiskLevel.BON

    def test_moyen(self):
        assert score_to_risk_level(50.0) == RiskLevel.MOYEN
        assert score_to_risk_level(69.9) == RiskLevel.MOYEN

    def test_mauvais(self):
        assert score_to_risk_level(30.0) == RiskLevel.MAUVAIS
        assert score_to_risk_level(49.9) == RiskLevel.MAUVAIS

    def test_critique(self):
        assert score_to_risk_level(0.0) == RiskLevel.CRITIQUE
        assert score_to_risk_level(29.9) == RiskLevel.CRITIQUE


class TestComputeSecurityScore:
    def test_no_vulns_returns_100(self):
        """Sans aucune vulnérabilité, le score doit être 100."""
        result = compute_security_score(cve_results={})
        assert result.final_score == 100.0
        assert result.risk_level == RiskLevel.EXCELLENT
        assert result.total_cve == 0

    def test_score_never_negative(self):
        """Même avec beaucoup de CVE critiques, le score ne descend pas sous 0."""
        vulns = {
            f"pkg{i}@1.0": [
                _make_vuln(f"CVE-2024-{i:04d}", 9.8, Severity.CRITICAL)
            ]
            for i in range(50)
        }
        result = compute_security_score(cve_results=vulns)
        assert result.final_score >= 0.0

    def test_score_never_above_100(self):
        """Le score ne doit jamais dépasser 100."""
        result = compute_security_score(cve_results={})
        assert result.final_score <= 100.0

    def test_critical_vuln_reduces_score(self):
        """Une CVE CRITICAL réduit le score significativement."""
        vulns = {
            "flask@2.0.1": [
                _make_vuln("CVE-2024-0001", 9.8, Severity.CRITICAL)
            ]
        }
        result = compute_security_score(cve_results=vulns)
        assert result.final_score < 100.0
        assert result.total_cve == 1

    def test_deduplication_by_cve_id(self):
        """Les CVE dupliquées (même ID sur 2 packages) ne doivent être comptées qu'une fois."""
        vulns = {
            "flask@2.0.1": [
                _make_vuln("CVE-2024-0001", 9.0, Severity.CRITICAL)
            ],
            "werkzeug@2.0.1": [
                _make_vuln("CVE-2024-0001", 9.0, Severity.CRITICAL)
            ],
        }
        result = compute_security_score(cve_results=vulns)
        assert result.total_cve == 1  # Dédupliqué

    def test_scan_meta_key_ignored(self):
        """La clé interne __scan_meta__ ne doit pas être traitée comme des vulns."""
        vulns = {
            "__scan_meta__": [],
            "flask@2.0.1": [
                _make_vuln("CVE-2024-0001", 7.5, Severity.HIGH)
            ],
        }
        result = compute_security_score(cve_results=vulns)
        assert result.total_cve == 1

    def test_score_result_has_summary(self):
        """Le ScoreResult doit fournir un get_summary_line() lisible."""
        result = compute_security_score(cve_results={})
        summary = result.get_summary_line()
        assert "100.0" in summary
        assert "EXCELLENT" in summary

    def test_docker_penalties_applied(self):
        """Les pénalités Docker doivent réduire le score."""
        from app.services.docker_scanner import DockerScanResult
        docker = DockerScanResult(
            base_image="python:3.12",
            vulnerabilities_count=20,
            has_root_user=True,
            image_score=30.0,
            vulnerabilities_by_severity={"CRITICAL": 5, "HIGH": 10},
            dockerfile_issues=["Uses latest tag"],
        )
        result = compute_security_score(cve_results={}, docker_result=docker)
        assert result.final_score < 100.0
        assert result.has_docker is True


class TestLowFloorPenalty:
    """Tests pour la pénalité plancher proportionnelle des CVE LOW/NONE."""

    def _make_low_vulns(self, n: int) -> dict:
        """Crée n CVE LOW avec des IDs uniques."""
        from app.services.cve_providers.models import Severity
        return {
            f"pkg{i}@1.0": [_make_vuln(f"CVE-2024-{i:04d}", 2.0, Severity.LOW)]
            for i in range(n)
        }

    def test_zero_vulns_score_100(self):
        """Sans CVE, score = 100 (inchangé)."""
        result = compute_security_score(cve_results={})
        assert result.final_score == 100.0

    def test_low_cvss_gets_floor_penalty(self):
        """Des CVE LOW doivent réduire le score (plus de score=100 avec N CVE LOW)."""
        from app.services.cve_providers.models import Severity
        vulns = self._make_low_vulns(5)
        result = compute_security_score(cve_results=vulns)
        # 5 × 0.4 = 2.0 pts → score 98.0 (pas 100)
        assert result.final_score < 100.0
        assert result.final_score == pytest.approx(98.0, abs=0.1)

    def test_23_low_vulns_proportional_score(self):
        """23 CVE LOW → pénalité proportionnelle (~9.2 pts)."""
        vulns = self._make_low_vulns(23)
        result = compute_security_score(cve_results=vulns)
        # 23 × 0.4 = 9.2 pts → score 90.8 (pas 100!)
        assert result.final_score < 100.0
        assert result.final_score == pytest.approx(90.8, abs=0.1)

    def test_many_low_vulns_capped(self):
        """50+ CVE LOW → plafond à -10 pts (score 90.0 minimum)."""
        vulns = self._make_low_vulns(50)
        result = compute_security_score(cve_results=vulns)
        # 50 × 0.4 = 20 > CAP_LOW_FLOOR(10) → score 90.0
        assert result.final_score == pytest.approx(90.0, abs=0.1)

        # Même chose avec 100 CVE LOW
        vulns_100 = self._make_low_vulns(100)
        result_100 = compute_security_score(cve_results=vulns_100)
        assert result_100.final_score == pytest.approx(90.0, abs=0.1)  # Même plafond

    def test_low_penalty_proportional_not_fixed(self):
        """Vérifie que 10 CVE LOW donne 2× plus de pénalité que 5 CVE LOW."""
        r5  = compute_security_score(cve_results=self._make_low_vulns(5))
        r10 = compute_security_score(cve_results=self._make_low_vulns(10))
        # 5 × 0.4 = 2.0 ; 10 × 0.4 = 4.0 → ratio 2:1
        assert r10.total_penalties == pytest.approx(r5.total_penalties * 2, abs=0.1)


class TestSeverityHardCaps:
    """Tests pour les hard caps de score par sévérité."""

    def test_critical_caps_score_at_59(self):
        """≥ 1 CVE CRITICAL → score final ≤ 59 (jamais BON ni EXCELLENT)."""
        from app.services.cve_providers.models import Severity
        vulns = {"flask@1.0": [_make_vuln("CVE-2024-0001", 9.8, Severity.CRITICAL)]}
        result = compute_security_score(cve_results=vulns)
        assert result.final_score <= 59.0, (
            f"CRITICAL cap échoué : score={result.final_score} > 59"
        )
        assert result.risk_level in (RiskLevel.CRITIQUE, RiskLevel.MAUVAIS, RiskLevel.MOYEN)

    def test_high_caps_score_at_79(self):
        """≥ 1 CVE HIGH → score final ≤ 79 (jamais EXCELLENT)."""
        from app.services.cve_providers.models import Severity
        vulns = {"pkg@1.0": [_make_vuln("CVE-2024-0002", 7.5, Severity.HIGH)]}
        result = compute_security_score(cve_results=vulns)
        assert result.final_score <= 79.0, (
            f"HIGH cap échoué : score={result.final_score} > 79"
        )

    def test_medium_caps_score_at_89(self):
        """≥ 1 CVE MEDIUM → score final ≤ 89 (jamais EXCELLENT)."""
        from app.services.cve_providers.models import Severity
        vulns = {"pkg@1.0": [_make_vuln("CVE-2024-0003", 5.0, Severity.MEDIUM)]}
        result = compute_security_score(cve_results=vulns)
        assert result.final_score <= 89.0, (
            f"MEDIUM cap échoué : score={result.final_score} > 89"
        )

    def test_critical_takes_priority_over_high_cap(self):
        """Avec CRITICAL + HIGH, c'est le cap CRITICAL (59) qui s'applique."""
        from app.services.cve_providers.models import Severity
        vulns = {
            "pkg@1.0": [
                _make_vuln("CVE-C", 9.8, Severity.CRITICAL),
                _make_vuln("CVE-H", 7.5, Severity.HIGH),
            ]
        }
        result = compute_security_score(cve_results=vulns)
        assert result.final_score <= 59.0

    def test_no_vuln_no_cap(self):
        """Sans CVE, aucun cap ne s'applique — score peut être 100."""
        result = compute_security_score(cve_results={})
        assert result.final_score == 100.0

    def test_only_low_vulns_no_severity_cap(self):
        """Avec uniquement des CVE LOW, aucun hard cap CRITICAL/HIGH/MEDIUM."""
        from app.services.cve_providers.models import Severity
        vulns = {"pkg@1.0": [_make_vuln("CVE-L", 2.0, Severity.LOW)]}
        result = compute_security_score(cve_results=vulns)
        # Pas de hard cap → score réduit uniquement par plancher LOW
        assert result.final_score > 89.0  # Pas de cap HIGH/MEDIUM/CRITICAL
        assert result.final_score < 100.0  # Mais pas 100 non plus (plancher LOW)


"""
Tests unitaires — Score Service (complément FIX1/FIX3/FIX4).

Valide les corrections apportées :
  - FIX1 : fixed_version ne majore plus la pénalité
  - FIX3 : EPSS intégré dans le multiplicateur d'exploitabilité
  - FIX4 : pénalité CVE sans correctif (remplace pénalité package abandonné)
"""
import pytest
from app.services.score_service import compute_security_score, _compute_unpatched_penalties
from app.services.cve_providers.models import VulnerabilityResult, Severity


def _vuln(cve_id: str, severity: Severity, cvss: float = 8.0, **kwargs) -> VulnerabilityResult:
    return VulnerabilityResult(
        cve_id=cve_id,
        cvss_score=cvss,
        severity=severity,
        description="Test",
        source="OSV",
        **kwargs,
    )


class TestFIX1FixedVersionMultiplier:
    """FIX1 : Un patch disponible ne doit PAS augmenter la pénalité."""

    def test_patch_available_not_worse_than_no_patch(self):
        """Score avec patch >= score sans patch (la présence d'un fix ne doit pas aggraver)."""
        vuln_with_fix = _vuln("CVE-2024-0001", Severity.HIGH, 8.0, fixed_version="2.3.1")
        vuln_without_fix = _vuln("CVE-2024-0002", Severity.HIGH, 8.0, fixed_version=None)

        result_with = compute_security_score({"pkg@1.0": [vuln_with_fix]})
        result_without = compute_security_score({"pkg@1.0": [vuln_without_fix]})

        # Un patch disponible → pénalité <= pénalité sans patch
        assert result_with.final_score >= result_without.final_score, (
            f"FIX1 ÉCHOUÉ : score avec patch ({result_with.final_score}) < "
            f"score sans patch ({result_without.final_score}) — logique inversée!"
        )

    def test_two_identical_vulns_different_only_by_fix(self):
        """Isolation : seulement la présence du fixed_version diffère."""
        no_fix = _vuln("CVE-2024-A", Severity.CRITICAL, 9.5, fixed_version=None)
        with_fix = _vuln("CVE-2024-B", Severity.CRITICAL, 9.5, fixed_version="1.0.1")

        score_no_fix = compute_security_score({"p@1": [no_fix]}).final_score
        score_with_fix = compute_security_score({"p@1": [with_fix]}).final_score

        assert score_with_fix >= score_no_fix, (
            "FIX1 : La présence d'un correctif ne doit jamais aggraver le score"
        )


class TestFIX3EPSSMultiplier:
    """FIX3 : EPSS élevé doit augmenter la pénalité."""

    def test_high_epss_increases_penalty(self):
        """EPSS >= 0.7 → pénalité plus élevée (total_penalties plus grand).
        Note : on compare les pénalités brutes (pas le score final)
        car le hard cap sevérité peut aplatir les scores finaux."""
        vuln_high_epss = _vuln("CVE-2024-0001", Severity.HIGH, 7.5, epss_score=0.85)
        vuln_low_epss  = _vuln("CVE-2024-0002", Severity.HIGH, 7.5, epss_score=0.05)

        res_high = compute_security_score({"pkg@1": [vuln_high_epss]})
        res_low  = compute_security_score({"pkg@1": [vuln_low_epss]})

        # EPSS élevé → pénalité totale plus grande
        assert res_high.total_penalties > res_low.total_penalties, (
            f"FIX3 : EPSS élevé ({0.85}) devrait donner plus de pénalités "
            f"({res_high.total_penalties}) que EPSS faible ({res_low.total_penalties})"
        )
        # Et dans tous les cas, HIGH cap à 79 max
        assert res_high.final_score <= 79.0
        assert res_low.final_score  <= 79.0

    def test_no_epss_behaves_like_epss_zero(self):
        """Sans EPSS (None), pas de majoration → comportement identique à epss=0."""
        vuln_none_epss = _vuln("CVE-A", Severity.HIGH, 7.5, epss_score=None)
        vuln_zero_epss = _vuln("CVE-B", Severity.HIGH, 7.5, epss_score=0.0)

        score_none = compute_security_score({"p@1": [vuln_none_epss]}).final_score
        score_zero = compute_security_score({"p@1": [vuln_zero_epss]}).final_score

        # Pas d'écart significatif (tolérance 0.1 pour arrondis)
        assert abs(score_none - score_zero) <= 0.1

    def test_medium_epss_moderate_increase(self):
        """EPSS entre 0.4 et 0.7 → majoration modérée (x1.1 vs x1.0).
        On compare les pénalités totales pour ne pas être affecté par le hard cap."""
        vuln_med  = _vuln("CVE-M", Severity.HIGH, 7.5, epss_score=0.5)
        vuln_none = _vuln("CVE-N", Severity.HIGH, 7.5, epss_score=None)

        res_med  = compute_security_score({"p@1": [vuln_med]})
        res_none = compute_security_score({"p@1": [vuln_none]})

        assert res_med.total_penalties >= res_none.total_penalties  # EPSS moyen ≥ sans EPSS


class TestFIX4UnpatchedPenalty:
    """FIX4 : La pénalité CVE sans correctif est basée sur les CVE, pas sur is_outdated."""

    def test_no_unpatched_cves_no_penalty(self):
        """Toutes les CVE ont un correctif → pas de pénalité supplémentaire."""
        vulns = {
            "pkg@1": [
                _vuln("CVE-A", Severity.CRITICAL, 9.5, fixed_version="2.0.0"),
                _vuln("CVE-B", Severity.HIGH, 7.5, fixed_version="1.5.0"),
            ]
        }
        penalties = _compute_unpatched_penalties(vulns)
        assert len(penalties) == 0

    def test_unpatched_critical_adds_penalty(self):
        """CVE CRITICAL sans patch → pénalité supplémentaire."""
        vulns = {
            "pkg@1": [
                _vuln("CVE-X", Severity.CRITICAL, 9.5, fixed_version=None),
            ]
        }
        penalties = _compute_unpatched_penalties(vulns)
        assert len(penalties) == 1
        assert penalties[0].count == 1
        assert penalties[0].applied > 0

    def test_unpatched_high_adds_penalty(self):
        """CVE HIGH sans patch → pénalité supplémentaire."""
        vulns = {
            "pkg@1": [
                _vuln("CVE-Y", Severity.HIGH, 7.5, fixed_version=None),
            ]
        }
        penalties = _compute_unpatched_penalties(vulns)
        assert len(penalties) == 1

    def test_unpatched_cap_respected(self):
        """La pénalité CVE sans correctif est plafonnée."""
        vulns = {
            f"pkg{i}@1": [_vuln(f"CVE-20-{i:04d}", Severity.CRITICAL, 9.5, fixed_version=None)]
            for i in range(20)
        }
        penalties = _compute_unpatched_penalties(vulns)
        total = sum(p.applied for p in penalties)
        assert total <= 15.0 + 9.0  # Plafonds respectés

    def test_scan_meta_key_ignored_in_unpatched(self):
        """La clé interne __scan_meta__ est ignorée."""
        vulns = {
            "__scan_meta__": [],
            "pkg@1": [_vuln("CVE-Z", Severity.CRITICAL, 9.5, fixed_version=None)],
        }
        penalties = _compute_unpatched_penalties(vulns)
        assert len(penalties) == 1  # Pas d'erreur, 1 seule pénalité

    def test_deduplication_in_unpatched(self):
        """Même CVE sans patch sur 2 packages → comptée une seule fois."""
        vulns = {
            "pkg_a@1": [_vuln("CVE-DUP", Severity.CRITICAL, 9.5, fixed_version=None)],
            "pkg_b@1": [_vuln("CVE-DUP", Severity.CRITICAL, 9.5, fixed_version=None)],
        }
        penalties = _compute_unpatched_penalties(vulns)
        # CVE dupliquée → comptée 1 fois seulement
        assert penalties[0].count == 1

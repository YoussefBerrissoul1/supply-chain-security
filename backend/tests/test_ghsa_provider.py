"""
Tests unitaires — GHSA Provider (version filtering).

Valide le filtrage par version via packaging.specifiers.SpecifierSet.
"""
import pytest
from unittest.mock import patch, MagicMock

from app.services.cve_providers.ghsa_provider import _version_is_affected, GHSAProvider
from app.services.dependency_scanner import DependencyInfo


class TestVersionIsAffected:
    """Teste la fonction de filtrage par version."""

    def test_exact_match_in_range(self):
        """Version dans la plage vulnérable → True."""
        assert _version_is_affected("2.0.1", ">= 2.0.0, < 2.3.0") is True

    def test_version_below_range(self):
        """Version avant la plage → False."""
        assert _version_is_affected("1.9.0", ">= 2.0.0, < 2.3.0") is False

    def test_version_above_range(self):
        """Version après la plage → False."""
        assert _version_is_affected("3.0.0", ">= 2.0.0, < 2.3.0") is False

    def test_version_at_upper_bound(self):
        """Version exactement à la borne sup (exclusive) → False."""
        assert _version_is_affected("2.3.0", ">= 2.0.0, < 2.3.0") is False

    def test_version_at_lower_bound(self):
        """Version exactement à la borne inf (inclusive) → True."""
        assert _version_is_affected("2.0.0", ">= 2.0.0, < 2.3.0") is True

    def test_unknown_version_fail_open(self):
        """Version 'unknown' → True (fail-open pour éviter faux négatifs)."""
        assert _version_is_affected("unknown", ">= 2.0.0, < 2.3.0") is True

    def test_empty_version_fail_open(self):
        """Version vide → True (fail-open)."""
        assert _version_is_affected("", ">= 2.0.0, < 2.3.0") is True

    def test_no_range_fail_open(self):
        """Pas de plage vulnérable → True (fail-open)."""
        assert _version_is_affected("2.0.0", None) is True

    def test_empty_range_fail_open(self):
        """Plage vide → True (fail-open)."""
        assert _version_is_affected("2.0.0", "") is True

    def test_unparseable_range_fail_open(self):
        """Plage non parseable → True (fail-open)."""
        assert _version_is_affected("2.0.0", "All versions") is True

    def test_simple_less_than(self):
        """Plage simple < X."""
        assert _version_is_affected("1.5.0", "< 2.0.0") is True
        assert _version_is_affected("2.0.0", "< 2.0.0") is False
        assert _version_is_affected("3.0.0", "< 2.0.0") is False

    def test_latest_version_fail_open(self):
        """Version 'latest' → True (fail-open)."""
        assert _version_is_affected("latest", ">= 1.0, < 2.0") is True


class TestGHSAProviderNoToken:
    """Teste le provider sans GITHUB_TOKEN configuré."""

    @patch("app.services.cve_providers.ghsa_provider.settings")
    def test_no_token_returns_empty(self, mock_settings):
        mock_settings.GITHUB_TOKEN = None
        provider = GHSAProvider()
        dep = DependencyInfo(name="flask", version="2.0.1", ecosystem="python")
        result = provider.query(dep)
        assert result == []

    @patch("app.services.cve_providers.ghsa_provider.settings")
    def test_unsupported_ecosystem_returns_empty(self, mock_settings):
        mock_settings.GITHUB_TOKEN = "test-token"
        provider = GHSAProvider()
        dep = DependencyInfo(name="some-pkg", version="1.0", ecosystem="unknown_eco")
        result = provider.query(dep)
        assert result == []

"""
Tests unitaires — Validation des schémas Pydantic (SEC3).

Valide que le champ repo_url est correctement filtré pour GitHub et Docker.
"""
import pytest
from pydantic import ValidationError
from app.schemas.analysis_schema import AnalysisRequest


class TestGitHubURLValidation:
    """Tests de validation pour les URLs GitHub."""

    def test_valid_github_url(self):
        req = AnalysisRequest(repo_url="https://github.com/user/repo", target_type="github")
        assert req.repo_url == "https://github.com/user/repo"

    def test_valid_github_url_with_git_suffix(self):
        req = AnalysisRequest(repo_url="https://github.com/user/repo.git", target_type="github")
        assert req.repo_url == "https://github.com/user/repo.git"

    def test_valid_github_url_with_trailing_slash(self):
        req = AnalysisRequest(repo_url="https://github.com/user/repo/", target_type="github")
        assert req.repo_url == "https://github.com/user/repo/"

    def test_invalid_non_github_domain(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="https://gitlab.com/user/repo", target_type="github")

    def test_invalid_http_not_https(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="http://github.com/user/repo", target_type="github")

    def test_invalid_internal_ip(self):
        """SEC3 : Les IPs internes doivent être rejetées."""
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="https://192.168.1.1/user/repo", target_type="github")

    def test_invalid_missing_repo_name(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="https://github.com/user", target_type="github")

    def test_invalid_empty_url(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="", target_type="github")

    def test_invalid_path_traversal_in_url(self):
        """SEC3 : Path traversal doit être rejeté."""
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="https://github.com/../etc/passwd", target_type="github")


class TestDockerImageValidation:
    """Tests de validation pour les noms d'images Docker."""

    def test_valid_simple_image(self):
        req = AnalysisRequest(repo_url="python:3.12-slim", target_type="docker")
        assert req.repo_url == "python:3.12-slim"

    def test_valid_image_with_registry(self):
        req = AnalysisRequest(repo_url="ghcr.io/user/myapp:latest", target_type="docker")
        assert req.repo_url == "ghcr.io/user/myapp:latest"

    def test_valid_image_lowercase_conversion(self):
        """Les noms Docker sont normalisés en minuscules."""
        req = AnalysisRequest(repo_url="Python:3.12", target_type="docker")
        assert req.repo_url == "python:3.12"

    def test_valid_image_without_tag(self):
        req = AnalysisRequest(repo_url="ubuntu", target_type="docker")
        assert req.repo_url == "ubuntu"

    def test_invalid_path_traversal_docker(self):
        """SEC3 : Path traversal via nom Docker doit être rejeté."""
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="../../etc/passwd", target_type="docker")

    def test_invalid_url_with_http_protocol(self):
        """Une URL avec protocole http:// n'est pas un nom d'image valide."""
        # Les URLs avec '//' sont rejetées car '//' contient ':' suivi de '//'
        # mais une URL complète http://... contient des caractères invalides
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="http://evil.com/image", target_type="docker")

    def test_invalid_spaces_in_docker_image(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="my image:latest", target_type="docker")


class TestScanTypeValidation:
    """Valide que scan_type accepte uniquement 'standard' et 'deep'."""

    def test_standard_scan_type(self):
        req = AnalysisRequest(repo_url="https://github.com/user/repo", scan_type="standard")
        assert req.scan_type == "standard"

    def test_deep_scan_type(self):
        req = AnalysisRequest(repo_url="https://github.com/user/repo", scan_type="deep")
        assert req.scan_type == "deep"

    def test_invalid_scan_type(self):
        with pytest.raises(ValidationError):
            AnalysisRequest(repo_url="https://github.com/user/repo", scan_type="ultra")

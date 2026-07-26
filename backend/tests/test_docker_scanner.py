"""
Tests unitaires — Docker Scanner (analyse statique Dockerfile).

Valide la détection des mauvaises pratiques, des secrets en clair,
et l'extraction de l'image de base sans exécuter Docker ni Trivy.
"""
import pytest
from pathlib import Path
from app.services.docker_scanner import analyze_dockerfile, DockerScannerError


class TestAnalyzeDockerfile:
    """Tests de l'analyseur statique de Dockerfile."""

    def _write_dockerfile(self, tmp_path: Path, content: str) -> Path:
        p = tmp_path / "Dockerfile"
        p.write_text(content, encoding="utf-8")
        return p

    def test_extracts_base_image(self, tmp_path):
        """L'image de base est correctement extraite du FROM."""
        df = self._write_dockerfile(tmp_path, "FROM python:3.12-slim\nRUN pip install flask\n")
        result = analyze_dockerfile(df)
        assert result["base_image"] == "python:3.12-slim"

    def test_extracts_base_image_with_platform(self, tmp_path):
        """FROM avec --platform est correctement parsé."""
        df = self._write_dockerfile(tmp_path, "FROM --platform=linux/amd64 node:18-alpine\n")
        result = analyze_dockerfile(df)
        assert result["base_image"] == "node:18-alpine"

    def test_latest_tag_is_issue(self, tmp_path):
        """Le tag ':latest' doit être détecté comme une mauvaise pratique."""
        df = self._write_dockerfile(tmp_path, "FROM python:latest\n")
        result = analyze_dockerfile(df)
        assert any("latest" in issue.lower() for issue in result["issues"])

    def test_no_tag_is_issue(self, tmp_path):
        """Pas de tag = latest implicite → mauvaise pratique."""
        df = self._write_dockerfile(tmp_path, "FROM ubuntu\n")
        result = analyze_dockerfile(df)
        assert any("latest" in issue.lower() for issue in result["issues"])

    def test_no_user_instruction_is_issue(self, tmp_path):
        """Absence d'instruction USER → root par défaut → mauvaise pratique."""
        df = self._write_dockerfile(tmp_path, "FROM python:3.12\nRUN echo hello\n")
        result = analyze_dockerfile(df)
        assert result["has_root_user"] is True
        assert any("user" in issue.lower() for issue in result["issues"])

    def test_non_root_user_is_good_practice(self, tmp_path):
        """Un USER non-root est une bonne pratique → has_root_user = False."""
        df = self._write_dockerfile(tmp_path, "FROM python:3.12\nUSER appuser\n")
        result = analyze_dockerfile(df)
        assert result["has_root_user"] is False

    def test_explicit_root_user_is_issue(self, tmp_path):
        """USER root explicite est une mauvaise pratique."""
        df = self._write_dockerfile(tmp_path, "FROM python:3.12\nUSER root\n")
        result = analyze_dockerfile(df)
        assert any("root" in issue.lower() for issue in result["issues"])

    def test_secret_in_env_is_detected(self, tmp_path):
        """Les secrets en clair dans ENV sont détectés."""
        df = self._write_dockerfile(tmp_path,
            "FROM python:3.12\nENV API_KEY=supersecret123\nUSER appuser\n"
        )
        result = analyze_dockerfile(df)
        assert any("secret" in issue.lower() or "api_key" in issue.lower()
                   for issue in result["issues"])

    def test_password_in_env_is_detected(self, tmp_path):
        """ENV PASSWORD= est détecté comme secret en clair."""
        df = self._write_dockerfile(tmp_path,
            "FROM python:3.12\nENV PASSWORD=admin123\nUSER appuser\n"
        )
        result = analyze_dockerfile(df)
        assert any("password" in issue.lower() or "secret" in issue.lower()
                   for issue in result["issues"])

    def test_comments_are_ignored(self, tmp_path):
        """Les commentaires ne doivent pas déclencher de faux positifs."""
        df = self._write_dockerfile(tmp_path,
            "# FROM ubuntu:latest — old base image\nFROM python:3.12-slim\nUSER appuser\n"
        )
        result = analyze_dockerfile(df)
        # L'image doit être python:3.12-slim, pas ubuntu
        assert result["base_image"] == "python:3.12-slim"
        # Pas de faux latest car c'est dans un commentaire
        latest_issues = [i for i in result["issues"] if "latest" in i.lower()]
        assert len(latest_issues) == 0

    def test_good_dockerfile_has_no_issues(self, tmp_path):
        """Un Dockerfile bien configuré ne doit avoir aucun problème."""
        df = self._write_dockerfile(tmp_path,
            "FROM python:3.12-slim\n"
            "WORKDIR /app\n"
            "COPY requirements.txt .\n"
            "RUN pip install -r requirements.txt\n"
            "USER appuser\n"
        )
        result = analyze_dockerfile(df)
        assert result["has_root_user"] is False
        assert result["base_image"] == "python:3.12-slim"
        assert len(result["issues"]) == 0

    def test_unreadable_dockerfile_raises_error(self, tmp_path):
        """Un Dockerfile inexistant lève DockerScannerError."""
        fake_path = tmp_path / "nonexistent_dockerfile"
        with pytest.raises(DockerScannerError):
            analyze_dockerfile(fake_path)

"""
Tests unitaires — Dependency Scanner.

Valide l'extraction des dépendances depuis les fichiers de configuration.
"""
import pytest
import tempfile
from pathlib import Path

from app.services.dependency_scanner import (
    DependencyInfo,
    parse_requirements_txt,
    scan_dependencies,
)


class TestDependencyInfo:
    def test_normalization(self):
        """Les noms sont normalisés en lowercase, les versions trimées."""
        dep = DependencyInfo(name="  Flask  ", version="  2.0.1  ", ecosystem="  Python  ")
        assert dep.name == "flask"
        assert dep.version == "2.0.1"
        assert dep.ecosystem == "python"

    def test_empty_version_becomes_unknown(self):
        """Version vide → 'unknown'."""
        dep = DependencyInfo(name="flask", version="", ecosystem="python")
        assert dep.version == "unknown"

    def test_none_version_becomes_unknown(self):
        """Version None → 'unknown'."""
        dep = DependencyInfo(name="flask", version=None, ecosystem="python")
        assert dep.version == "unknown"

    def test_is_valid(self):
        """Un DependencyInfo avec nom non vide est valide."""
        dep = DependencyInfo(name="flask", version="1.0", ecosystem="python")
        assert dep.is_valid() is True

    def test_empty_name_is_invalid(self):
        """Un DependencyInfo avec nom vide n'est pas valide."""
        dep = DependencyInfo(name="", version="1.0", ecosystem="python")
        assert dep.is_valid() is False


class TestParseRequirementsTxt:
    def test_simple_requirements(self, tmp_path):
        """Parse un requirements.txt standard."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.0.1\nrequests>=2.28.0\nnumpy\n")
        result = parse_requirements_txt(req_file)
        names = [d.name for d in result]
        assert "flask" in names
        assert "requests" in names
        assert "numpy" in names

    def test_comments_ignored(self, tmp_path):
        """Les commentaires et lignes vides sont ignorés."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# This is a comment\nflask==2.0.1\n\n  \n# Another comment\n")
        result = parse_requirements_txt(req_file)
        assert len(result) == 1
        assert result[0].name == "flask"

    def test_version_operators(self, tmp_path):
        """Différents opérateurs de version sont parsés."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.0.1\nrequests>=2.28\nnumpy~=1.24\ndjango!=3.0\n")
        result = parse_requirements_txt(req_file)
        assert len(result) == 4

    def test_empty_file(self, tmp_path):
        """Fichier vide → liste vide."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")
        result = parse_requirements_txt(req_file)
        assert result == []

    def test_nonexistent_file(self, tmp_path):
        """Fichier inexistant → liste vide (pas d'exception)."""
        result = parse_requirements_txt(tmp_path / "nonexistent.txt")
        assert result == []

    def test_extras_ignored(self, tmp_path):
        """Les extras [security] sont ignorés dans le nom."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests[security]==2.28.0\n")
        result = parse_requirements_txt(req_file)
        assert len(result) == 1
        assert result[0].name == "requests"


class TestScanDependencies:
    def test_empty_dependency_files(self, tmp_path):
        """Aucun fichier de dépendances → liste vide."""
        result = scan_dependencies(tmp_path, {})
        assert result == []

    def test_python_requirements(self, tmp_path):
        """Détecte les dépendances Python à partir d'un requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("flask==2.0.1\nrequests==2.28.0\n")
        dep_files = {"python": ["requirements.txt"]}
        result = scan_dependencies(tmp_path, dep_files)
        assert len(result) >= 2
        ecosystems = set(d.ecosystem for d in result)
        assert "python" in ecosystems

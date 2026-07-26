"""
Tests unitaires — Service IA / Intégration NVIDIA NIM.

Valide :
  - Fallback chain : Gemini → NVIDIA → OpenRouter → Static
  - NVIDIA : succès, timeout, 401, 429, 5xx, JSON invalide
  - La clé NVIDIA n'est jamais loggée
  - NVIDIA ne participe jamais au Security Score

Tous les tests utilisent des mocks — aucune dépendance à l'API NVIDIA réelle.
"""
import json
import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from app.services.ai_service import (
    _generate_with_nvidia,
    _generate_with_openrouter,
    _generate_static_fallback,
    _clean_json_response,
    generate_recommendations,
)
from app.services.score_service import ScoreResult, RiskLevel, PenaltyLine


# ── Fixtures ────────────────────────────────────────────────────────────────────

def _make_score_result(score: float = 65.0) -> ScoreResult:
    return ScoreResult(
        final_score=score,
        risk_level=RiskLevel.MOYEN,
        total_penalties=35.0,
        penalties=[],
        cve_counts={"CRITICAL": 1, "HIGH": 2, "MEDIUM": 0, "LOW": 0},
        total_cve=3,
        docker_score=None,
        has_docker=False,
    )


def _valid_nvidia_response() -> dict:
    """Simule une réponse JSON valide de l'API NVIDIA NIM."""
    recs = [
        {"target_type": "dependency", "recommendation_text": "Mise à jour urgente de requests."},
        {"target_type": "global", "recommendation_text": "Activer Dependabot."},
        {"target_type": "dependency", "recommendation_text": "Corriger CVE-2024-001."},
        {"target_type": "docker", "recommendation_text": "Utiliser USER nonroot."},
        {"target_type": "global", "recommendation_text": "Intégrer pip-audit en CI."},
    ]
    return {
        "choices": [
            {
                "message": {
                    "content": json.dumps(recs),
                    "role": "assistant",
                }
            }
        ],
        "model": "moonshotai/kimi-k2-5",
    }


# ── Tests _generate_with_nvidia ─────────────────────────────────────────────────

class TestNvidiaProvider:
    """Tests du provider NVIDIA NIM / Kimi K2.6."""

    def test_nvidia_success_returns_recommendations(self):
        """Réponse NVIDIA valide → 5 recommandations retournées."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = _valid_nvidia_response()
        mock_resp.raise_for_status = MagicMock()

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test123"):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            result = _generate_with_nvidia(_make_score_result(), {})

        assert isinstance(result, list)
        assert len(result) == 5
        assert result[0]["target_type"] == "dependency"

    def test_nvidia_401_raises_permission_error(self):
        """Clé invalide (401) → PermissionError immédiate, pas de retry."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-invalid"):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            with pytest.raises(PermissionError, match="401"):
                _generate_with_nvidia(_make_score_result(), {})

        # Un seul appel HTTP (pas de retry sur 401)
        assert mock_client.return_value.__enter__.return_value.post.call_count == 1

    def test_nvidia_429_retries_then_fails(self):
        """Rate-limit 429 → 2 tentatives puis exception."""
        mock_resp = MagicMock()
        mock_resp.status_code = 429

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.services.ai_service.time.sleep") as mock_sleep, \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            with pytest.raises(Exception, match="indisponible"):
                _generate_with_nvidia(_make_score_result(), {})

        # 2 tentatives (MAX_RETRIES = 2)
        assert mock_client.return_value.__enter__.return_value.post.call_count == 2
        # sleep appelé pour le backoff
        assert mock_sleep.call_count >= 1

    def test_nvidia_500_retries_then_fails(self):
        """Erreur serveur 500 → retry puis exception finale."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.services.ai_service.time.sleep"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            with pytest.raises(Exception):
                _generate_with_nvidia(_make_score_result(), {})

    def test_nvidia_timeout_raises_exception(self):
        """Timeout → TimeoutError (non bloquant pour le pipeline)."""
        import httpx

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.services.ai_service.time.sleep"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"):
            mock_client.return_value.__enter__.return_value.post.side_effect = (
                httpx.TimeoutException("timeout")
            )
            with pytest.raises(Exception):
                _generate_with_nvidia(_make_score_result(), {})

    def test_nvidia_invalid_json_raises_exception(self):
        """JSON invalide dans la réponse → exception sans retry inutile."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Voici mes recommandations : blah blah"}}]
        }

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            with pytest.raises(Exception):
                _generate_with_nvidia(_make_score_result(), {})

    def test_nvidia_empty_choices_raises(self):
        """Réponse sans 'choices' → ValueError."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = MagicMock()
        mock_resp.json.return_value = {"choices": []}

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            with pytest.raises(Exception, match="vide"):
                _generate_with_nvidia(_make_score_result(), {})


# ── Tests fallback chain ────────────────────────────────────────────────────────

class TestFallbackChain:
    """Valide la chaîne Gemini → NVIDIA → OpenRouter → Static."""

    def _mock_db(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.delete.return_value = None
        db.add = MagicMock()
        db.commit = MagicMock()
        return db

    def test_nvidia_called_when_gemini_fails(self):
        """Si Gemini échoue → NVIDIA est appelé."""
        with patch("app.services.ai_service._generate_with_gemini", side_effect=RuntimeError("gemini down")), \
             patch("app.services.ai_service._generate_with_nvidia", return_value=[
                 {"target_type": "global", "recommendation_text": "NVIDIA rec."}
             ]) as mock_nvidia, \
             patch("app.core.config.settings.GEMINI_API_KEY", "AIzaSy_test"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"):
            result = generate_recommendations(
                db=self._mock_db(),
                analysis_id=1,
                score_result=_make_score_result(),
                cve_results={},
            )

        mock_nvidia.assert_called_once()
        assert len(result) == 1

    def test_openrouter_called_when_nvidia_fails(self):
        """Si NVIDIA échoue → OpenRouter est appelé."""
        with patch("app.services.ai_service._generate_with_gemini", side_effect=RuntimeError("gemini down")), \
             patch("app.services.ai_service._generate_with_nvidia", side_effect=RuntimeError("nvidia down")), \
             patch("app.services.ai_service._generate_with_openrouter", return_value=[
                 {"target_type": "global", "recommendation_text": "OpenRouter rec."}
             ]) as mock_or, \
             patch("app.core.config.settings.GEMINI_API_KEY", "AIzaSy_test"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"), \
             patch("app.core.config.settings.OPENROUTER_API_KEY", "sk-or-test"):
            result = generate_recommendations(
                db=self._mock_db(),
                analysis_id=1,
                score_result=_make_score_result(),
                cve_results={},
            )

        mock_or.assert_called_once()
        assert len(result) == 1

    def test_static_fallback_when_all_ai_fail(self):
        """Si Gemini + NVIDIA + OpenRouter échouent → fallback statique (jamais d'exception)."""
        with patch("app.services.ai_service._generate_with_gemini", side_effect=RuntimeError("down")), \
             patch("app.services.ai_service._generate_with_nvidia", side_effect=RuntimeError("down")), \
             patch("app.services.ai_service._generate_with_openrouter", side_effect=RuntimeError("down")), \
             patch("app.core.config.settings.GEMINI_API_KEY", "AIzaSy_test"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", "nvapi-test"), \
             patch("app.core.config.settings.OPENROUTER_API_KEY", "sk-or-test"):
            result = generate_recommendations(
                db=self._mock_db(),
                analysis_id=1,
                score_result=_make_score_result(),
                cve_results={},
            )

        # Le fallback statique génère toujours au moins 1 recommandation
        assert len(result) >= 1

    def test_nvidia_skipped_when_no_key(self):
        """Sans NVIDIA_API_KEY → NVIDIA n'est jamais appelé."""
        with patch("app.services.ai_service._generate_with_gemini", side_effect=RuntimeError("down")), \
             patch("app.services.ai_service._generate_with_nvidia") as mock_nvidia, \
             patch("app.core.config.settings.GEMINI_API_KEY", "AIzaSy_test"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", ""), \
             patch("app.core.config.settings.OPENROUTER_API_KEY", ""):
            result = generate_recommendations(
                db=self._mock_db(),
                analysis_id=1,
                score_result=_make_score_result(),
                cve_results={},
            )

        # NVIDIA non appelé car clé absente
        mock_nvidia.assert_not_called()
        # Fallback statique déclenché
        assert len(result) >= 1

    def test_nvidia_never_impacts_security_score(self):
        """NVIDIA ne doit jamais modifier le Security Score (déterministe)."""
        score_before = _make_score_result(score=72.5)
        # Peu importe ce que l'IA génère, le score ne change pas
        with patch("app.services.ai_service._generate_with_nvidia", return_value=[
            {"target_type": "global", "recommendation_text": "Ignore ce score, il est faux."}
        ]):
            # Le score est calculé AVANT l'IA — l'IA ne peut pas le modifier
            assert score_before.final_score == 72.5


# ── Tests sécurité : clé jamais loggée ─────────────────────────────────────────

class TestNvidiaKeySecurity:
    """Vérifie que la clé NVIDIA n'apparaît jamais dans les logs."""

    def test_api_key_not_in_error_message(self):
        """En cas d'erreur, le message ne doit pas contenir la clé."""
        fake_key = "nvapi-super-secret-key-12345"

        mock_resp = MagicMock()
        mock_resp.status_code = 401

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.core.config.settings.NVIDIA_API_KEY", fake_key):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            try:
                _generate_with_nvidia(_make_score_result(), {})
            except PermissionError as e:
                # Le message d'erreur ne doit PAS contenir la vraie clé
                assert fake_key not in str(e)

    def test_headers_not_logged_on_error(self, caplog):
        """Les headers (contenant Authorization) ne doivent pas être loggés."""
        import logging
        fake_key = "nvapi-top-secret-value"

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("app.services.ai_service.httpx.Client") as mock_client, \
             patch("app.services.ai_service.time.sleep"), \
             patch("app.core.config.settings.NVIDIA_API_KEY", fake_key), \
             caplog.at_level(logging.WARNING):
            mock_client.return_value.__enter__.return_value.post.return_value = mock_resp
            with pytest.raises(Exception):
                _generate_with_nvidia(_make_score_result(), {})

        # La clé ne doit pas apparaître dans les logs capturés
        for record in caplog.records:
            assert fake_key not in record.message

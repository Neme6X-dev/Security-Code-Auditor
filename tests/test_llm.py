"""Tests pour le module LLM (GeminiClient, prompts, config)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from auditor.config import get_gemini_api_key
from auditor.llm.gemini_client import (
    MAX_RETRIES,
    GeminiClient,
    build_failure_result,
    _parse_analysis_response,
)
from auditor.llm.prompts import build_analysis_prompt


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

SAMPLE_FINDING: dict[str, object] = {
    "rule_id": "dangerous-strcpy",
    "message": "strcpy utilise sans bornage",
    "severity": "ERROR",
    "file": "src/main.c",
    "line": 42,
}

SAMPLE_CODE_SNIPPET: str = (
    "32: void copy_input(const char *src) {\n"
    "33:     char buf[64];\n"
    "...\n"
    "42:     strcpy(buf, src);\n"
    "...\n"
    "52: }\n"
)

VALID_GEMINI_RESPONSE: dict[str, object] = {
    "explanation": "La fonction strcpy copie la source dans buf sans verifier la taille.",
    "severity_cvss_estimate": 8.1,
    "suggested_patch": "strncpy(buf, src, sizeof(buf) - 1);",
    "confidence": "high",
}


# ---------------------------------------------------------------------------
# config.get_gemini_api_key
# ---------------------------------------------------------------------------


class TestGetGeminiApiKey:
    """Tests pour la fonction get_gemini_api_key."""

    @patch.dict("os.environ", {}, clear=True)
    @patch("auditor.config.load_dotenv")
    def test_raises_when_key_missing(self, _mock_dotenv: MagicMock) -> None:
        """Verifie qu'une erreur est levee si GEMINI_API_KEY est absente."""
        with pytest.raises(EnvironmentError, match="Cle API Gemini manquante"):
            get_gemini_api_key()

    @patch.dict("os.environ", {"GEMINI_API_KEY": "   "})
    @patch("auditor.config.load_dotenv")
    def test_raises_when_key_blank(self, _mock_dotenv: MagicMock) -> None:
        """Verifie qu'une erreur est levee si GEMINI_API_KEY est vide."""
        with pytest.raises(EnvironmentError, match="Cle API Gemini manquante"):
            get_gemini_api_key()

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key-123"})
    @patch("auditor.config.load_dotenv")
    def test_returns_key_when_present(self, _mock_dotenv: MagicMock) -> None:
        """Verifie que la cle est retournee quand elle est definie."""
        assert get_gemini_api_key() == "test-key-123"

    @patch.dict("os.environ", {"GEMINI_API_KEY": "  my-key  "})
    @patch("auditor.config.load_dotenv")
    def test_strips_whitespace(self, _mock_dotenv: MagicMock) -> None:
        """Verifie que les espaces autour de la cle sont supprimes."""
        assert get_gemini_api_key() == "my-key"

    @patch.dict("os.environ", {}, clear=True)
    @patch("auditor.config.load_dotenv")
    def test_api_key_never_in_error_message(self, _mock_dotenv: MagicMock) -> None:
        """Verifie que la cle n'apparait jamais dans un message d'erreur."""
        with pytest.raises(EnvironmentError) as exc_info:
            get_gemini_api_key()
        assert "GEMINI_API_KEY" not in str(exc_info.value) or "manquante" in str(exc_info.value)

    @patch.dict("os.environ", {"GOOGLE_GENAI_API_KEY": "genai-key-123"})
    @patch("auditor.config.load_dotenv")
    def test_returns_google_genai_key(self, _mock_dotenv: MagicMock) -> None:
        """Verifie que GOOGLE_GENAI_API_KEY est accepte en fallback."""
        assert get_gemini_api_key() == "genai-key-123"

    @patch.dict("os.environ", {"GEMINI_API_KEY": "primary", "GOOGLE_GENAI_API_KEY": "fallback"})
    @patch("auditor.config.load_dotenv")
    def test_gemini_key_takes_priority(self, _mock_dotenv: MagicMock) -> None:
        """Verifie que GEMINI_API_KEY a priorite sur GOOGLE_GENAI_API_KEY."""
        assert get_gemini_api_key() == "primary"


# ---------------------------------------------------------------------------
# prompts.build_analysis_prompt
# ---------------------------------------------------------------------------


class TestBuildAnalysisPrompt:
    """Tests pour la fonction build_analysis_prompt."""

    def test_contains_finding_data(self) -> None:
        """Verifie que le prompt contient toutes les donnees du finding."""
        prompt = build_analysis_prompt(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)
        assert "dangerous-strcpy" in prompt
        assert "strcpy utilise sans bornage" in prompt
        assert "ERROR" in prompt
        assert "src/main.c" in prompt
        assert "42" in prompt

    def test_contains_code_snippet(self) -> None:
        """Verifie que le code source est inclus dans le prompt."""
        prompt = build_analysis_prompt(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)
        assert SAMPLE_CODE_SNIPPET in prompt

    def test_requests_json_output(self) -> None:
        """Verifie que le prompt demande explicitement du JSON."""
        prompt = build_analysis_prompt(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)
        assert "JSON" in prompt

    def test_mentions_cvss_and_confidence(self) -> None:
        """Verifie que le prompt mentionne les cles du schema de reponse."""
        prompt = build_analysis_prompt(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)
        assert "severity_cvss_estimate" in prompt
        assert "confidence" in prompt
        assert "suggested_patch" in prompt
        assert "explanation" in prompt

    def test_instructs_no_invention_when_ambiguous(self) -> None:
        """Verifie que le prompt interdit d'inventer un CWE."""
        prompt = build_analysis_prompt(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)
        assert "ambigu" in prompt.lower() or "inventer" in prompt.lower()


# ---------------------------------------------------------------------------
# gemini_client._parse_analysis_response
# ---------------------------------------------------------------------------


class TestParseAnalysisResponse:
    """Tests pour la fonction _parse_analysis_response."""

    def test_valid_response(self) -> None:
        """Verifie le parsing d'une reponse JSON valide et complete."""
        raw = json.dumps(VALID_GEMINI_RESPONSE)
        result = _parse_analysis_response(raw)
        assert result["explanation"] == VALID_GEMINI_RESPONSE["explanation"]
        assert result["severity_cvss_estimate"] == 8.1
        assert result["confidence"] == "high"

    def test_invalid_json_raises(self) -> None:
        """Verifie qu'une exception est levee pour un JSON invalide."""
        with pytest.raises(json.JSONDecodeError):
            _parse_analysis_response("not json at all")

    def test_missing_keys_raises(self) -> None:
        """Verifie qu'une exception est levee si des cles sont manquantes."""
        incomplete = json.dumps({"explanation": "ok"})
        with pytest.raises(ValueError, match="Cles manquantes"):
            _parse_analysis_response(incomplete)

    def test_bad_cvss_type_raises(self) -> None:
        """Verifie qu'une exception est levee si severity_cvss_estimate n'est pas un nombre."""
        bad = json.dumps({
            "explanation": "ok",
            "severity_cvss_estimate": "high",
            "suggested_patch": "code",
            "confidence": "high",
        })
        with pytest.raises(ValueError, match="severity_cvss_estimate"):
            _parse_analysis_response(bad)

    def test_cvss_out_of_range_raises(self) -> None:
        """Verifie qu'une exception est levee si le CVSS est hors [0-10]."""
        bad = json.dumps({
            "explanation": "ok",
            "severity_cvss_estimate": 15.0,
            "suggested_patch": "code",
            "confidence": "high",
        })
        with pytest.raises(ValueError, match="hors range"):
            _parse_analysis_response(bad)

    def test_invalid_confidence_raises(self) -> None:
        """Verifie qu'une exception est levee si confidence n'est pas high/medium/low."""
        bad = json.dumps({
            "explanation": "ok",
            "severity_cvss_estimate": 5.0,
            "suggested_patch": "code",
            "confidence": "very_high",
        })
        with pytest.raises(ValueError, match="confidence invalide"):
            _parse_analysis_response(bad)

    def test_boundary_cvss_zero(self) -> None:
        """Verifie que CVSS=0.0 est accepte."""
        raw = json.dumps({
            "explanation": "ok",
            "severity_cvss_estimate": 0.0,
            "suggested_patch": "code",
            "confidence": "low",
        })
        result = _parse_analysis_response(raw)
        assert result["severity_cvss_estimate"] == 0.0

    def test_boundary_cvss_ten(self) -> None:
        """Verifie que CVSS=10.0 est accepte."""
        raw = json.dumps({
            "explanation": "ok",
            "severity_cvss_estimate": 10.0,
            "suggested_patch": "code",
            "confidence": "high",
        })
        result = _parse_analysis_response(raw)
        assert result["severity_cvss_estimate"] == 10.0


# ---------------------------------------------------------------------------
# gemini_client.GeminiClient
# ---------------------------------------------------------------------------


class TestGeminiClient:
    """Tests pour la classe GeminiClient."""

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_init_sets_up_client(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie que l'initialisation configure le client."""
        client = GeminiClient(model_name="gemini-pro")
        mock_client_cls.assert_called_once_with(api_key="fake-key")
        assert client.model_name == "gemini-pro"

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_success(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie qu'un finding analyse correctement retourne le JSON parse."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps(VALID_GEMINI_RESPONSE)
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["explanation"] == VALID_GEMINI_RESPONSE["explanation"]
        assert result["severity_cvss_estimate"] == 8.1
        assert result["confidence"] == "high"
        assert "status" not in result


# ---------------------------------------------------------------------------
# gemini_client.build_failure_result
# ---------------------------------------------------------------------------


class TestBuildFailureResult:
    """Tests pour la fonction build_failure_result."""

    def test_includes_error_type_and_message(self) -> None:
        """Verifie que le type et le message de l'erreur sont dans explanation."""
        result = build_failure_result(ValueError("cles manquantes"))
        assert "ValueError" in result["explanation"]
        assert "cles manquantes" in result["explanation"]
        assert result["status"] == "analysis_failed"

    def test_api_key_filtered_from_explanation(self) -> None:
        """Verifie que les mots-cles sensibles sont filtres du message."""
        result = build_failure_result(Exception("Invalid api_key: sk-abc123"))
        assert "sk-abc123" not in result["explanation"]
        assert "filtre" in result["explanation"]

    def test_empty_message_uses_type_only(self) -> None:
        """Verifie qu'un message vide produit un explanation avec le type seul."""
        result = build_failure_result(RuntimeError())
        assert "RuntimeError" in result["explanation"]

    def test_standard_fields_present(self) -> None:
        """Verifie que les champs standard sont toujours presents."""
        result = build_failure_result(Exception("test"))
        assert result["severity_cvss_estimate"] == 0.0
        assert result["suggested_patch"] == ""
        assert result["confidence"] == "low"

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_api_error_returns_failed(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie qu'une erreur API ne casse pas le pipeline."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("Rate limit exceeded")
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["status"] == "analysis_failed"
        assert result["confidence"] == "low"

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_invalid_json_returns_failed(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie qu'une reponse non-JSON apres retry retourne analysis_failed."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "this is not json"
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["status"] == "analysis_failed"
        assert mock_client.models.generate_content.call_count == MAX_RETRIES

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_value_error_retries_max_times(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie qu'une ValueError (schema invalide) est reessayee MAX_RETRIES fois."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = json.dumps({"explanation": "ok"})
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["status"] == "analysis_failed"
        assert mock_client.models.generate_content.call_count == MAX_RETRIES

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_failure_contains_error_type(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie que le message d'echec contient le type d'erreur reel."""
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "not json"
        mock_client.models.generate_content.return_value = mock_response
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["status"] == "analysis_failed"
        assert "JSONDecodeError" in result["explanation"]

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_api_error_failure_contains_error_type(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie que le message d'echec API contient le type d'erreur reel."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("boom")
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["status"] == "analysis_failed"
        assert "Exception" in result["explanation"]
        assert "boom" in result["explanation"]

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_retries_on_json_error(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie que le client reessaie apres un echec de parsing JSON."""
        mock_client = MagicMock()

        bad_response = MagicMock()
        bad_response.text = "not json"

        good_response = MagicMock()
        good_response.text = json.dumps(VALID_GEMINI_RESPONSE)

        mock_client.models.generate_content.side_effect = [bad_response, good_response]
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["explanation"] == VALID_GEMINI_RESPONSE["explanation"]
        assert mock_client.models.generate_content.call_count == 2

    @patch("auditor.llm.gemini_client.genai.Client")
    @patch("auditor.llm.gemini_client.get_gemini_api_key", return_value="fake-key")
    def test_analyze_finding_no_api_key_leak_in_logs(
        self,
        _mock_key: MagicMock,
        mock_client_cls: MagicMock,
    ) -> None:
        """Verifie que la cle API n'est pas exposee en cas d'erreur."""
        mock_client = MagicMock()
        mock_client.models.generate_content.side_effect = Exception("boom")
        mock_client_cls.return_value = mock_client

        client = GeminiClient()
        result = client.analyze_finding(SAMPLE_FINDING, SAMPLE_CODE_SNIPPET)

        assert result["status"] == "analysis_failed"
        assert "fake-key" not in result["explanation"]
        assert "fake-key" not in str(result)
        _mock_key.assert_called_once_with()

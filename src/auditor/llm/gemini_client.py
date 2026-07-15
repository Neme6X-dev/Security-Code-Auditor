"""Client Gemini : interface avec l'API Google Gen AI pour l'analyse de code."""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from google import genai
from google.genai import types

from auditor.config import get_gemini_api_key
from auditor.llm.prompts import build_analysis_prompt

logger = logging.getLogger(__name__)

MAX_RETRIES: int = 2
RATE_LIMIT_RETRIES: int = 5
RATE_LIMIT_DEFAULT_DELAY: int = 30

ANALYSIS_RESPONSE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "explanation": {
            "type": "string",
            "description": "Explication de la vulnerabilite en francais, niveau etudiant avance.",
        },
        "severity_cvss_estimate": {
            "type": "number",
            "description": "Estimation de la severite CVSS entre 0.0 et 10.0.",
        },
        "suggested_patch": {
            "type": "string",
            "description": "Snippet de code corrige minimal et sur.",
        },
        "confidence": {
            "type": "string",
            "enum": ["high", "medium", "low"],
            "description": "Niveau de confiance dans l'analyse.",
        },
    },
    "required": ["explanation", "severity_cvss_estimate", "suggested_patch", "confidence"],
}

DEFAULT_ANALYSIS_RESULT: dict[str, object] = {
    "explanation": "Analyse echouee : impossible de parser la reponse du modele.",
    "severity_cvss_estimate": 0.0,
    "suggested_patch": "",
    "confidence": "low",
    "status": "analysis_failed",
}


def _parse_retry_delay(exc: Exception) -> int | None:
    """Extrait le delai de retry depuis une erreur API Google Gen AI.

    Args:
        exc: Exception capturee lors de l'appel API.

    Returns:
        Delai en secondes ou None si non disponible.
    """
    try:
        error_details = getattr(exc, "details", None)
        if not error_details:
            return None

        for detail in error_details:
            if detail.get("@type", "").endswith("RetryInfo"):
                delay_str = detail.get("retryDelay", "")
                if delay_str.endswith("s"):
                    return int(float(delay_str[:-1]))
    except Exception:
        pass

    return None


class GeminiClient:
    """Client pour l'API Gemini, utilise pour l'analyse contextuelle de code.

    Attributes:
        model_name: Identifiant du modele Gemini a utiliser.
        _client: Instance du client Google Gen AI configuree.
    """

    def __init__(self, model_name: str = "gemini-2.0-flash") -> None:
        """Initialise le client Gemini avec la cle API depuis l'environnement.

        Args:
            model_name: Identifiant du modele Gemini (defaut : gemini-2.0-flash).
        """
        api_key = get_gemini_api_key()
        self._client = genai.Client(api_key=api_key)
        self.model_name = model_name

    def analyze_finding(
        self,
        finding: dict[str, object],
        code_snippet: str,
    ) -> dict[str, object]:
        """Analyse un finding de securite en envoyant le code a Gemini.

        Envoie le finding + un extrait de code au modele et retourne une
        reponse structuree. En cas d'echec (reseau, parsing, API), l'erreur
        est loggee et un resultat par defaut avec status='analysis_failed'
        est retourne pour ne pas casser le pipeline.

        Args:
            finding: Dictionnaire normalise representant le finding.
            code_snippet: Extrait de code source (+/- 10 lignes).

        Returns:
            Dictionnaire contenant : explanation, severity_cvss_estimate,
            suggested_patch, confidence. En cas d'echec, la cle
            'status' vaut 'analysis_failed'.
        """
        prompt = build_analysis_prompt(finding, code_snippet)

        last_exception: Exception | None = None
        attempt = 0
        max_attempts = MAX_RETRIES

        while attempt < max_attempts:
            attempt += 1
            try:
                response = self._client.models.generate_content(
                    model=self.model_name,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=ANALYSIS_RESPONSE_SCHEMA,
                    ),
                )

                return _parse_analysis_response(response.text)

            except json.JSONDecodeError as exc:
                last_exception = exc
                logger.warning(
                    "Tentative %d/%d : reponse non-JSON, retry...",
                    attempt,
                    max_attempts,
                )

            except Exception as exc:
                last_exception = exc
                error_type = type(exc).__name__
                retry_delay = _parse_retry_delay(exc)

                if retry_delay is not None and attempt < RATE_LIMIT_RETRIES:
                    max_attempts = RATE_LIMIT_RETRIES
                    logger.warning(
                        "Tentative %d/%d : quota depasse, attente de %ds...",
                        attempt,
                        max_attempts,
                        retry_delay,
                    )
                    time.sleep(retry_delay)
                    continue

                logger.error(
                    "Tentative %d/%d : erreur API (%s) — abandon pour ce finding.",
                    attempt,
                    max_attempts,
                    error_type,
                )
                break

        logger.error(
            "Analyse echouee apres %d tentative(s) : %s",
            attempt,
            last_exception,
        )
        return dict(DEFAULT_ANALYSIS_RESULT)


def _parse_analysis_response(raw_text: str) -> dict[str, object]:
    """Parse la reponse JSON du modele en dictionnaire valide.

    Valide que toutes les cles requises sont presentes et que les types
    sont corrects avant de retourner le resultat.

    Args:
        raw_text: Texte brut retourne par le modele (JSON attendu).

    Returns:
        Dictionnaire avec les cles : explanation, severity_cvss_estimate,
        suggested_patch, confidence.

    Raises:
        json.JSONDecodeError: Si le texte n'est pas un JSON valide.
        ValueError: Si des cles requises sont manquantes ou de mauvais types.
    """
    data = json.loads(raw_text)

    required_keys = {"explanation", "severity_cvss_estimate", "suggested_patch", "confidence"}
    missing = required_keys - data.keys()
    if missing:
        raise ValueError(f"Cles manquantes dans la reponse : {missing}")

    if not isinstance(data["explanation"], str):
        raise ValueError("explanation doit etre une chaine")

    try:
        cvss = float(data["severity_cvss_estimate"])
    except (TypeError, ValueError):
        raise ValueError(
            f"severity_cvss_estimate doit etre un nombre, "
            f"recu : {type(data['severity_cvss_estimate']).__name__}"
        ) from None
    if not (0.0 <= cvss <= 10.0):
        raise ValueError(f"severity_cvss_estimate hors range [0-10] : {cvss}")
    data["severity_cvss_estimate"] = cvss

    if not isinstance(data["suggested_patch"], str):
        raise ValueError("suggested_patch doit etre une chaine")

    valid_confidence = {"high", "medium", "low"}
    if data["confidence"] not in valid_confidence:
        raise ValueError(
            f"confidence invalide : '{data['confidence']}' "
            f"(attendu parmi {valid_confidence})"
        )

    return data

"""Gestion de la configuration et du chargement des variables d'environnement."""

from __future__ import annotations

import os

from dotenv import load_dotenv

_ENV_LOADED: bool = False


def _ensure_env_loaded() -> None:
    """Charge le fichier .env une seule fois au premier appel.

    Cette fonction est appelee automatiquement par get_gemini_api_key()
    pour garantir que les variables d'environnement sont disponibles.
    """
    global _ENV_LOADED  # noqa: PLW0603
    if not _ENV_LOADED:
        load_dotenv()
        _ENV_LOADED = True


def get_gemini_api_key() -> str:
    """Retourne la cle API Gemini depuis les variables d'environnement.

    Supporte les noms de variable GEMINI_API_KEY et GOOGLE_GENAI_API_KEY.
    Le premier trouve est utilise. Le fichier .env est charge automatiquement
    si ce n'est pas encore fait. La cle n'est jamais loggee ni affichee,
    meme en cas d'erreur.

    Returns:
        La valeur de la cle API.

    Raises:
        EnvironmentError: Si aucune cle n'est definie ou si la valeur est vide.
    """
    _ensure_env_loaded()

    key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not key:
        key = os.environ.get("GOOGLE_GENAI_API_KEY", "").strip()

    if not key:
        raise EnvironmentError(
            "Cle API Gemini manquante : copiez .env.example vers .env "
            "et renseignez GEMINI_API_KEY ou GOOGLE_GENAI_API_KEY "
            "avec votre cle API Google AI Studio."
        )

    return key

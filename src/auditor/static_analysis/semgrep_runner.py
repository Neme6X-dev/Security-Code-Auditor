"""Runner Semgrep : execute Semgrep avec des regles personnalisees et collecte les resultats."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

SEMGREP_TIMEOUT: int = 120

SEMGREP_MISSING_MSG: str = (
    "Semgrep non trouve. Installez-le avec : pip install semgrep"
)


def run_semgrep(
    files: list[Path],
    rules_path: str | Path,
) -> list[dict[str, object]]:
    """Execute Semgrep sur une liste de fichiers et retourne les findings normalises.

    Args:
        files: Fichiers source a analyser.
        rules_path: Chemin vers le fichier de regles Semgrep YAML.

    Returns:
        Liste de dictionnaires normalises contenant les champs :
        file, line, rule_id, message, severity.

    Raises:
        FileNotFoundError: Si le binaire semgrep n'est pas dans le PATH.
        subprocess.TimeoutExpired: Si l'execution depasse 120 secondes.
        subprocess.CalledProcessError: Si Semgrep retourne un code d'erreur.
    """
    if shutil.which("semgrep") is None:
        raise FileNotFoundError(SEMGREP_MISSING_MSG)

    rules = Path(rules_path)
    if not rules.exists():
        raise FileNotFoundError(
            f"Fichier de regles introuvable : {rules}"
        )

    cmd: list[str] = [
        "semgrep",
        "--config",
        str(rules),
        "--json",
        "--timeout",
        str(SEMGREP_TIMEOUT),
        *[str(f) for f in files],
    ]

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=SEMGREP_TIMEOUT + 30,
    )

    if result.returncode not in (0, 1):
        result.check_returncode()

    return _parse_semgrep_output(result.stdout)


def _parse_semgrep_output(raw_output: str) -> list[dict[str, object]]:
    """Parse la sortie JSON de Semgrep en une liste de findings normalises.

    Args:
        raw_output: Sortie JSON brute de Semgrep.

    Returns:
        Liste de dictionnaires representant les findings.
    """
    if not raw_output.strip():
        return []

    data = json.loads(raw_output)
    results: list[dict[str, object]] = []

    for item in data.get("results", []):
        findings: dict[str, object] = {
            "file": item.get("check_id", ""),
            "line": 0,
            "rule_id": item.get("check_id", ""),
            "message": item.get("extra", {}).get("message", ""),
            "severity": item.get("extra", {}).get("severity", "WARNING"),
        }

        start = item.get("start", {})
        findings["line"] = start.get("line", 0)

        findings["file"] = item.get("path", "")

        results.append(findings)

    return results

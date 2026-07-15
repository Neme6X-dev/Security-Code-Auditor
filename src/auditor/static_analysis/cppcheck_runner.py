"""Runner Cppcheck : execute Cppcheck et collecte les resultats."""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

CPPCHECK_TIMEOUT: int = 120

CPPCHECK_MISSING_MSG: str = (
    "Cppcheck non trouve. Installez-le avec :\n"
    "  - Ubuntu/Debian : sudo apt install cppcheck\n"
    "  - macOS : brew install cppcheck\n"
    "  - Windows : choco install cppcheck"
)


def run_cppcheck(
    files: list[Path],
    extra_args: list[str] | None = None,
) -> list[dict[str, object]]:
    """Execute Cppcheck sur une liste de fichiers et retourne les findings normalises.

    Args:
        files: Fichiers source a analyser.
        extra_args: Arguments supplementaires a passer a Cppcheck.

    Returns:
        Liste de dictionnaires normalises contenant les champs :
        file, line, rule_id, message, severity.

    Raises:
        FileNotFoundError: Si le binaire cppcheck n'est pas dans le PATH.
        subprocess.TimeoutExpired: Si l'execution depasse le timeout.
    """
    if shutil.which("cppcheck") is None:
        raise FileNotFoundError(CPPCHECK_MISSING_MSG)

    cmd: list[str] = [
        "cppcheck",
        "--enable=all",
        "--xml",
        "--xml-version=2",
        "--suppress=missingIncludeSystem",
    ]

    if extra_args:
        cmd.extend(extra_args)

    cmd.extend(str(f) for f in files)

    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=CPPCHECK_TIMEOUT,
    )

    return _parse_cppcheck_output(result.stderr)


def _parse_cppcheck_output(raw_output: str) -> list[dict[str, object]]:
    """Parse la sortie XML de Cppcheck en une liste de findings normalises.

    Args:
        raw_output: Sortie XML brute de Cppcheck (envoyee sur stderr).

    Returns:
        Liste de dictionnaires representant les findings.
    """
    if not raw_output.strip():
        return []

    root = ET.fromstring(raw_output)
    findings: list[dict[str, object]] = []

    for error_elem in root.iter("error"):
        severity = error_elem.get("severity", "style")
        findings.append(
            {
                "file": error_elem.get("file", ""),
                "line": int(error_elem.get("line", 0)),
                "rule_id": error_elem.get("id", ""),
                "message": error_elem.get("verbose", error_elem.get("msg", "")),
                "severity": _normalize_severity(severity),
            }
        )

    return findings


def _normalize_severity(raw: str) -> str:
    """Normalise les niveaux de severite Cppcheck vers des categories standardisees.

    Args:
        raw: Severite brut retornee par Cppcheck.

    Returns:
        Severite normalisee parmi : critical, high, medium, low.
    """
    mapping: dict[str, str] = {
        "error": "critical",
        "warning": "high",
        "style": "low",
        "performance": "medium",
        "portability": "medium",
        "information": "low",
    }
    return mapping.get(raw.lower(), "low")

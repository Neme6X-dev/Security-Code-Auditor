"""Modeles de donnees pour les findings et rapports d'audit."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Niveaux de severite d'une vulnerabilite, derives du score CVSS estime.

    Mapping CVSS -> Severite :
        - CRITICAL : 9.0 - 10.0
        - HIGH     : 7.0 - 8.9
        - MEDIUM   : 4.0 - 6.9
        - LOW      : 1.0 - 3.9
        - INFO     : 0.0 - 0.9
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> Severity:
        """Determine la severite a partir d'un score CVSS estime.

        Args:
            score: Score CVSS entre 0.0 et 10.0.

        Returns:
            Niveau de severite correspondant.
        """
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score >= 1.0:
            return cls.LOW
        return cls.INFO


class Finding(BaseModel):
    """Represente une vulnerabilite detectee, fusion d'un finding statique et de l'analyse LLM.

    Attributes:
        rule_id: Identifiant de la regle ayant detecte la vulnerabilite.
        message: Description brute du finding (depuis l'analyseur statique).
        severity: Niveau de severite (defini par le CVSS estime par Gemini).
        file: Chemin du fichier contenant la vulnerabilite.
        line: Numero de ligne approximatif.
        cvss_estimate: Estimation du score CVSS par Gemini (0.0 - 10.0).
        explanation: Explication detaillee en francais (Gemini).
        suggested_patch: Snippet de code corrige (Gemini).
        confidence: Niveau de confiance de l'analyse LLM (high/medium/low).
        source: Outil ayant detecte le finding initial (semgrep/cppcheck).
    """

    rule_id: str
    message: str
    severity: Severity
    file: str
    line: int
    cvss_estimate: float = Field(ge=0.0, le=10.0, default=0.0)
    explanation: str = ""
    suggested_patch: str = ""
    confidence: str = "low"
    source: str = "unknown"


class AuditReport(BaseModel):
    """Rapport complet d'un audit de securite.

    Attributes:
        repo_path: Chemin du repertoire analyse.
        scan_date: Horodatage UTC de l'analyse.
        total_files_scanned: Nombre de fichiers source examines.
        findings: Liste des vulnerabilites detectees, tries par severite.
        summary: Compteur de findings par severite.
    """

    repo_path: str
    scan_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_files_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)

    @property
    def summary(self) -> dict[str, int]:
        """Retourne le compteur de findings par niveau de severite.

        Returns:
            Dictionnaire {severite: nombre} avec les cles en minuscules.
        """
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for f in self.findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    @property
    def total_findings(self) -> int:
        """Retourne le nombre total de findings."""
        return len(self.findings)

    def sorted_findings(self) -> list[Finding]:
        """Retourne les findings tries par severite decroissante, puis par fichier/ligne.

        Returns:
            Liste de Finding triee.
        """
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        return sorted(
            self.findings,
            key=lambda f: (severity_order.get(f.severity, 5), f.file, f.line),
        )

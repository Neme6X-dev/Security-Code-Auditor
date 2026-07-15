"""Tests pour le module de rapport (models, generator)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from auditor.report.generator import generate_json_report, generate_markdown_report
from auditor.report.models import AuditReport, Finding, Severity


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

def _make_finding(
    rule_id: str = "test-rule",
    message: str = "Test vulnerability",
    severity: Severity = Severity.HIGH,
    file: str = "src/test.c",
    line: int = 10,
    cvss: float = 7.5,
    explanation: str = "Explanation text",
    patch: str = "fixed_code();",
    confidence: str = "high",
    source: str = "semgrep",
) -> Finding:
    """Cree un Finding de test avec des valeurs par defaut raisonnables."""
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=severity,
        file=file,
        line=line,
        cvss_estimate=cvss,
        explanation=explanation,
        suggested_patch=patch,
        confidence=confidence,
        source=source,
    )


def _make_report(findings: list[Finding] | None = None) -> AuditReport:
    """Cree un AuditReport de test."""
    return AuditReport(
        repo_path="/test/project",
        scan_date=datetime(2025, 6, 15, 12, 0, 0, tzinfo=timezone.utc),
        total_files_scanned=42,
        findings=findings or [],
    )


# ---------------------------------------------------------------------------
# Tests Severity
# ---------------------------------------------------------------------------


class TestSeverityFromCvss:
    """Tests pour Severity.from_cvss."""

    def test_critical_at_9(self) -> None:
        assert Severity.from_cvss(9.0) == Severity.CRITICAL

    def test_critical_at_10(self) -> None:
        assert Severity.from_cvss(10.0) == Severity.CRITICAL

    def test_high_at_7(self) -> None:
        assert Severity.from_cvss(7.0) == Severity.HIGH

    def test_high_at_8_9(self) -> None:
        assert Severity.from_cvss(8.9) == Severity.HIGH

    def test_medium_at_4(self) -> None:
        assert Severity.from_cvss(4.0) == Severity.MEDIUM

    def test_medium_at_6_9(self) -> None:
        assert Severity.from_cvss(6.9) == Severity.MEDIUM

    def test_low_at_1(self) -> None:
        assert Severity.from_cvss(1.0) == Severity.LOW

    def test_low_at_3_9(self) -> None:
        assert Severity.from_cvss(3.9) == Severity.LOW

    def test_info_at_0(self) -> None:
        assert Severity.from_cvss(0.0) == Severity.INFO

    def test_info_below_1(self) -> None:
        assert Severity.from_cvss(0.5) == Severity.INFO


# ---------------------------------------------------------------------------
# Tests Finding
# ---------------------------------------------------------------------------


class TestFindingModel:
    """Tests pour le modele Finding."""

    def test_create_finding_with_all_fields(self) -> None:
        """Verifie la creation d'un Finding avec tous les champs requis."""
        f = _make_finding()
        assert f.rule_id == "test-rule"
        assert f.severity == Severity.HIGH
        assert f.cvss_estimate == 7.5

    def test_finding_severity_enum(self) -> None:
        """Verifie que les niveaux de severite sont valides."""
        for sev in Severity:
            f = _make_finding(severity=sev)
            assert f.severity == sev

    def test_finding_default_values(self) -> None:
        """Verifie que les valeurs par defaut sont appliquees."""
        f = Finding(
            rule_id="r",
            message="m",
            severity=Severity.LOW,
            file="f.c",
            line=1,
        )
        assert f.cvss_estimate == 0.0
        assert f.explanation == ""
        assert f.suggested_patch == ""
        assert f.confidence == "low"


# ---------------------------------------------------------------------------
# Tests AuditReport
# ---------------------------------------------------------------------------


class TestAuditReportModel:
    """Tests pour le modele AuditReport."""

    def test_create_report_with_findings(self) -> None:
        """Verifie la creation d'un rapport contenant des findings."""
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
        ]
        report = _make_report(findings)
        assert report.total_findings == 3
        assert len(report.findings) == 3

    def test_summary_counts(self) -> None:
        """Verifie que les compteurs par severite sont corrects."""
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.MEDIUM),
            _make_finding(severity=Severity.LOW),
        ]
        report = _make_report(findings)
        counts = report.summary
        assert counts["critical"] == 2
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 0

    def test_summary_empty_report(self) -> None:
        """Verifie le resume d'un rapport sans findings."""
        report = _make_report([])
        assert report.total_findings == 0
        assert all(v == 0 for v in report.summary.values())

    def test_sorted_findings_by_severity(self) -> None:
        """Verifie que les findings sont tries par severite decroissante."""
        findings = [
            _make_finding(severity=Severity.LOW, file="a.c", line=1),
            _make_finding(severity=Severity.CRITICAL, file="a.c", line=5),
            _make_finding(severity=Severity.MEDIUM, file="a.c", line=3),
            _make_finding(severity=Severity.HIGH, file="a.c", line=2),
        ]
        report = _make_report(findings)
        sorted_f = report.sorted_findings()
        severities = [f.severity for f in sorted_f]
        assert severities == [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ]


# ---------------------------------------------------------------------------
# Tests generate_markdown_report
# ---------------------------------------------------------------------------


class TestGenerateMarkdownReport:
    """Tests pour la fonction generate_markdown_report."""

    def test_header_content(self) -> None:
        """Verifie que l'en-tete contient les metadonnees du rapport."""
        report = _make_report()
        md = generate_markdown_report(report)
        assert "# Rapport d'Audit de Securite" in md
        assert "2025-06-15" in md
        assert "/test/project" in md
        assert "42" in md

    def test_summary_table(self) -> None:
        """Verifie que le tableau de synthese est present avec les bonnes en-tetes."""
        report = _make_report([
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(severity=Severity.HIGH),
        ])
        md = generate_markdown_report(report)
        assert "| Severite | Nombre |" in md
        assert "| Critique | 1 |" in md
        assert "| Haute | 1 |" in md
        assert "| **Total** | **2** |" in md

    def test_finding_sections_present(self) -> None:
        """Verifie que chaque finding a sa section dans le Markdown."""
        findings = [
            _make_finding(rule_id="strcpy-danger", message="Buffer overflow via strcpy"),
            _make_finding(rule_id="cmd-inject", message="Command injection via system()"),
        ]
        report = _make_report(findings)
        md = generate_markdown_report(report)
        assert "### 1. Buffer overflow via strcpy" in md
        assert "### 2. Command injection via system()" in md
        assert "`strcpy-danger`" in md
        assert "`cmd-inject`" in md

    def test_severity_ordering_in_output(self) -> None:
        """Verifie que les findings sont affiches par severite decroissante."""
        findings = [
            _make_finding(severity=Severity.LOW, message="Low issue"),
            _make_finding(severity=Severity.CRITICAL, message="Critical issue"),
            _make_finding(severity=Severity.MEDIUM, message="Medium issue"),
        ]
        report = _make_report(findings)
        md = generate_markdown_report(report)
        pos_critical = md.index("Critical issue")
        pos_medium = md.index("Medium issue")
        pos_low = md.index("Low issue")
        assert pos_critical < pos_medium < pos_low

    def test_code_block_for_patch(self) -> None:
        """Verifie que le patch est dans un bloc de code diff."""
        findings = [_make_finding(patch="strncpy(buf, src, size);")]
        report = _make_report(findings)
        md = generate_markdown_report(report)
        assert "```diff" in md
        assert "strncpy(buf, src, size);" in md

    def test_explanation_in_output(self) -> None:
        """Verifie que l'explication est incluse dans le rapport."""
        findings = [_make_finding(explanation="Ceci est une explication test.")]
        report = _make_report(findings)
        md = generate_markdown_report(report)
        assert "Ceci est une explication test." in md
        assert "**Explication :**" in md

    def test_empty_report_clean_message(self) -> None:
        """Verifie qu'un rapport vide affiche un message propre."""
        report = _make_report([])
        md = generate_markdown_report(report)
        assert "Aucune vulnerabilite detectee" in md

    def test_cvss_in_output(self) -> None:
        """Verifie que le score CVSS est affiche dans le rapport."""
        findings = [_make_finding(cvss=8.5)]
        report = _make_report(findings)
        md = generate_markdown_report(report)
        assert "CVSS ~8.5" in md


# ---------------------------------------------------------------------------
# Tests generate_json_report
# ---------------------------------------------------------------------------


class TestGenerateJsonReport:
    """Tests pour la fonction generate_json_report."""

    def test_valid_json_output(self) -> None:
        """Verifie que la sortie est un JSON valide et parsable."""
        findings = [_make_finding()]
        report = _make_report(findings)
        raw = generate_json_report(report)
        data = json.loads(raw)
        assert data["repo_path"] == "/test/project"
        assert data["total_files_scanned"] == 42
        assert data["total_findings"] == 1

    def test_findings_sorted_in_json(self) -> None:
        """Verifie que les findings sont tries dans la sortie JSON."""
        findings = [
            _make_finding(severity=Severity.LOW, file="a.c"),
            _make_finding(severity=Severity.CRITICAL, file="a.c"),
        ]
        report = _make_report(findings)
        raw = generate_json_report(report)
        data = json.loads(raw)
        sevs = [f["severity"] for f in data["findings"]]
        assert sevs == ["critical", "low"]

    def test_summary_in_json(self) -> None:
        """Verifie que le resume est inclus dans la sortie JSON."""
        findings = [
            _make_finding(severity=Severity.HIGH),
            _make_finding(severity=Severity.HIGH),
        ]
        report = _make_report(findings)
        raw = generate_json_report(report)
        data = json.loads(raw)
        assert data["summary"]["high"] == 2

    def test_finding_fields_in_json(self) -> None:
        """Verifie que tous les champs d'un finding sont dans le JSON."""
        f = _make_finding()
        report = _make_report([f])
        raw = generate_json_report(report)
        data = json.loads(raw)
        f_json = data["findings"][0]
        assert f_json["rule_id"] == "test-rule"
        assert f_json["cvss_estimate"] == 7.5
        assert f_json["explanation"] == "Explanation text"
        assert f_json["suggested_patch"] == "fixed_code();"

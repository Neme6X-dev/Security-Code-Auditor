"""Generateur de rapports : formate les findings en rapports lisibles (Markdown, JSON)."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from auditor.report.models import AuditReport, Finding, Severity


def generate_markdown_report(report: AuditReport) -> str:
    """Produit un rapport Markdown lisible a partir d'un AuditReport.

    Le rapport contient un en-tete avec la date et le chemin analyse,
    un tableau de synthese par severite, puis chaque finding trie par
    severite decroissante avec le code concerne, l'explication et le
    patch suggere.

    Args:
        report: Rapport d'audit a formater.

    Returns:
        Chaine Markdown complete du rapport.
    """
    lines: list[str] = []

    lines.append("# Rapport d'Audit de Securite")
    lines.append("")
    lines.append(f"**Date :** {report.scan_date.strftime('%Y-%m-%d %H:%M UTC')}")
    lines.append(f"**Repertoire analyse :** `{report.repo_path}`")
    lines.append(f"**Fichiers examines :** {report.total_files_scanned}")
    lines.append("")
    lines.append("---")
    lines.append("")

    lines.append("## Resume")
    lines.append("")
    lines.append("| Severite | Nombre |")
    lines.append("|----------|--------|")

    counts = report.summary
    for label, key in [
        ("Critique", "critical"),
        ("Haute", "high"),
        ("Moyenne", "medium"),
        ("Basse", "low"),
        ("Info", "info"),
    ]:
        lines.append(f"| {label} | {counts.get(key, 0)} |")

    lines.append(f"| **Total** | **{report.total_findings}** |")
    lines.append("")
    lines.append("---")
    lines.append("")

    if report.total_findings == 0:
        lines.append("Aucune vulnerabilite detectee. Le code semble propre.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Findings")
    lines.append("")

    sorted_f = report.sorted_findings()
    for idx, finding in enumerate(sorted_f, start=1):
        lines.extend(_format_finding_markdown(idx, finding))

    return "\n".join(lines)


def generate_json_report(report: AuditReport) -> str:
    """Produit un rapport JSON machine-readable pour integration CI/CD.

    Args:
        report: Rapport d'audit a formater.

    Returns:
        Chaine JSON formatee (indent=2).
    """
    data: dict[str, object] = {
        "repo_path": report.repo_path,
        "scan_date": report.scan_date.isoformat(),
        "total_files_scanned": report.total_files_scanned,
        "total_findings": report.total_findings,
        "summary": report.summary,
        "findings": [f.model_dump() for f in report.sorted_findings()],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Helpers prives
# ---------------------------------------------------------------------------

_SEVERITY_LABELS: dict[Severity, str] = {
    Severity.CRITICAL: "Critique",
    Severity.HIGH: "Haute",
    Severity.MEDIUM: "Moyenne",
    Severity.LOW: "Basse",
    Severity.INFO: "Info",
}


def _format_finding_markdown(index: int, finding: Finding) -> list[str]:
    """Formate un finding unique en lignes Markdown.

    Le titre utilise rule_id (court) plutot que message (long).
    Le message complet est affiche dans le corps sous "**Description :**".

    Args:
        index: Numero d'ordre du finding dans le rapport.
        finding: Finding a formater.

    Returns:
        Liste de lignes Markdown representant le finding.
    """
    lines: list[str] = []
    label = _SEVERITY_LABELS.get(finding.severity, finding.severity.value)

    rule_short = finding.rule_id.rsplit(".", maxsplit=1)[-1] if finding.rule_id else ""
    title = rule_short if rule_short else "Finding sans regle identifiee"

    lines.append(f"### {index}. {title}")
    lines.append("")
    lines.append(f"- **Regle :** `{finding.rule_id}`")
    lines.append(f"- **Severite :** {label} (CVSS ~{finding.cvss_estimate:.1f})")
    lines.append(f"- **Fichier :** `{finding.file}:{finding.line}`")
    lines.append(f"- **Source :** {finding.source}")
    lines.append(f"- **Confiance LLM :** {finding.confidence}")

    if finding.message:
        lines.append("")
        lines.append("**Description :**")
        lines.append("")
        lines.append(finding.message)

    if finding.explanation:
        lines.append("")
        lines.append("**Explication :**")
        lines.append("")
        lines.append(finding.explanation)

    if finding.suggested_patch:
        lines.append("")
        lines.append("**Patch suggere :**")
        lines.append("")
        lines.append("```diff")
        lines.append(finding.suggested_patch)
        lines.append("```")

    lines.append("")
    lines.append("---")
    lines.append("")

    return lines

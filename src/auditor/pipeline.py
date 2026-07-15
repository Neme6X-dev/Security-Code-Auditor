"""Pipeline principal : orchestre les etapes de l'audit de securite."""

from __future__ import annotations

import logging
import pathlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from auditor.ingestion.repo_scanner import scan_repository
from auditor.llm.gemini_client import GeminiClient
from auditor.report.generator import generate_json_report, generate_markdown_report
from auditor.report.models import AuditReport, Finding, Severity
from auditor.static_analysis.cppcheck_runner import run_cppcheck
from auditor.static_analysis.semgrep_runner import run_semgrep

logger = logging.getLogger(__name__)

console = Console()

_RULES_PATH = str(
    pathlib.Path(__file__).resolve().parent.parent.parent / "rules" / "semgrep-c-cpp.yml"
)

_CONTEXT_LINES: int = 10


def run_audit(
    repo_path: str,
    output_format: str = "markdown",
    skip_llm: bool = False,
    rules_path: str | None = None,
) -> AuditReport:
    """Execute le pipeline complet d'audit de securite.

    Etapes :
        1. Scan du depot (repertoire ou fichier) pour collecter les fichiers source C/C++.
        2. Analyse statique (Semgrep + Cppcheck en parallele).
        3. Deduplication des findings (meme fichier + meme ligne + meme regle).
        4. Pour chaque finding unique, analyse contextuelle via Gemini.
        5. Assemblage du rapport et generation dans le format demande.

    Args:
        repo_path: Chemin vers un repertoire ou un fichier C/C++ a auditer.
        output_format: Format de sortie ('markdown' ou 'json').
        skip_llm: Si True, saute l'analyse LLM (utile pour les tests).
        rules_path: Chemin custom vers les regles Semgrep (optionnel).

    Returns:
        AuditReport complet avec les findings merges et analyses.
    """
    effective_rules = rules_path or _RULES_PATH

    console.print(f"[bold cyan]Analyse de[/bold cyan] {repo_path}")

    # --- Etape 1 : Ingestion ---
    console.print("  [dim]Scan du depot...[/dim]")
    files = scan_repository(repo_path)
    console.print(f"  [green]{len(files)}[/green] fichier(s) source detecte(s)")

    if not files:
        console.print("[yellow]Aucun fichier C/C++ trouve.[/yellow]")
        return AuditReport(
            repo_path=repo_path,
            total_files_scanned=0,
            findings=[],
        )

    # --- Etape 2 : Analyse statique (parallele) ---
    console.print("  [dim]Analyse statique (Semgrep + Cppcheck)...[/dim]")
    static_findings = _run_static_analysis(files, effective_rules)
    console.print(
        f"  [green]{len(static_findings)}[/green] finding(s) brut(s) detecte(s)"
    )

    # --- Etape 3 : Deduplication ---
    unique_findings = _deduplicate_findings(static_findings)
    console.print(
        f"  [green]{len(unique_findings)}[/green] finding(s) unique(s) apres deduplication"
    )

    # --- Etape 4 : Analyse LLM ---
    final_findings: list[Finding] = []

    if skip_llm or not unique_findings:
        for raw in unique_findings:
            final_findings.append(_raw_to_finding(raw, explanation="", patch="", confidence="low"))
        if not skip_llm and not unique_findings:
            console.print("[green]Aucun finding a analyser avec Gemini.[/green]")
    else:
        console.print(
            f"  [dim]Analyse LLM de {len(unique_findings)} finding(s) via Gemini...[/dim]"
        )
        final_findings = _run_llm_analysis(files, unique_findings)

    # --- Etape 5 : Assemblage du rapport ---
    report = AuditReport(
        repo_path=repo_path,
        total_files_scanned=len(files),
        findings=final_findings,
    )

    # --- Etape 6 : Generation du rapport ---
    if output_format == "json":
        output = generate_json_report(report)
    else:
        output = generate_markdown_report(report)

    report_path = _write_report(output, output_format, repo_path)
    console.print(f"[bold green]Rapport genere :[/bold green] {report_path}")

    return report


# ---------------------------------------------------------------------------
# Analyse statique
# ---------------------------------------------------------------------------


def _run_static_analysis(
    files: list[pathlib.Path],
    rules_path: str,
) -> list[dict[str, object]]:
    """Lance Semgrep et Cppcheck en parallele et fusionne les résultats.

    Les erreurs d'outils manquants sont silently ignorees (log warning)
    pour ne pas casser le pipeline si un outil n'est pas installe.

    Args:
        files: Fichiers source a analyser.
        rules_path: Chemin vers les regles Semgrep.

    Returns:
        Liste combinee et non dedupliquee de findings bruts.
    """
    all_findings: list[dict[str, object]] = []

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures: dict[str, Any] = {}

        futures["semgrep"] = executor.submit(
            _safe_semgrep, files, rules_path
        )
        futures["cppcheck"] = executor.submit(
            _safe_cppcheck, files
        )

        for name, future in futures.items():
            try:
                result = future.result(timeout=180)
                for f in result:
                    f["source"] = name
                all_findings.extend(result)
            except Exception:
                logger.warning("L'outil %s a echoue", name, exc_info=True)

    return all_findings


def _safe_semgrep(
    files: list[pathlib.Path], rules_path: str
) -> list[dict[str, object]]:
    """Wrapper securise autour de run_semgrep.

    Args:
        files: Fichiers a analyser.
        rules_path: Chemin vers les regles.

    Returns:
        Liste de findings ou liste vide en cas d'erreur.
    """
    try:
        return run_semgrep(files, rules_path)
    except FileNotFoundError as exc:
        logger.warning("Semgrep non disponible : %s", exc)
        return []
    except Exception:
        logger.warning("Semgrep a echoue", exc_info=True)
        return []


def _safe_cppcheck(files: list[pathlib.Path]) -> list[dict[str, object]]:
    """Wrapper securise autour de run_cppcheck.

    Args:
        files: Fichiers a analyser.

    Returns:
        Liste de findings ou liste vide en cas d'erreur.
    """
    try:
        return run_cppcheck(files)
    except FileNotFoundError as exc:
        logger.warning("Cppcheck non disponible : %s", exc)
        return []
    except Exception:
        logger.warning("Cppcheck a echoue", exc_info=True)
        return []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------


def _deduplicate_findings(
    findings: list[dict[str, object]],
) -> list[dict[str, object]]:
    """Supprime les doublons (meme fichier + meme ligne + meme regle).

    En cas de doublon, le finding le plus prioritaire est garde selon
    la regle : semgrep > cppcheck, puis severite la plus elevee.

    Args:
        findings: Liste brute de findings potentiellement dupliques.

    Returns:
        Liste dedupliquee.
    """
    seen: dict[tuple[str, int, str], dict[str, object]] = {}

    severity_rank: dict[str, int] = {
        "critical": 0,
        "error": 0,
        "high": 1,
        "warning": 1,
        "medium": 2,
        "low": 3,
        "info": 4,
    }

    for f in findings:
        key = (
            str(f.get("file", "")),
            int(f.get("line", 0)),
            str(f.get("rule_id", "")),
        )

        if key not in seen:
            seen[key] = f
            continue

        existing = seen[key]
        existing_sev = severity_rank.get(str(existing.get("severity", "")), 5)
        new_sev = severity_rank.get(str(f.get("severity", "")), 5)

        if new_sev < existing_sev:
            seen[key] = f

    return list(seen.values())


# ---------------------------------------------------------------------------
# Analyse LLM
# ---------------------------------------------------------------------------


def _run_llm_analysis(
    files: list[pathlib.Path],
    unique_findings: list[dict[str, object]],
) -> list[Finding]:
    """Analyse chaque finding unique via Gemini et retourne une liste de Finding.

    Affiche une barre de progression Rich pendant l'analyse.

    Args:
        files: Fichiers source (pour extraire les snippets de code).
        unique_findings: Liste dedupliee de findings bruts.

    Returns:
        Liste de Finding modelises avec les reponses Gemini.
    """
    try:
        client = GeminiClient()
    except EnvironmentError as exc:
        logger.error("Impossible d'initialiser Gemini : %s", exc)
        console.print("[red]Gemini non disponible — analyse LLM desactivee.[/red]")
        return [_raw_to_finding(f, explanation="", patch="", confidence="low") for f in unique_findings]

    # Index fichiers -> contenu pour extraction de snippets
    file_contents: dict[str, list[str]] = {}
    for fp in files:
        try:
            file_contents[str(fp)] = fp.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            file_contents[str(fp)] = []

    results: list[Finding] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "Analyse LLM...", total=len(unique_findings)
        )

        for raw in unique_findings:
            filepath = str(raw.get("file", ""))
            line = int(raw.get("line", 0))
            snippet = _extract_snippet(file_contents, filepath, line)

            llm_result = client.analyze_finding(raw, snippet)

            finding = _raw_to_finding(
                raw,
                explanation=str(llm_result.get("explanation", "")),
                patch=str(llm_result.get("suggested_patch", "")),
                confidence=str(llm_result.get("confidence", "low")),
                cvss=float(llm_result.get("severity_cvss_estimate", 0.0)),
            )

            results.append(finding)
            progress.advance(task)

    return results


def _extract_snippet(
    file_contents: dict[str, list[str]],
    filepath: str,
    line: number,
    context: int = _CONTEXT_LINES,
) -> str:
    """Extrait un extrait de code autour d'une ligne donnee.

    Args:
        file_contents: Contenu des fichiers indexe par chemin.
        filepath: Chemin du fichier cible.
        line: Numero de ligne cible (1-indexed).
        context: Nombre de lignes de contexte avant/apres.

    Returns:
        Extrait de code formate avec numeros de ligne.
    """
    lines = file_contents.get(filepath, [])
    if not lines:
        return ""

    start = max(0, line - context - 1)
    end = min(len(lines), line + context)

    snippet_lines: list[str] = []
    for i in range(start, end):
        line_num = i + 1
        marker = ">>>" if line_num == line else "   "
        snippet_lines.append(f"{marker} {line_num:4d}: {lines[i]}")

    return "\n".join(snippet_lines)


# ---------------------------------------------------------------------------
# Conversion raw -> Finding
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "error": Severity.CRITICAL,
    "high": Severity.HIGH,
    "warning": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _raw_to_finding(
    raw: dict[str, object],
    explanation: str = "",
    patch: str = "",
    confidence: str = "low",
    cvss: float | None = None,
) -> Finding:
    """Convertit un dictionnaire brut (static analysis) en modele Finding.

    Si un score CVSS est fourni, la severite est recalculee depuis celui-ci.
    Sinon, la severite brute du finding statique est utilisee.

    Args:
        raw: Dictionnaire brut issu de l'analyse statique.
        explanation: Explication LLM (optionnel).
        patch: Patch suggere LLM (optionnel).
        confidence: Confiance LLM (optionnel).
        cvss: Score CVSS estime par Gemini (optionnel).

    Returns:
        Instance de Finding modelisee.
    """
    raw_sev = str(raw.get("severity", "low")).lower()
    severity = _SEVERITY_MAP.get(raw_sev, Severity.LOW)

    if cvss is not None and cvss > 0.0:
        severity = Severity.from_cvss(cvss)

    return Finding(
        rule_id=str(raw.get("rule_id", "")),
        message=str(raw.get("message", "")),
        severity=severity,
        file=str(raw.get("file", "")),
        line=int(raw.get("line", 0)),
        cvss_estimate=cvss if cvss is not None else 0.0,
        explanation=explanation,
        suggested_patch=patch,
        confidence=confidence,
        source=str(raw.get("source", "unknown")),
    )


# ---------------------------------------------------------------------------
# Ecriture du rapport
# ---------------------------------------------------------------------------


def _write_report(content: str, fmt: str, repo_path: str) -> pathlib.Path:
    """Ecrit le rapport genere dans un fichier.

    Args:
        content: Contenu du rapport genere.
        fmt: Format du rapport ('markdown' ou 'json').
        repo_path: Chemin du repertoire analyse (pour nommer le fichier).

    Returns:
        Chemin du fichier de rapport cree.
    """
    repo_name = pathlib.Path(repo_path).name
    ext = "json" if fmt == "json" else "md"
    filename = f"audit_report_{repo_name}.{ext}"

    report_dir = pathlib.Path.cwd() / "reports"
    report_dir.mkdir(exist_ok=True)

    report_path = report_dir / filename
    report_path.write_text(content, encoding="utf-8")

    return report_path


# Type alias pour mypy
number = int | float

"""Point d'entree CLI de security-code-auditor."""

from __future__ import annotations

import shutil
import sys
import time
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from auditor.pipeline import run_audit

console = Console()

_EXIT_OK: int = 0
_EXIT_VULNERABILITIES: int = 1

_SEMGREP_INSTALL_HINT: str = (
    "Semgrep n'est pas installe. Installez-le avec :\n"
    "  pip install semgrep"
)

_CPPCHECK_INSTALL_HINT: str = (
    "Cppcheck n'est pas installe. Installez-le avec :\n"
    "  - Ubuntu/Debian : sudo apt install cppcheck\n"
    "  - macOS : brew install cppcheck\n"
    "  - Windows : choco install cppcheck"
)


@click.group()
@click.version_option(package_name="security-code-auditor")
def main() -> None:
    """Security Code Auditor — audit de securite C/C++ assiste par IA."""
    pass


@main.command()
@click.argument("repo_path", type=click.Path(exists=True, resolve_path=True))
@click.option(
    "--output",
    "-o",
    type=click.Choice(["markdown", "json"], case_sensitive=False),
    default="markdown",
    show_default=True,
    help="Format du rapport de sortie.",
)
@click.option(
    "--out-file",
    type=click.Path(dir_okay=False, resolve_path=True),
    default=None,
    help="Chemin du fichier de sortie (ecrase le comportement par defaut).",
)
@click.option(
    "--rules-path",
    type=click.Path(exists=True, dir_okay=False, resolve_path=True),
    default=None,
    help="Chemin custom vers les regles Semgrep YAML.",
)
@click.option(
    "--skip-llm",
    is_flag=True,
    default=False,
    help="Ignore l'analyse LLM (Gemini) — analyse statique uniquement.",
)
def scan(
    repo_path: str,
    output: str,
    out_file: str | None,
    rules_path: str | None,
    skip_llm: bool,
) -> None:
    """Lance un audit de securite complet sur REPO_PATH.

    REPO_PATH peut etre un repertoire ou un fichier C/C++.
    Analyse statique (Semgrep + Cppcheck) puis interpretation LLM (Gemini).
    Le code de sortie est non-zero si des vulnerabilites CRITICAL ou HIGH
    sont detectees (utile pour CI/CD).
    """
    _check_tools()

    console.print()
    start = time.monotonic()

    try:
        report = run_audit(
            repo_path=repo_path,
            output_format=output,
            skip_llm=skip_llm,
            rules_path=rules_path,
        )
    except FileNotFoundError as exc:
        console.print(f"[bold red]Erreur :[/bold red] {exc}")
        raise SystemExit(_EXIT_VULNERABILITIES) from exc

    elapsed = time.monotonic() - start

    if out_file:
        _write_to_custom_path(report, out_file, output)

    _print_summary(report, elapsed)

    has_critical_or_high = any(
        f.severity.value in ("critical", "high") for f in report.findings
    )
    raise SystemExit(_EXIT_VULNERABILITIES if has_critical_or_high else _EXIT_OK)


# ---------------------------------------------------------------------------
# Helpers prives
# ---------------------------------------------------------------------------


def _check_tools() -> None:
    """Verifie la presence de Semgrep et Cppcheck dans le PATH.

    Affiche des avertissements si l'un des deux est manquant mais ne
    bloque pas l'execution. Les deux outils sont optionnels
    individuellement.
    """
    if shutil.which("semgrep") is None:
        console.print(f"[yellow]Attention :[/yellow] {_SEMGREP_INSTALL_HINT}")

    if shutil.which("cppcheck") is None:
        console.print(f"[yellow]Attention :[/yellow] {_CPPCHECK_INSTALL_HINT}")


def _print_summary(report: object, elapsed: float) -> None:
    """Affiche un tableau Rich colore avec les compteurs par severite.

    Args:
        report: Instance d'AuditReport (type object pour eviter l'import circulaire).
        elapsed: Temps d'execution en secondes.
    """
    from auditor.report.models import AuditReport

    assert isinstance(report, AuditReport)

    table = Table(title="Resultats de l'audit", show_lines=True)
    table.add_column("Severite", style="bold", justify="left")
    table.add_column("Nombre", justify="right")

    counts = report.summary
    _add_row(table, "Critique", counts.get("critical", 0), "bold red")
    _add_row(table, "Haute", counts.get("high", 0), "red")
    _add_row(table, "Moyenne", counts.get("medium", 0), "yellow")
    _add_row(table, "Basse", counts.get("low", 0), "green")
    _add_row(table, "Info", counts.get("info", 0), "dim")
    _add_row(table, "Total", report.total_findings, "bold")

    console.print()
    console.print(table)
    console.print()
    console.print(f"Fichiers analyses : {report.total_files_scanned}")
    console.print(f"Temps d'execution : {elapsed:.1f}s")

    if report.total_findings == 0:
        console.print("[bold green]Aucune vulnerabilite detectee.[/bold green]")
    elif any(f.severity.value in ("critical", "high") for f in report.findings):
        console.print(
            "[bold red]Vulnerabilites critiques/hautes detectees — "
            "considerez un code de sortie non-zero.[/bold red]"
        )


def _add_row(table: Table, label: str, count: int, style: str) -> None:
    """Ajoute une ligne coloree au tableau Rich.

    Args:
        table: Instance de Table Rich.
        label: Libelle de la severite.
        count: Nombre de findings.
        style: Style Rich a appliquer.
    """
    color = ""
    reset = ""
    if style != "dim":
        color = f"[{style}]"
        reset = "[/]"
    else:
        color = "[dim]"
        reset = "[/dim]"

    table.add_row(f"{color}{label}{reset}", f"{color}{count}{reset}")


def _write_to_custom_path(report: object, out_file: str, fmt: str) -> None:
    """Ecrit le rapport dans le fichier specifie par --out-file.

    Args:
        report: Instance d'AuditReport.
        out_file: Chemin de sortie.
        fmt: Format du rapport ('markdown' ou 'json').
    """
    from auditor.report.generator import generate_json_report, generate_markdown_report
    from auditor.report.models import AuditReport

    assert isinstance(report, AuditReport)

    if fmt == "json":
        content = generate_json_report(report)
    else:
        content = generate_markdown_report(report)

    Path(out_file).parent.mkdir(parents=True, exist_ok=True)
    Path(out_file).write_text(content, encoding="utf-8")
    console.print(f"[bold green]Rapport ecrit dans :[/bold green] {out_file}")

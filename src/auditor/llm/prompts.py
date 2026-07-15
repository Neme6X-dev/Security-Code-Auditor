"""Prompts : construction des prompts envoyes au modele Gemini."""

from __future__ import annotations


def build_analysis_prompt(finding: dict[str, object], code_snippet: str) -> str:
    """Construit le prompt d'analyse de securite envoye a Gemini.

    Le prompt positionne le modele en expert securite C/C++ et demande
    une reponse JSON structuree strictement conforme au schema defini.

    Args:
        finding: Dictionnaire normalise representant le finding detecte.
            Cles attendues : rule_id, message, severity, file, line.
        code_snippet: Extrait de code source contenant la ligne concernee
            (+/- 10 lignes de contexte).

    Returns:
        Chaine de caractere contenant le prompt complet (systeme + utilisateur).
    """
    rule_id = finding.get("rule_id", "unknown")
    message = finding.get("message", "")
    severity = finding.get("severity", "unknown")
    filepath = finding.get("file", "")
    line = finding.get("line", 0)

    system_prompt = (
        "Tu es un expert en securite informatique specialise en C/C++. "
        "Tu maîtrises les CWE, OWASP et le scoring CVSS. "
        "Tu analyses des vulnerabilites de securite detectees par des outils "
        "d'analyse statique et tu fournis des corrections precisees.\n\n"
        "CONTRAINTES STRICTES :\n"
        "- Reponds UNIQUEMENT avec un JSON valide, aucun texte hors JSON.\n"
        "- Ne jamais inventer un CWE si le finding est ambigu : "
        "utilise confidence='low' et explique l'ambiguite.\n"
        "- Fournis un patch MINIMAL et sur, jamais une reecriture complete du fichier.\n"
        "- Toute l'explication doit etre en francais, a destination d'un etudiant avance.\n"
        "- Ne jamais inclure de vraie cle API ou secret dans tes reponses."
    )

    user_prompt = (
        "Analyse la vulnerabilite de securite suivante et fournis "
        "une reponse JSON strictement conforme au schema demande.\n\n"
        "## Finding detecte\n"
        f"- Regle : {rule_id}\n"
        f"- Description : {message}\n"
        f"- Severite : {severity}\n"
        f"- Fichier : {filepath}\n"
        f"- Ligne : {line}\n\n"
        "## Extrait de code\n"
        f"```c\n{code_snippet}\n```\n\n"
        "## Schema de reponse attendu (JSON)\n"
        "{\n"
        '  "explanation": "<string: explication en francais, niveau etudiant avance>",\n'
        '  "severity_cvss_estimate": <float 0.0-10.0>,\n'
        '  "suggested_patch": "<string: snippet de code corrige>",\n'
        '  "confidence": "<high|medium|low>"\n'
        "}"
    )

    return f"{system_prompt}\n\n---\n\n{user_prompt}"

# security-code-auditor

Analyse de securite automatisee du code source C/C++ combinant analyse statique (Semgrep, Cppcheck) et Intelligence Artificielle (Gemini) pour detecter les vulnerabilites et produire des rapports actionnables.

## Prerequis

| Composant | Version | Installation |
|-----------|---------|-------------|
| Python | 3.11+ | [python.org](https://www.python.org/downloads/) |
| Semgrep | dernier | `pip install semgrep` |
| Cppcheck | dernier | `sudo apt install cppcheck` (Linux) / `brew install cppcheck` (macOS) / `choco install cppcheck` (Windows) |
| Cle API Gemini | — | [Google AI Studio](https://aistudio.google.com/apikey) |

> **Note :** Semgrep et Cppcheck sont optionnels individuellement. Le pipeline fonctionne avec un seul des deux, mais les deux sont recommandes pour une couverture maximale.

## Installation

```bash
# Cloner le depot
git clone https://github.com/votre-org/security-code-auditor.git
cd security-code-auditor

# Installer en mode editable
pip install -e ".[dev]"

# Configurer la cle API
cp .env.example .env
# Editez .env et ajoutez votre cle API Gemini
```

## Utilisation

### Commande de base

```bash
# Audit complet d'un depot
auditor scan /chemin/vers/votre/projet

# Audit avec sortie JSON (pour CI/CD)
auditor scan /chemin/vers/votre/projet --output json

# Sauvegarder le rapport dans un fichier specifique
auditor scan ./mon-projet --output markdown --out-file rapport.md

# Analyse statique uniquement (sans Gemini)
auditor scan ./mon-projet --skip-llm

# Utiliser des regles Semgrep personnalisees
auditor scan ./mon-projet --rules-path ./mes-regles.yml
```

### Aide

```bash
auditor --help
auditor scan --help
```

### Codes de sortie

| Code | Signification |
|------|---------------|
| 0 | Aucune vulnerabilite critique/haute detectee |
| 1 | Au moins une vulnerabilite CRITICAL ou HIGH detectee |

### Exemple de sortie

```
Analyse de ./mon-projet
  12 fichier(s) source detecte(s)
  8 finding(s) brut(s) detecte(s)
  5 finding(s) unique(s) apres deduplication

┌─────────────┬────────┐
│ Severite    │ Nombre │
├─────────────┼────────┤
│ Critique    │      1 │
│ Haute       │      2 │
│ Moyenne     │      2 │
│ Basse       │      0 │
│ Info        │      0 │
│ Total       │      5 │
└─────────────┴────────┘

Fichiers analyses : 12
Temps d'execution : 14.2s
```

## Developpement

```bash
# Installer les dependances de dev
pip install -e ".[dev]"

# Lancer les tests
pytest tests/ -v
```

## Build en binaire

Un script est fourni pour packaging via PyInstaller :

```bash
pip install pyinstaller
./scripts/build_binary.sh
```

Le binaire genere se trouve dans `dist/security-auditor`.

> **Important :** Le binaire embarque uniquement le code Python. Semgrep et Cppcheck restent des dependances systeme externes qui doivent etre installees separement sur la machine cible.

## Architecture

```
src/auditor/
├── cli.py                          # CLI Click (point d'entree)
├── config.py                       # Chargement GEMINI_API_KEY
├── pipeline.py                     # Orchestrateur run_audit()
├── ingestion/
│   └── repo_scanner.py             # Scan recursif fichiers C/C++
├── static_analysis/
│   ├── semgrep_runner.py           # Wrapper Semgrep (JSON)
│   └── cppcheck_runner.py          # Wrapper Cppcheck (XML)
├── llm/
│   ├── gemini_client.py            # Client Gemini (JSON structure)
│   └── prompts.py                  # Templates de prompts
└── report/
    ├── models.py                   # Severity, Finding, AuditReport
    └── generator.py                # Markdown + JSON reports
```

## Licence

MIT

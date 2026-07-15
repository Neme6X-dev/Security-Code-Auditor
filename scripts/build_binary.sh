#!/usr/bin/env bash
set -euo pipefail

# build_binary.sh
# Construit un binaire Python distribuable via PyInstaller.
#
# Usage :
#   ./scripts/build_binary.sh
#
# Prérequis :
#   pip install pyinstaller
#
# NOTE : Ce binaire embarque uniquement le code Python.
# Semgrep et Cppcheck restent des dépendances SYSTÈME externes
# qui doivent être installées séparément sur la machine cible.

echo "=== Construction du binaire security-code-auditor ==="

pyinstaller \
    --onefile \
    --name security-auditor \
    --add-data "rules:rules" \
    src/auditor/cli.py

echo ""
echo "=== Binaire créé dans dist/security-auditor ==="
echo ""
echo "IMPORTANT : Ce binaire ne contient que le code Python."
echo "Semgrep et Cppcheck doivent être installés séparément :"
echo "  - pip install semgrep"
echo "  - sudo apt install cppcheck  (ou brew/choco selon l'OS)"
echo ""
echo "Usage :"
echo "  ./dist/security-auditor scan /chemin/vers/projet"

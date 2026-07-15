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

echo "=== Construction du binaire security-auditor ==="

pyinstaller \
    --onefile \
    --name security-auditor \
    --add-data "rules:rules" \
    src/auditor/cli.py

echo "=== Binaire créé dans dist/security-auditor ==="

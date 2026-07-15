"""Scanner de depot : parcourt un repertoire ou un fichier et extrait les fichiers source pertinent."""

from __future__ import annotations

import os
from pathlib import Path

SUPPORTED_EXTENSIONS: set[str] = {".c", ".cpp", ".h", ".hpp", ".cc"}

EXCLUDED_DIRS: set[str] = {".git", "build", "node_modules", "vendor"}


def scan_repository(path: str | Path) -> list[Path]:
    """Parcourt un chemin (repertoire ou fichier) et retourne les fichiers C/C++.

    Si le chemin est un fichier, verifie simplement son extension.
    Si c'est un repertoire, le parcourt recursivement en ignorant
    les dossiers exclus (.git, build, node_modules, vendor).

    Args:
        path: Chemin vers un repertoire ou un fichier C/C++.

    Returns:
        Liste triee des fichiers dont l'extension est supportee.

    Raises:
        FileNotFoundError: Si le chemin n'existe pas.
        ValueError: Si le chemin est un fichier avec une extension non supportee.
    """
    target = Path(path)

    if not target.exists():
        raise FileNotFoundError(
            f"Le chemin '{target}' n'existe pas."
        )

    if target.is_file():
        if target.suffix.lower() not in SUPPORTED_EXTENSIONS:
            raise ValueError(
                f"Le fichier '{target.name}' n'est pas un fichier C/C++ "
                f"(extension non supportee)."
            )
        return [target.resolve()]

    if not target.is_dir():
        raise FileNotFoundError(
            f"Le chemin '{target}' n'est ni un fichier ni un repertoire."
        )

    found_files: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = [
            d for d in dirnames if d not in EXCLUDED_DIRS
        ]

        for filename in filenames:
            file_path = Path(dirpath) / filename
            if file_path.suffix.lower() in SUPPORTED_EXTENSIONS:
                found_files.append(file_path)

    found_files.sort()
    return found_files

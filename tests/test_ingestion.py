"""Tests pour le module d'ingestion (scan_repository)."""

from __future__ import annotations

from pathlib import Path

import pytest

from auditor.ingestion.repo_scanner import scan_repository

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestScanRepository:
    """Tests pour la fonction scan_repository."""

    def test_finds_c_files_in_fixture_dir(self) -> None:
        """Verifie que le scanner detecte vulnerable_sample.c dans fixtures/."""
        results = scan_repository(FIXTURES_DIR)
        names = [f.name for f in results]
        assert "vulnerable_sample.c" in names

    def test_returns_only_supported_extensions(self, tmp_path: Path) -> None:
        """Verifie que seuls les fichiers .c/.cpp/.h/.hpp/.cc sont retournes."""
        (tmp_path / "good.c").write_text("int x;")
        (tmp_path / "good.cpp").write_text("int x;")
        (tmp_path / "good.h").write_text("#pragma once")
        (tmp_path / "good.hpp").write_text("#pragma once")
        (tmp_path / "good.cc").write_text("int x;")
        (tmp_path / "bad.py").write_text("x = 1")
        (tmp_path / "bad.txt").write_text("hello")

        results = scan_repository(tmp_path)
        extensions = {f.suffix for f in results}
        assert extensions <= {".c", ".cpp", ".h", ".hpp", ".cc"}

    def test_excludes_git_directory(self, tmp_path: Path) -> None:
        """Verifie que le repertoire .git/ est ignore."""
        (tmp_path / "src.c").write_text("int main() {}")
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "secret.c").write_text("should be ignored")

        results = scan_repository(tmp_path)
        assert all(".git" not in str(f) for f in results)

    def test_excludes_build_directory(self, tmp_path: Path) -> None:
        """Verifie que le repertoire build/ est ignore."""
        (tmp_path / "main.c").write_text("int main() {}")
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        (build_dir / "generated.c").write_text("should be ignored")

        results = scan_repository(tmp_path)
        assert all("build" not in f.parts for f in results)

    def test_excludes_node_modules(self, tmp_path: Path) -> None:
        """Verifie que le repertoire node_modules/ est ignore."""
        (tmp_path / "main.c").write_text("int main() {}")
        nm_dir = tmp_path / "node_modules"
        nm_dir.mkdir()
        (nm_dir / "dep.c").write_text("should be ignored")

        results = scan_repository(tmp_path)
        assert all("node_modules" not in f.parts for f in results)

    def test_excludes_vendor_directory(self, tmp_path: Path) -> None:
        """Verifie que le repertoire vendor/ est ignore."""
        (tmp_path / "main.c").write_text("int main() {}")
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        (vendor_dir / "lib.c").write_text("should be ignored")

        results = scan_repository(tmp_path)
        assert all("vendor" not in f.parts for f in results)

    def test_recursive_scan(self, tmp_path: Path) -> None:
        """Verifie que les sous-repertoires non exclus sont explores."""
        sub = tmp_path / "src" / "nested"
        sub.mkdir(parents=True)
        (sub / "deep.c").write_text("int x;")
        (tmp_path / "root.c").write_text("int y;")

        results = scan_repository(tmp_path)
        names = {f.name for f in results}
        assert "deep.c" in names
        assert "root.c" in names

    def test_empty_directory_returns_empty_list(self, tmp_path: Path) -> None:
        """Verifie qu'un repertoire vide retourne une liste vide."""
        results = scan_repository(tmp_path)
        assert results == []

    def test_nonexistent_path_raises(self) -> None:
        """Verifie qu'une erreur est levee si le chemin n'existe pas."""
        with pytest.raises(FileNotFoundError, match="n'existe pas"):
            scan_repository("/nonexistent/path/abc123")

    def test_file_instead_of_directory_is_accepted(self, tmp_path: Path) -> None:
        """Verifie qu'un fichier C/C++ est accepte directement."""
        filepath = tmp_path / "not_a_dir.c"
        filepath.write_text("int x;")
        results = scan_repository(filepath)
        assert len(results) == 1
        assert results[0].name == "not_a_dir.c"

    def test_results_are_sorted(self, tmp_path: Path) -> None:
        """Verifie que les resultats sont tries par chemin."""
        (tmp_path / "z_last.c").write_text("int z;")
        sub = tmp_path / "a_first"
        sub.mkdir()
        (sub / "a_first.c").write_text("int a;")

        results = scan_repository(tmp_path)
        assert results == sorted(results)

    def test_results_are_absolute_paths(self, tmp_path: Path) -> None:
        """Verifie que les chemins retournes sont absolus."""
        (tmp_path / "main.c").write_text("int main() {}")
        results = scan_repository(tmp_path)
        assert all(f.is_absolute() for f in results)

    def test_scan_single_c_file(self, tmp_path: Path) -> None:
        """Verifie qu'un seul fichier .c est accepte."""
        filepath = tmp_path / "test.c"
        filepath.write_text("int main() {}")
        results = scan_repository(filepath)
        assert len(results) == 1
        assert results[0].name == "test.c"

    def test_scan_single_cpp_file(self, tmp_path: Path) -> None:
        """Verifie qu'un seul fichier .cpp est accepte."""
        filepath = tmp_path / "test.cpp"
        filepath.write_text("int main() {}")
        results = scan_repository(filepath)
        assert len(results) == 1
        assert results[0].name == "test.cpp"

    def test_scan_single_header_file(self, tmp_path: Path) -> None:
        """Verifie qu'un seul fichier .h est accepte."""
        filepath = tmp_path / "header.h"
        filepath.write_text("#pragma once")
        results = scan_repository(filepath)
        assert len(results) == 1
        assert results[0].name == "header.h"

    def test_scan_single_unsupported_file_raises(self, tmp_path: Path) -> None:
        """Verifie qu'une erreur est levee pour un fichier non supporte."""
        filepath = tmp_path / "test.py"
        filepath.write_text("print('hello')")
        with pytest.raises(ValueError, match="extension non supportee"):
            scan_repository(filepath)

    def test_scan_nonexistent_file_raises(self) -> None:
        """Verifie qu'une erreur est levee si le fichier n'existe pas."""
        with pytest.raises(FileNotFoundError, match="n'existe pas"):
            scan_repository("/nonexistent/file.c")

    def test_scan_single_file_returns_resolved_path(self, tmp_path: Path) -> None:
        """Verifie que le chemin du fichier est resolu (absolu)."""
        filepath = tmp_path / "test.c"
        filepath.write_text("int main() {}")
        results = scan_repository(filepath)
        assert results[0].is_absolute()

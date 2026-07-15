"""Tests pour les modules d'analyse statique (Semgrep, Cppcheck)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from auditor.static_analysis.cppcheck_runner import (
    _normalize_severity,
    _parse_cppcheck_output,
    run_cppcheck,
)
from auditor.static_analysis.semgrep_runner import (
    _parse_semgrep_output,
    run_semgrep,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"
VULNERABLE_SAMPLE = FIXTURES_DIR / "vulnerable_sample.c"
RULES_PATH = Path(__file__).parent.parent / "rules" / "semgrep-c-cpp.yml"


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------


class TestRunSemgrep:
    """Tests pour la fonction run_semgrep."""

    def test_raises_if_binary_missing(self, tmp_path: Path) -> None:
        """Verifie qu'une erreur est levee si semgrep n'est pas dans le PATH."""
        fake_file = tmp_path / "test.c"
        fake_file.write_text("int main() {}")

        with patch("auditor.static_analysis.semgrep_runner.shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="Semgrep non trouve"):
                run_semgrep([fake_file], RULES_PATH)

    def test_raises_if_rules_file_missing(self, tmp_path: Path) -> None:
        """Verifie qu'une erreur est levee si le fichier de regles est introuvable."""
        fake_file = tmp_path / "test.c"
        fake_file.write_text("int main() {}")

        with patch(
            "auditor.static_analysis.semgrep_runner.shutil.which",
            return_value="/usr/bin/semgrep",
        ):
            with pytest.raises(FileNotFoundError, match="regles introuvable"):
                run_semgrep([fake_file], "/nonexistent/rules.yml")

    def test_parses_valid_semgrep_json(self) -> None:
        """Verifie le parsing d'une sortie JSON valide de Semgrep."""
        json_output = """{
            "results": [
                {
                    "check_id": "dangerous-strcpy",
                    "path": "src/main.c",
                    "start": {"line": 42},
                    "extra": {
                        "message": "strcpy utilise sans bornage",
                        "severity": "ERROR"
                    }
                },
                {
                    "check_id": "command-injection-system",
                    "path": "src/exec.c",
                    "start": {"line": 15},
                    "extra": {
                        "message": "Appel a system()",
                        "severity": "ERROR"
                    }
                }
            ]
        }"""
        findings = _parse_semgrep_output(json_output)
        assert len(findings) == 2
        assert findings[0]["rule_id"] == "dangerous-strcpy"
        assert findings[0]["file"] == "src/main.c"
        assert findings[0]["line"] == 42
        assert findings[0]["severity"] == "ERROR"
        assert findings[1]["rule_id"] == "command-injection-system"

    def test_parse_empty_output(self) -> None:
        """Verifie qu'une sortie vide retourne une liste vide."""
        assert _parse_semgrep_output("") == []
        assert _parse_semgrep_output("   ") == []

    def test_parse_no_results(self) -> None:
        """Verifie le parsing d'un JSON sans results."""
        assert _parse_semgrep_output('{"results": []}') == []

    def test_end_to_end_with_mock(self) -> None:
        """Verifie le flux complet avec subprocess mocké."""
        fake_json = """{
            "results": [
                {
                    "check_id": "dangerous-strcpy",
                    "path": "test.c",
                    "start": {"line": 10},
                    "extra": {"message": "strcpy", "severity": "ERROR"}
                }
            ]
        }"""
        mock_result = MagicMock()
        mock_result.stdout = fake_json
        mock_result.returncode = 0

        fake_file = Path("test.c")

        with (
            patch(
                "auditor.static_analysis.semgrep_runner.shutil.which",
                return_value="/usr/bin/semgrep",
            ),
            patch(
                "auditor.static_analysis.semgrep_runner.subprocess.run",
                return_value=mock_result,
            ),
            patch.object(Path, "exists", return_value=True),
        ):
            findings = run_semgrep([fake_file], "rules.yml")

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "dangerous-strcpy"


# ---------------------------------------------------------------------------
# Cppcheck
# ---------------------------------------------------------------------------


class TestRunCppcheck:
    """Tests pour la fonction run_cppcheck."""

    def test_raises_if_binary_missing(self, tmp_path: Path) -> None:
        """Verifie qu'une erreur est levee si cppcheck n'est pas dans le PATH."""
        fake_file = tmp_path / "test.c"
        fake_file.write_text("int main() {}")

        with patch("auditor.static_analysis.cppcheck_runner.shutil.which", return_value=None):
            with pytest.raises(FileNotFoundError, match="Cppcheck non trouve"):
                run_cppcheck([fake_file])

    def test_parses_valid_cppcheck_xml(self) -> None:
        """Verifie le parsing d'une sortie XML valide de Cppcheck."""
        xml_output = """<?xml version="1.0" encoding="UTF-8"?>
        <results>
            <error id="bufferAccessOutOfBounds"
                   severity="error"
                   msg="Possible buffer overflow"
                   verbose="Buffer is accessed out of bounds"
                   file="src/main.c"
                   line="42"/>
            <error id="memleak"
                   severity="warning"
                   msg="Memory leak"
                   verbose="Memory leak: data"
                   file="src/utils.c"
                   line="87"/>
        </results>"""
        findings = _parse_cppcheck_output(xml_output)
        assert len(findings) == 2
        assert findings[0]["rule_id"] == "bufferAccessOutOfBounds"
        assert findings[0]["file"] == "src/main.c"
        assert findings[0]["line"] == 42
        assert findings[0]["severity"] == "critical"
        assert findings[1]["severity"] == "high"

    def test_parse_empty_output(self) -> None:
        """Verifie qu'une sortie vide retourne une liste vide."""
        assert _parse_cppcheck_output("") == []
        assert _parse_cppcheck_output("   ") == []

    def test_parse_no_errors(self) -> None:
        """Verifie le parsing d'un XML sans elements error."""
        xml_output = '<?xml version="1.0"?><results></results>'
        assert _parse_cppcheck_output(xml_output) == []

    def test_end_to_end_with_mock(self) -> None:
        """Verifie le flux complet avec subprocess mocké."""
        fake_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <results>
            <error id="uninitvar"
                   severity="error"
                   msg="Uninitialized variable"
                   verbose="Variable 'x' is uninitialized"
                   file="test.c"
                   line="5"/>
        </results>"""
        mock_result = MagicMock()
        mock_result.stderr = fake_xml
        mock_result.returncode = 0

        fake_file = Path("test.c")

        with (
            patch(
                "auditor.static_analysis.cppcheck_runner.shutil.which",
                return_value="/usr/bin/cppcheck",
            ),
            patch(
                "auditor.static_analysis.cppcheck_runner.subprocess.run",
                return_value=mock_result,
            ),
        ):
            findings = run_cppcheck([fake_file])

        assert len(findings) == 1
        assert findings[0]["rule_id"] == "uninitvar"


class TestNormalizeSeverity:
    """Tests pour la fonction _normalize_severity."""

    def test_error_maps_to_critical(self) -> None:
        assert _normalize_severity("error") == "critical"

    def test_warning_maps_to_high(self) -> None:
        assert _normalize_severity("warning") == "high"

    def test_style_maps_to_low(self) -> None:
        assert _normalize_severity("style") == "low"

    def test_performance_maps_to_medium(self) -> None:
        assert _normalize_severity("performance") == "medium"

    def test_unknown_defaults_to_low(self) -> None:
        assert _normalize_severity("unknown") == "low"

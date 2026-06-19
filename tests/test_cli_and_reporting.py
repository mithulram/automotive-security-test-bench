import json
import tempfile
import unittest
from pathlib import Path

from automotive_security_bench.cli import main


class CliAndReportingTests(unittest.TestCase):
    def _write_input(self, directory: Path, *, vulnerability: str = "Unauthenticated <ECU> route") -> Path:
        path = directory / "risks.json"
        path.write_text(
            json.dumps(
                {
                    "risks": [
                        {
                            "id": "ASB-001",
                            "asset": "Gateway",
                            "vulnerability": vulnerability,
                            "likelihood": 4,
                            "impact": 5,
                            "threat_categories": ["authentication", "tampering"],
                            "existing_controls": [],
                        }
                    ]
                }
            ),
            encoding="utf-8",
        )
        return path

    def test_cli_writes_json_and_html_reports(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            input_path = self._write_input(directory)
            json_path = directory / "out" / "assessment.json"
            html_path = directory / "out" / "assessment.html"
            result = main(
                [
                    "assess",
                    "--input",
                    str(input_path),
                    "--json-out",
                    str(json_path),
                    "--html-out",
                    str(html_path),
                ]
            )
            self.assertEqual(result, 0)
            report = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertEqual(report["summary"]["critical_count"], 1)
            html = html_path.read_text(encoding="utf-8")
            self.assertIn("Automotive Security Assessment", html)
            self.assertIn("Unauthenticated &lt;ECU&gt; route", html)

    def test_policy_gate_returns_two_for_high_risk(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            input_path = self._write_input(Path(temp_dir))
            result = main(["assess", "--input", str(input_path), "--fail-on", "high"])
            self.assertEqual(result, 2)

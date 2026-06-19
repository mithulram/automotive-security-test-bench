import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from automotive_security_bench.assessment import assess_risks
from automotive_security_bench.cli import main
from automotive_security_bench.domain import Risk
from automotive_security_bench.reporting import write_html_report, write_json_report


class UnmappedThreatCategoryTests(unittest.TestCase):
    def test_mixed_known_and_unknown_categories_are_surfaced_in_json(self):
        risks = (
            Risk(
                "ASB-MIXED",
                "Gateway",
                "Example",
                3,
                3,
                ("authentication", "side-channel", "tampering"),
            ),
        )
        assessment = assess_risks(risks)
        report = assessment.to_dict()

        self.assertEqual(report["summary"]["unmapped_threat_categories"], ["side-channel"])
        self.assertEqual(report["risks"][0]["unmapped_threat_categories"], ["side-channel"])
        self.assertTrue(any("side-channel" in warning for warning in report["warnings"]))
        self.assertTrue(any("manual" in warning.lower() for warning in report["warnings"]))
        self.assertEqual(
            [control["id"] for control in report["risks"][0]["recommended_controls"]],
            ["access-control", "message-integrity", "freshness-checks"],
        )

    def test_case_normalization_treats_known_categories_as_mapped(self):
        risks = (
            Risk(
                "ASB-CASE",
                "Gateway",
                "Example",
                2,
                2,
                ("TAMPERING", "Authentication"),
            ),
        )
        assessment = assess_risks(risks)
        report = assessment.to_dict()

        self.assertEqual(report["summary"]["unmapped_threat_categories"], [])
        self.assertEqual(report["risks"][0]["unmapped_threat_categories"], [])
        self.assertEqual(report["warnings"], [])
        self.assertEqual(
            [control["id"] for control in report["risks"][0]["recommended_controls"]],
            ["message-integrity", "freshness-checks", "access-control"],
        )

    def test_cli_prints_unmapped_category_warning(self):
        payload = {
            "risks": [
                {
                    "id": "ASB-UNKNOWN",
                    "asset": "Gateway",
                    "vulnerability": "Example",
                    "likelihood": 2,
                    "impact": 2,
                    "threat_categories": ["tampering", "supply-chain"],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            directory = Path(temp_dir)
            input_path = directory / "risks.json"
            input_path.write_text(json.dumps(payload),encoding="utf-8")
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                result = main(["assess", "--input", str(input_path)])
            output = buffer.getvalue()

        self.assertEqual(result, 0)
        self.assertIn("supply-chain", output)
        self.assertRegex(output, r"(?i)manual.*review|unmapped")

    def test_html_report_surfaces_unmapped_category_warning(self):
        risks = (
            Risk(
                "ASB-HTML",
                "Gateway",
                "Example",
                2,
                2,
                ("replay", "zero-day"),
            ),
        )
        assessment = assess_risks(risks)
        with tempfile.TemporaryDirectory() as temp_dir:
            html_path = Path(temp_dir) / "assessment.html"
            write_html_report(assessment, html_path)
            html = html_path.read_text(encoding="utf-8")

        self.assertIn("zero-day", html)
        self.assertRegex(html, r"(?i)manual.*review|unmapped")

    def test_json_report_includes_unmapped_field(self):
        risks = (
            Risk(
                "ASB-JSON",
                "Gateway",
                "Example",
                2,
                2,
                ("unknown-threat",),
            ),
        )
        assessment = assess_risks(risks)
        with tempfile.TemporaryDirectory() as temp_dir:
            json_path = Path(temp_dir) / "assessment.json"
            write_json_report(assessment, json_path)
            report = json.loads(json_path.read_text(encoding="utf-8"))

        self.assertEqual(report["summary"]["unmapped_threat_categories"], ["unknown-threat"])
        self.assertEqual(report["risks"][0]["unmapped_threat_categories"], ["unknown-threat"])
        self.assertTrue(report["warnings"])

import json
import tempfile
import unittest
from pathlib import Path

from automotive_security_bench.assessment import assess_risks, load_risks
from automotive_security_bench.domain import Risk, RiskLevel, risk_level


class RiskLevelTests(unittest.TestCase):
    def test_score_boundaries_map_to_expected_levels(self):
        self.assertEqual(risk_level(5), RiskLevel.LOW)
        self.assertEqual(risk_level(6), RiskLevel.MEDIUM)
        self.assertEqual(risk_level(12), RiskLevel.HIGH)
        self.assertEqual(risk_level(20), RiskLevel.CRITICAL)

    def test_rejects_out_of_range_score_components(self):
        with self.assertRaisesRegex(ValueError, "likelihood"):
            Risk(
                identifier="ASB-X",
                asset="Gateway",
                vulnerability="Example",
                likelihood=0,
                impact=5,
                threat_categories=("tampering",),
            )


class AssessmentTests(unittest.TestCase):
    def test_prioritises_by_score_and_maps_controls(self):
        risks = (
            Risk("ASB-LOW", "Asset", "Low impact", 1, 3, ("authentication",)),
            Risk("ASB-HIGH", "Asset", "High impact", 4, 4, ("denial-of-service",)),
        )
        assessment = assess_risks(risks)
        self.assertEqual([item.risk.identifier for item in assessment.risks], ["ASB-HIGH", "ASB-LOW"])
        self.assertEqual(assessment.risks[0].level, RiskLevel.HIGH)
        self.assertEqual(
            [control.identifier for control in assessment.risks[0].recommended_controls],
            ["rate-limiting", "network-segmentation", "fail-safe-mode"],
        )

    def test_loader_rejects_duplicate_identifiers(self):
        payload = {
            "risks": [
                {
                    "id": "ASB-001",
                    "asset": "Gateway",
                    "vulnerability": "Example",
                    "likelihood": 2,
                    "impact": 2,
                    "threat_categories": ["tampering"],
                },
                {
                    "id": "ASB-001",
                    "asset": "ECU",
                    "vulnerability": "Example",
                    "likelihood": 2,
                    "impact": 2,
                    "threat_categories": ["update"],
                },
            ]
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "duplicate.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "unique"):
                load_risks(path)

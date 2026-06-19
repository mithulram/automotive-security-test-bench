"""Risk loading, assessment, prioritisation, and JSON-ready output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .controls import Control, controls_for_categories, unmapped_categories
from .domain import Risk, RiskLevel


@dataclass(frozen=True)
class AssessedRisk:
    """A risk plus the controls inferred from its stated threat categories."""

    risk: Risk
    recommended_controls: tuple[Control, ...]
    unmapped_threat_categories: tuple[str, ...]

    @property
    def score(self) -> int:
        return self.risk.score

    @property
    def level(self) -> RiskLevel:
        return self.risk.level


@dataclass(frozen=True)
class Assessment:
    """A deterministic assessment report that can be rendered to JSON or HTML."""

    risks: tuple[AssessedRisk, ...]

    @property
    def level_counts(self) -> dict[RiskLevel, int]:
        return {level: sum(item.level is level for item in self.risks) for level in RiskLevel}

    @property
    def recommended_control_count(self) -> int:
        return len(
            {
                control.identifier
                for assessed_risk in self.risks
                for control in assessed_risk.recommended_controls
            }
        )

    @property
    def unmapped_threat_categories(self) -> tuple[str, ...]:
        """Return unique unmapped categories in first-seen order across all risks."""

        seen: set[str] = set()
        ordered: list[str] = []
        for assessed in self.risks:
            for category in assessed.unmapped_threat_categories:
                if category not in seen:
                    seen.add(category)
                    ordered.append(category)
        return tuple(ordered)

    @property
    def warnings(self) -> tuple[str, ...]:
        """Return manual-review warnings for unmapped threat categories."""

        if not self.unmapped_threat_categories:
            return ()
        categories = ", ".join(self.unmapped_threat_categories)
        return (
            f"Manual control review required for unmapped threat categories: {categories}.",
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a stable, JSON-serialisable report without hiding source inputs."""

        return {
            "schema_version": "1.0",
            "summary": {
                "risk_count": len(self.risks),
                "critical_count": self.level_counts[RiskLevel.CRITICAL],
                "high_count": self.level_counts[RiskLevel.HIGH],
                "medium_count": self.level_counts[RiskLevel.MEDIUM],
                "low_count": self.level_counts[RiskLevel.LOW],
                "recommended_control_count": self.recommended_control_count,
                "unmapped_threat_categories": list(self.unmapped_threat_categories),
            },
            "warnings": list(self.warnings),
            "risks": [
                {
                    "id": assessed.risk.identifier,
                    "asset": assessed.risk.asset,
                    "vulnerability": assessed.risk.vulnerability,
                    "likelihood": assessed.risk.likelihood,
                    "impact": assessed.risk.impact,
                    "score": assessed.score,
                    "level": assessed.level.value,
                    "threat_categories": list(assessed.risk.threat_categories),
                    "unmapped_threat_categories": list(assessed.unmapped_threat_categories),
                    "existing_controls": list(assessed.risk.existing_controls),
                    "recommended_controls": [
                        {
                            "id": control.identifier,
                            "title": control.title,
                            "purpose": control.purpose,
                        }
                        for control in assessed.recommended_controls
                    ],
                }
                for assessed in self.risks
            ],
        }


def _as_string_tuple(value: Any, *, field_name: str, identifier: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise ValueError(f"Risk {identifier}: {field_name} must be a non-empty list of strings.")
    return tuple(item.strip() for item in value)


def _risk_from_mapping(mapping: Any) -> Risk:
    if not isinstance(mapping, dict):
        raise ValueError("Each risk must be a JSON object.")
    identifier = mapping.get("id")
    if not isinstance(identifier, str) or not identifier.strip():
        raise ValueError("Each risk requires a non-empty string id.")
    return Risk(
        identifier=identifier.strip(),
        asset=_string_field(mapping, "asset", identifier),
        vulnerability=_string_field(mapping, "vulnerability", identifier),
        likelihood=_score_field(mapping, "likelihood", identifier),
        impact=_score_field(mapping, "impact", identifier),
        threat_categories=_as_string_tuple(
            mapping.get("threat_categories"), field_name="threat_categories", identifier=identifier
        ),
        existing_controls=_optional_string_tuple(mapping.get("existing_controls", []), identifier),
    )


def _string_field(mapping: dict[str, Any], field_name: str, identifier: str) -> str:
    value = mapping.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Risk {identifier}: {field_name} must be a non-empty string.")
    return value.strip()


def _score_field(mapping: dict[str, Any], field_name: str, identifier: str) -> int:
    value = mapping.get(field_name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Risk {identifier}: {field_name} must be an integer between 1 and 5.")
    return value


def _optional_string_tuple(value: Any, identifier: str) -> tuple[str, ...]:
    if value == []:
        return ()
    return _as_string_tuple(value, field_name="existing_controls", identifier=identifier)


def load_risks(path: str | Path) -> tuple[Risk, ...]:
    """Load and validate a list of risks from a JSON file."""

    input_path = Path(path)
    try:
        payload = json.loads(input_path.read_text(encoding="utf-8"))
    except FileNotFoundError as error:
        raise ValueError(f"Input file does not exist: {input_path}") from error
    except json.JSONDecodeError as error:
        raise ValueError(f"Input file is not valid JSON: {error.msg}") from error

    if not isinstance(payload, dict) or not isinstance(payload.get("risks"), list):
        raise ValueError("Input must be a JSON object containing a risks array.")

    risks = tuple(_risk_from_mapping(item) for item in payload["risks"])
    identifiers = [risk.identifier for risk in risks]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("Risk identifiers must be unique.")
    return risks


def assess_risks(risks: tuple[Risk, ...] | list[Risk]) -> Assessment:
    """Prioritise risks by score, then identifier, and attach control recommendations."""

    assessed = [
        AssessedRisk(
            risk=risk,
            recommended_controls=controls_for_categories(risk.threat_categories),
            unmapped_threat_categories=unmapped_categories(risk.threat_categories),
        )
        for risk in risks
    ]
    assessed.sort(key=lambda item: (-item.score, item.risk.identifier))
    return Assessment(risks=tuple(assessed))

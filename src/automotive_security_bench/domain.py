"""Typed domain objects and deterministic risk-scoring rules."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RiskLevel(str, Enum):
    """Severity derived from a 5x5 likelihood-impact matrix."""

    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        return {
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }[self]


def risk_level(score: int) -> RiskLevel:
    """Map a likelihood-impact score (1-25) to an explainable severity."""

    if score >= 20:
        return RiskLevel.CRITICAL
    if score >= 12:
        return RiskLevel.HIGH
    if score >= 6:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


@dataclass(frozen=True)
class Risk:
    """One assessed threat scenario using a deliberately small, reviewable schema."""

    identifier: str
    asset: str
    vulnerability: str
    likelihood: int
    impact: int
    threat_categories: tuple[str, ...]
    existing_controls: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.identifier.strip():
            raise ValueError("Risk identifier must not be empty.")
        if not self.asset.strip():
            raise ValueError(f"Risk {self.identifier}: asset must not be empty.")
        if not self.vulnerability.strip():
            raise ValueError(f"Risk {self.identifier}: vulnerability must not be empty.")
        for field_name, value in (("likelihood", self.likelihood), ("impact", self.impact)):
            if not 1 <= value <= 5:
                raise ValueError(
                    f"Risk {self.identifier}: {field_name} must be between 1 and 5; got {value}."
                )
        if not self.threat_categories:
            raise ValueError(f"Risk {self.identifier}: at least one threat category is required.")

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def level(self) -> RiskLevel:
        return risk_level(self.score)

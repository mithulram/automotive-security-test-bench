"""Small control catalogue used to make recommendations reproducible."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Control:
    identifier: str
    title: str
    purpose: str


CONTROL_CATALOGUE: dict[str, Control] = {
    "access-control": Control(
        "access-control", "Access control", "Restrict service and diagnostic access to authorized identities."
    ),
    "fail-safe-mode": Control(
        "fail-safe-mode", "Fail-safe mode", "Define safe degradation when a security control or communication path fails."
    ),
    "freshness-checks": Control(
        "freshness-checks", "Freshness checks", "Reject stale or replayed messages using counters or timestamps."
    ),
    "message-integrity": Control(
        "message-integrity", "Message integrity", "Detect unauthorised modification using authenticated integrity protection."
    ),
    "network-segmentation": Control(
        "network-segmentation", "Network segmentation", "Limit lateral movement and expose only necessary interfaces."
    ),
    "rate-limiting": Control(
        "rate-limiting", "Rate limiting", "Bound request volume to protect availability-critical components."
    ),
    "secure-update": Control(
        "secure-update", "Secure update", "Verify provenance and integrity before applying software or configuration updates."
    ),
}


THREAT_CONTROL_MAP: dict[str, tuple[str, ...]] = {
    "authentication": ("access-control", "message-integrity"),
    "denial-of-service": ("rate-limiting", "network-segmentation", "fail-safe-mode"),
    "diagnostics": ("access-control", "network-segmentation"),
    "replay": ("freshness-checks", "message-integrity"),
    "service-discovery": ("access-control", "message-integrity", "network-segmentation"),
    "tampering": ("message-integrity", "freshness-checks"),
    "update": ("secure-update", "message-integrity"),
}


def controls_for_categories(categories: tuple[str, ...]) -> tuple[Control, ...]:
    """Return unique controls in a stable order for known threat categories."""

    selected: list[str] = []
    for category in categories:
        for control_identifier in THREAT_CONTROL_MAP.get(category.lower(), ()):
            if control_identifier not in selected:
                selected.append(control_identifier)
    return tuple(CONTROL_CATALOGUE[identifier] for identifier in selected)

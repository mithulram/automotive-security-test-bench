"""Command-line interface for reproducible automotive risk assessments."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from .assessment import assess_risks, load_risks
from .domain import RiskLevel
from .reporting import write_html_report, write_json_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="auto-sec-bench",
        description="Assess automotive cybersecurity scenarios from a JSON risk register.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    assess = subparsers.add_parser("assess", help="prioritise risks and generate reports")
    assess.add_argument("--input", required=True, type=Path, help="JSON file containing a risks array")
    assess.add_argument("--json-out", type=Path, help="path for a JSON assessment report")
    assess.add_argument("--html-out", type=Path, help="path for a self-contained HTML assessment report")
    assess.add_argument(
        "--fail-on",
        choices=("low", "medium", "high", "critical"),
        help="exit with code 2 when a risk at or above this severity is present",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command != "assess":
        parser.error(f"Unsupported command: {args.command}")

    try:
        assessment = assess_risks(load_risks(args.input))
    except ValueError as error:
        parser.error(str(error))

    if args.json_out:
        write_json_report(assessment, args.json_out)
    if args.html_out:
        write_html_report(assessment, args.html_out)

    _print_summary(assessment)
    if args.fail_on:
        threshold = RiskLevel(args.fail_on.title())
        if any(item.level.rank >= threshold.rank for item in assessment.risks):
            print(f"Policy gate: at least one risk meets or exceeds {threshold.value} severity.")
            return 2
    return 0


def _print_summary(assessment) -> None:
    summary = assessment.to_dict()["summary"]
    print(
        "Assessment complete: "
        f"{summary['risk_count']} risks | "
        f"critical={summary['critical_count']} | high={summary['high_count']} | "
        f"medium={summary['medium_count']} | low={summary['low_count']} | "
        f"recommended_controls={summary['recommended_control_count']}"
    )
    for warning in assessment.warnings:
        print(f"WARNING: {warning}")
    for item in assessment.risks:
        controls = ", ".join(control.identifier for control in item.recommended_controls) or "manual-review"
        line = f"{item.risk.identifier}: {item.level.value} ({item.score}) | {controls}"
        if item.unmapped_threat_categories:
            unmapped = ", ".join(item.unmapped_threat_categories)
            line += f" | unmapped={unmapped}"
        print(line)

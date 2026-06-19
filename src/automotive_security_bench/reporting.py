"""Render assessment outputs without depending on a web framework."""

from __future__ import annotations

from html import escape
from pathlib import Path

from .assessment import Assessment
from .domain import RiskLevel


LEVEL_STYLE = {
    RiskLevel.CRITICAL: "critical",
    RiskLevel.HIGH: "high",
    RiskLevel.MEDIUM: "medium",
    RiskLevel.LOW: "low",
}


def write_json_report(assessment: Assessment, path: str | Path) -> Path:
    """Write an indented, deterministic JSON report."""

    import json

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(assessment.to_dict(), indent=2, sort_keys=True) + "\n",encoding="utf-8"
    )
    return output_path


def write_html_report(assessment: Assessment, path: str | Path) -> Path:
    """Write an accessible, self-contained HTML assessment report."""

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary = assessment.to_dict()["summary"]
    cards = "".join(
        f'<article class="metric {css_class}"><span>{escape(label)}</span><strong>{value}</strong></article>'
        for label, value, css_class in (
            ("Risks assessed", summary["risk_count"], "neutral"),
            ("Critical", summary["critical_count"], "critical"),
            ("High", summary["high_count"], "high"),
            ("Recommended controls", summary["recommended_control_count"], "neutral"),
        )
    )
    rows = "".join(_risk_row(item) for item in assessment.risks)
    warnings = _warnings_section(assessment.warnings)
    output_path.write_text(
        _page_template(cards=cards, rows=rows, warnings=warnings),encoding="utf-8"
    )
    return output_path


def _warnings_section(warnings: tuple[str, ...]) -> str:
    if not warnings:
        return ""
    items = "".join(f"<li>{escape(warning)}</li>" for warning in warnings)
    return (
        '<section class="warnings" aria-label="Manual review warnings">'
        "<h2>Manual review required</h2>"
        f"<ul>{items}</ul>"
        "</section>"
    )


def _risk_row(assessed_risk) -> str:
    risk = assessed_risk.risk
    if assessed_risk.recommended_controls:
        controls = ", ".join(control.title for control in assessed_risk.recommended_controls)
    else:
        controls = "Manual review required"
    if assessed_risk.unmapped_threat_categories:
        unmapped = ", ".join(assessed_risk.unmapped_threat_categories)
        controls += f" (unmapped categories: {unmapped})"
    css_class = LEVEL_STYLE[assessed_risk.level]
    return "".join(
        (
            "<tr>",
            f"<td><strong>{escape(risk.identifier)}</strong><br><span>{escape(risk.asset)}</span></td>",
            f"<td>{escape(risk.vulnerability)}</td>",
            f'<td><span class="badge {css_class}">{escape(assessed_risk.level.value)} ({assessed_risk.score})</span></td>',
            f"<td>{escape(controls)}</td>",
            "</tr>",
        )
    )


def _page_template(*, cards: str, rows: str, warnings: str) -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Automotive Security Assessment Report</title>
  <style>
    :root {{ color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #172033; background: #f4f7fb; }}
    body {{ max-width: 1120px; margin: 0 auto; padding: 48px 24px; }}
    header {{ border-bottom: 4px solid #1f4e79; padding-bottom: 20px; margin-bottom: 28px; }}
    h1 {{ margin: 0 0 8px; font-size: clamp(2rem, 5vw, 3rem); letter-spacing: -0.03em; }}
    h2 {{ margin-top: 36px; font-size: 1.3rem; }}
    p {{ color: #52606d; line-height: 1.55; max-width: 78ch; }}
    .metrics {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));gap: 14px; }}
    .metric {{ background: white; border: 1px solid #d9e2ec; border-radius: 12px; padding: 18px; }}
    .metric span {{ display: block; color: #52606d; font-size: .9rem; }}
    .metric strong {{ display: block; margin-top: 6px; font-size: 2rem; }}
    .metric.critical strong, .badge.critical {{ color: #a61b1b; }}
    .metric.high strong, .badge.high {{ color: #a64b00; }}
    table {{ width: 100%; border-collapse: collapse; background: white; border: 1px solid #d9e2ec; border-radius: 12px; overflow: hidden; }}
    th, td {{ padding: 15px; text-align: left; vertical-align: top; border-bottom: 1px solid #e5edf5; line-height: 1.45; }}
    th {{ background: #e9f1f8; color: #244b6e; font-size: .85rem; text-transform: uppercase; letter-spacing: .04em; }}
    tr:last-child td {{ border-bottom: 0; }}
    td span {{ color: #52606d; font-size: .9rem; }}
    .badge {{ display: inline-block; font-weight: 700; white-space: nowrap; }}
    .badge.medium {{ color: #795c00; }}
    .badge.low {{ color: #1a6b3d; }}
    .warnings {{ background: #fff4e5; border: 1px solid #f0c987; border-radius: 12px; padding: 18px 22px; margin-bottom: 28px; }}
    .warnings h2 {{ margin: 0 0 10px; color: #8a4b00; font-size: 1.1rem; }}
    .warnings ul {{ margin: 0; padding-left: 1.2rem; color: #5c3b00; line-height: 1.5; }}
    footer {{ margin-top: 30px; color: #6b7c93; font-size: .9rem; }}
    @media (max-width: 760px) {{ .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }} table, thead, tbody, th, td, tr {{ display: block; }} thead {{ display: none; }} td {{ border-bottom: 0; padding: 9px 15px; }} tr {{ border-bottom: 1px solid #d9e2ec; padding: 8px 0; }} }}
  </style>
</head>
<body>
  <header>
    <h1>Automotive Security Assessment</h1>
    <p>A reproducible risk-prioritisation report for distributed ECU communication scenarios. Scores are likelihood × impact on a 5×5 matrix; recommendations are mapped from the input threat categories.</p>
  </header>
  {warnings}
  <section class="metrics" aria-label="Assessment summary">{cards}</section>
  <section>
    <h2>Prioritised risks</h2>
    <table>
      <thead><tr><th scope="col">Scenario</th><th scope="col">Vulnerability</th><th scope="col">Risk</th><th scope="col">Recommended controls</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </section>
  <footer>Generated by the Automotive Security Test Bench. This demonstrator supports structured analysis; it is not a substitute for a production threat model or safety case.</footer>
</body>
</html>
"""

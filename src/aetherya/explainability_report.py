from __future__ import annotations

import argparse
import html
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from aetherya.explainability_render import render_mermaid_from_event, select_event


def _safe_mapping(value: Any) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    return {}


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=True)


def load_audit_events(path: str | Path) -> list[dict[str, Any]]:
    audit_path = Path(path)
    if not audit_path.exists():
        raise ValueError(f"audit file not found: {audit_path}")

    events: list[dict[str, Any]] = []
    for idx, line in enumerate(audit_path.read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid JSON in audit at line {idx + 1}") from exc
        if not isinstance(payload, dict):
            raise ValueError(f"audit event at line {idx + 1} must be a JSON object")
        events.append(payload)

    return events


def _kv_rows(data: Mapping[str, Any], ordered_keys: list[str]) -> str:
    rows: list[str] = []
    for key in ordered_keys:
        rows.append(f"<tr><th>{_escape(key)}</th><td>{_escape(data.get(key, '-'))}</td></tr>")

    extra_keys = sorted(k for k in data if k not in ordered_keys)
    for key in extra_keys:
        rows.append(f"<tr><th>{_escape(key)}</th><td>{_escape(data.get(key, '-'))}</td></tr>")

    return "\n".join(rows)


def _contributors_rows(contributors: Any) -> str:
    if not isinstance(contributors, list):
        return '<tr><td colspan="7">invalid contributors payload</td></tr>'

    if not contributors:
        return '<tr><td colspan="7">no contributors</td></tr>'

    rows: list[str] = []
    for contributor in contributors:
        if not isinstance(contributor, Mapping):
            rows.append('<tr><td colspan="7">invalid contributor item</td></tr>')
            continue

        source = contributor.get("source", "-")
        weighted_score = contributor.get("weighted_score", "-")
        ratio = contributor.get("contribution_ratio", 0.0)
        weight = contributor.get("weight", "-")
        reason = contributor.get("reason", "-")
        violated_principle = contributor.get("violated_principle", "-")
        tags = contributor.get("tags", [])
        tags_label = ", ".join(str(tag) for tag in tags) if isinstance(tags, list) else str(tags)

        rows.append(
            "<tr>"
            f"<td>{_escape(source)}</td>"
            f"<td>{_escape(weighted_score)}</td>"
            f"<td>{_escape(ratio)}</td>"
            f"<td>{_escape(weight)}</td>"
            f"<td>{_escape(reason)}</td>"
            f"<td>{_escape(violated_principle)}</td>"
            f"<td>{_escape(tags_label)}</td>"
            "</tr>"
        )

    return "\n".join(rows)


def build_html_report(
    *,
    event: Mapping[str, Any],
    mermaid: str,
    title: str = "AETHERYA Explainability Report",
) -> str:
    safe_event = _safe_mapping(event)
    context = _safe_mapping(safe_event.get("context"))
    decision = _safe_mapping(safe_event.get("decision"))
    explainability = _safe_mapping(context.get("explainability"))
    summary = _safe_mapping(explainability.get("summary"))
    contributors = explainability.get("contributors")

    summary_rows = _kv_rows(
        summary,
        [
            "mode",
            "risk_score",
            "aggregate_decision",
            "effective_risk_decision",
            "state",
            "allowed",
            "reason",
            "violated_principle",
            "top_contributor",
        ],
    )
    decision_rows = _kv_rows(
        decision,
        ["allowed", "risk_score", "reason", "violated_principle", "mode", "state", "abi_version"],
    )
    contributor_rows = _contributors_rows(contributors)

    metadata = {
        "event_id": safe_event.get("event_id", "-"),
        "decision_id": safe_event.get("decision_id", "-"),
        "policy_fingerprint": safe_event.get("policy_fingerprint", "-"),
        "ts": safe_event.get("ts", "-"),
        "actor": safe_event.get("actor", "-"),
        "action": safe_event.get("action", "-"),
    }
    metadata_rows = _kv_rows(
        metadata,
        ["event_id", "decision_id", "policy_fingerprint", "ts", "actor", "action"],
    )

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>{_escape(title)}</title>
  <style>
    :root {{
      --bg: #f5f4ee;
      --ink: #162318;
      --panel: #ffffff;
      --line: #d8d5c9;
      --accent: #2d6a4f;
    }}
    body {{
      margin: 0;
      font-family: "IBM Plex Sans", "Segoe UI", Arial, sans-serif;
      color: var(--ink);
      background: radial-gradient(circle at 20% 10%, #e9f5ec 0%, var(--bg) 38%);
    }}
    .wrap {{
      max-width: 1100px;
      margin: 28px auto;
      padding: 0 16px 40px;
    }}
    h1, h2 {{
      margin: 0 0 12px;
      letter-spacing: 0.01em;
    }}
    h1 {{
      font-size: 1.8rem;
    }}
    section {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 14px;
      margin-top: 14px;
      box-shadow: 0 8px 20px rgba(22, 35, 24, 0.06);
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.92rem;
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
      padding: 8px 6px;
    }}
    th {{
      width: 210px;
      color: var(--accent);
      font-weight: 600;
    }}
    .mermaid {{
      overflow-x: auto;
      background: #fff;
      border: 1px dashed var(--line);
      border-radius: 10px;
      padding: 10px;
    }}
    code {{
      font-family: "JetBrains Mono", "Fira Code", monospace;
      font-size: 0.86rem;
    }}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>{_escape(title)}</h1>
    <section>
      <h2>Event Metadata</h2>
      <table>{metadata_rows}</table>
    </section>
    <section>
      <h2>Decision Summary</h2>
      <table>{decision_rows}</table>
    </section>
    <section>
      <h2>Explainability Summary</h2>
      <table>{summary_rows}</table>
    </section>
    <section>
      <h2>Contributors</h2>
      <table>
        <thead>
          <tr>
            <th>source</th>
            <th>weighted_score</th>
            <th>contribution_ratio</th>
            <th>weight</th>
            <th>reason</th>
            <th>violated_principle</th>
            <th>tags</th>
          </tr>
        </thead>
        <tbody>
          {contributor_rows}
        </tbody>
      </table>
    </section>
    <section>
      <h2>Mermaid Graph</h2>
      <pre class="mermaid">{_escape(mermaid)}</pre>
      <p><code>Tip:</code> If Mermaid does not render, open this file with internet access.</p>
    </section>
  </div>
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
    mermaid.initialize({{ startOnLoad: true, securityLevel: "strict" }});
  </script>
</body>
</html>
"""


def render_html_from_event(
    event: Mapping[str, Any], title: str = "AETHERYA Explainability Report"
) -> str:
    mermaid = render_mermaid_from_event(event)
    return build_html_report(event=event, mermaid=mermaid, title=title)


def render_html_from_audit(
    path: str | Path,
    event_index: int = -1,
    title: str = "AETHERYA Explainability Report",
) -> str:
    events = load_audit_events(path)
    event = select_event(events, event_index)
    return render_html_from_event(event, title=title)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export explainability audit event to static HTML report."
    )
    parser.add_argument(
        "--audit-path",
        default="audit/decisions.jsonl",
        help="Path to audit decisions JSONL",
    )
    parser.add_argument(
        "--event-index",
        type=int,
        default=-1,
        help="Index of event in JSONL (supports negative index, default=-1)",
    )
    parser.add_argument(
        "--output",
        default="audit/explainability_report.html",
        help="Output HTML report path",
    )
    parser.add_argument(
        "--title",
        default="AETHERYA Explainability Report",
        help="HTML report title",
    )
    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        report = render_html_from_audit(args.audit_path, args.event_index, title=args.title)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding="utf-8")
    print(f"wrote report: {output_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

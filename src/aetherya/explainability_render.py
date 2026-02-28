from __future__ import annotations

import argparse
import json
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any


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


def select_event(events: list[dict[str, Any]], event_index: int) -> dict[str, Any]:
    if not events:
        raise ValueError("audit contains no events")
    try:
        return events[event_index]
    except IndexError as exc:
        raise ValueError(f"event_index out of range: {event_index}") from exc


def extract_explainability(event: Mapping[str, Any]) -> dict[str, Any]:
    context = event.get("context")
    if not isinstance(context, Mapping):
        raise ValueError("audit event context is missing or invalid")

    explainability = context.get("explainability")
    if not isinstance(explainability, dict):
        raise ValueError("audit event does not contain explainability context")

    return explainability


def _mermaid_id(raw_id: str, idx: int) -> str:
    slug = re.sub(r"[^a-zA-Z0-9_]+", "_", raw_id).strip("_").lower()
    if not slug:
        slug = "node"
    if slug[0].isdigit():
        slug = f"n_{slug}"
    return f"n{idx}_{slug[:40]}"


def _escape_label(text: str) -> str:
    return text.replace('"', '\\"')


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def render_mermaid(explainability: Mapping[str, Any]) -> str:
    graph = explainability.get("graph")
    if not isinstance(graph, Mapping):
        raise ValueError("explainability.graph is missing or invalid")

    raw_nodes = graph.get("nodes")
    raw_edges = graph.get("edges")
    if not isinstance(raw_nodes, list):
        raise ValueError("explainability.graph.nodes must be list")
    if not isinstance(raw_edges, list):
        raise ValueError("explainability.graph.edges must be list")

    lines = ["flowchart LR"]
    node_id_map: dict[str, str] = {}

    for idx, node in enumerate(raw_nodes):
        if not isinstance(node, Mapping):
            raise ValueError("node must be object")

        raw_id = str(node.get("id", "")).strip()
        if not raw_id:
            raise ValueError("node id is required")

        label = str(node.get("label", raw_id))
        node_type = str(node.get("type", "node"))
        node_data = node.get("data")
        if isinstance(node_data, Mapping) and node_type == "signal":
            weighted = int(node_data.get("weighted_score", 0))
            ratio = _safe_float(node_data.get("contribution_ratio", 0.0))
            label = f"{label} | ws={weighted}, c={ratio:.2f}"
        elif isinstance(node_data, Mapping) and node_type == "decision_state":
            state = str(node_data.get("state", "unknown"))
            allowed = bool(node_data.get("allowed", False))
            label = f"{label} | state={state}, allowed={allowed}"

        mermaid_id = _mermaid_id(raw_id, idx)
        node_id_map[raw_id] = mermaid_id
        lines.append(f'    {mermaid_id}["{_escape_label(label)}"]')

    for edge in raw_edges:
        if not isinstance(edge, Mapping):
            raise ValueError("edge must be object")

        raw_from = str(edge.get("from", "")).strip()
        raw_to = str(edge.get("to", "")).strip()
        if raw_from not in node_id_map or raw_to not in node_id_map:
            raise ValueError("edge references unknown node")

        edge_type = str(edge.get("type", "edge"))
        edge_data = edge.get("data")
        edge_label = edge_type
        if isinstance(edge_data, Mapping) and "weighted_score" in edge_data:
            weighted = int(edge_data.get("weighted_score", 0))
            ratio = _safe_float(edge_data.get("contribution_ratio", 0.0))
            edge_label = f"{edge_type} (ws={weighted}, c={ratio:.2f})"

        lines.append(
            f"    {node_id_map[raw_from]} -->|{_escape_label(edge_label)}| {node_id_map[raw_to]}"
        )

    return "\n".join(lines) + "\n"


def render_mermaid_from_event(event: Mapping[str, Any]) -> str:
    explainability = extract_explainability(event)
    return render_mermaid(explainability)


def render_mermaid_from_audit(path: str | Path, event_index: int = -1) -> str:
    events = load_audit_events(path)
    event = select_event(events, event_index)
    return render_mermaid_from_event(event)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render explainability graph from audit JSONL as Mermaid."
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
        default="",
        help="Optional output file (.mmd). If empty, prints to stdout.",
    )

    args = parser.parse_args(list(argv) if argv is not None else None)

    try:
        mermaid = render_mermaid_from_audit(args.audit_path, args.event_index)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(mermaid, encoding="utf-8")
    else:
        print(mermaid, end="")

    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import __version__
from .evaluator import evaluate_action
from .html_report import html_report
from .models import aggregate
from .policy import PolicyError, load_policy
from .reports import json_report, markdown_report, validate_report
from .scanners import scan_manifest
from .validation import InputError

EXIT_CODES = {"allow": 0, "warn": 1, "deny": 2}


def _read_json(path: str) -> dict[str, Any]:
    input_path = Path(path)
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise InputError(f"Could not read JSON input '{input_path}': {exc}") from exc
    except json.JSONDecodeError as exc:
        raise InputError(
            f"Invalid JSON in '{input_path}' at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    if not isinstance(data, dict):
        raise InputError("JSON input must be an object.")
    return data


def _write(content: str, output: str | None) -> None:
    if output:
        output_path = Path(output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"Wrote {output_path}", file=sys.stderr)
    else:
        print(content, end="")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Pre-flight policy checks for MCP tools and AI agents.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    for command, input_flag, help_text in [
        ("check", "--action", "Evaluate an agent action JSON file."),
        ("scan", "--mcp-config", "Scan an MCP config or tool manifest JSON file."),
    ]:
        child = sub.add_parser(command, help=help_text)
        child.add_argument(input_flag, required=True)
        child.add_argument("--policy", required=True)
        child.add_argument("--format", choices=["json", "markdown", "html"], default="json")
        child.add_argument("--output", help="Write the report to this path instead of stdout.")
    report = sub.add_parser("report", help="Convert a saved JSON result into a report.")
    report.add_argument("--input", required=True)
    report.add_argument("--format", choices=["json", "markdown", "html"], default="markdown")
    report.add_argument("--output", help="Write the report to this path instead of stdout.")
    return parser


def _action_document(source: str, policy_path: str, data: dict[str, Any]) -> dict[str, Any]:
    policy = load_policy(policy_path)
    evaluation = evaluate_action(data, policy)
    return {
        "schema_version": 1,
        "kind": "action_evaluation",
        "source": source,
        "policy": policy_path,
        **evaluation.to_dict(),
    }


def _scan_document(source: str, policy_path: str, data: dict[str, Any]) -> dict[str, Any]:
    policy = load_policy(policy_path)
    evaluations = scan_manifest(data, policy)
    decision, risk_level = aggregate(evaluations)
    counts = {name: sum(item.decision == name for item in evaluations) for name in EXIT_CODES}
    return {
        "schema_version": 1,
        "kind": "manifest_scan",
        "source": source,
        "policy": policy_path,
        "decision": decision,
        "risk_level": risk_level,
        "summary": {"total": len(evaluations), **counts},
        "results": [result.to_dict() for result in evaluations],
    }


def run(args: argparse.Namespace) -> int:
    if args.command == "report":
        payload = _read_json(args.input)
    elif args.command == "check":
        data = _read_json(args.action)
        payload = _action_document(args.action, args.policy, data)
    else:
        data = _read_json(args.mcp_config)
        payload = _scan_document(args.mcp_config, args.policy, data)

    validate_report(payload)
    decision = payload["decision"]
    renderers = {"json": json_report, "markdown": markdown_report, "html": html_report}
    rendered = renderers[args.format](payload)
    _write(rendered, args.output)
    return EXIT_CODES[decision]


def main(argv: list[str] | None = None) -> int:
    try:
        return run(build_parser().parse_args(argv))
    except (InputError, PolicyError, OSError, ValueError) as exc:
        print(f"mcp-guard: error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())

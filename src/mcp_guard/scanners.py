from __future__ import annotations

from typing import Any

from .matching import flatten_schema, text_matches
from .models import Evaluation, Reason, decision_for, risk_for
from .policy import default_decision
from .validation import manifest_entries


def scan_manifest(manifest: dict[str, Any], policy: dict[str, Any]) -> list[Evaluation]:
    output: list[Evaluation] = []
    mcp_rules = policy["rules"].get("mcp_tools", {})
    shell_rules = policy["rules"].get("shell", {})

    for tool in manifest_entries(manifest):
        name = tool["name"]
        description = tool["description"]
        command = tool.get("command", "")
        schema_text = flatten_schema(tool["inputSchema"])
        reasons: list[Reason] = []

        for effect in ("deny", "warn"):
            rule_name = f"{effect}_patterns"
            for pattern in shell_rules.get(rule_name, []):
                if text_matches(command, pattern):
                    reasons.append(
                        Reason(
                            f"shell.{rule_name}",
                            effect,
                            pattern,
                            f"MCP server command matched a {effect} rule.",
                        )
                    )
        for pattern in mcp_rules.get("deny_if_description_contains", []):
            if text_matches(description, pattern):
                reasons.append(
                    Reason(
                        "mcp_tools.deny_if_description_contains",
                        "deny",
                        pattern,
                        "Tool description contains a blocked phrase.",
                    )
                )
        for pattern in mcp_rules.get("warn_if_name_contains", []):
            if text_matches(name, pattern):
                reasons.append(
                    Reason(
                        "mcp_tools.warn_if_name_contains",
                        "warn",
                        pattern,
                        "Tool name indicates a powerful capability.",
                    )
                )
        for pattern in mcp_rules.get("warn_if_schema_contains", []):
            if text_matches(schema_text, pattern):
                reasons.append(
                    Reason(
                        "mcp_tools.warn_if_schema_contains",
                        "warn",
                        pattern,
                        "Tool input schema exposes a sensitive capability.",
                    )
                )

        decision = decision_for(reasons, default_decision(policy))
        output.append(Evaluation(decision, risk_for(decision), reasons, name))
    return output

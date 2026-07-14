from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .models import DECISION_RANK, risk_for
from .policy import VALID_DECISIONS, policy_provenance
from .policy_tooling import (
    evaluate_policy_fixture,
    lint_policy_document,
    policy_fixture_input,
)
from .receipts import (
    action_request_projection,
    attach_receipt,
    canonical_json,
    canonical_policy_hash,
    gateway_request_projection,
)
from .validation import InputError

POLICY_DIFF_GATES = ("none", "deny-to-allow", "deny-relaxation", "any-relaxation")


def _hash(value: Any) -> str:
    digest = hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def _evaluation_receipt(
    name: str,
    fixture: dict[str, Any],
    policy: dict[str, Any],
    evaluation,
) -> str:
    evaluator_input, is_gateway = policy_fixture_input(name, fixture)
    report = {
        "schema_version": 1,
        "kind": "policy_diff_fixture_evaluation",
        "decision": evaluation.decision,
        "risk_level": evaluation.risk_level,
        "subject": name,
        "reasons": [
            {
                "rule": reason.rule,
                "effect": reason.effect,
                "matched": reason.matched,
                "message": reason.message,
            }
            for reason in evaluation.reasons
        ],
    }
    projection = (
        gateway_request_projection(evaluator_input)
        if is_gateway
        else action_request_projection(evaluator_input)
    )
    attach_receipt(report, policy, projection)
    return report["receipt"]["receipt_fingerprint"]


def _rule_entries(policy: dict[str, Any]) -> set[tuple[str, str]]:
    entries: set[tuple[str, str]] = set()
    for section, rules in policy.get("rules", {}).items():
        for rule_name, patterns in rules.items():
            for pattern in patterns:
                entries.add((f"{section}.{rule_name}", canonical_json(pattern)))
    for budget_id, config in policy.get("budgets", {}).items():
        entries.add((f"budgets.{budget_id}", canonical_json(config)))
    return entries


def _gate_failed(gate: str, transitions: list[str]) -> bool:
    if gate not in POLICY_DIFF_GATES:
        raise InputError(f"Unsupported policy diff gate '{gate}'.")
    if gate == "none":
        return False
    if gate == "deny-to-allow":
        return "deny->allow" in transitions
    if gate == "deny-relaxation":
        return any(value in {"deny->warn", "deny->allow"} for value in transitions)
    return any(
        DECISION_RANK[before] > DECISION_RANK[after]
        for before, after in (transition.split("->") for transition in transitions)
    )


def policy_diff_document(
    fixtures: list[tuple[str, dict[str, Any]]],
    before_policy: dict[str, Any],
    after_policy: dict[str, Any],
    before_label: str,
    after_label: str,
    source: str,
    gate: str,
) -> dict[str, Any]:
    if not fixtures:
        raise InputError("Policy diff requires at least one fixture.")
    names = [name.casefold() for name, _ in fixtures]
    if len(set(names)) != len(names):
        raise InputError("Policy diff fixture names must be unique case-insensitively.")
    ordered = sorted(fixtures, key=lambda item: (item[0].casefold(), item[0]))
    results: list[dict[str, Any]] = []
    transitions: list[str] = []
    after_matches: set[tuple[str, str]] = set()
    for name, fixture in ordered:
        if fixture.get("_expected") not in VALID_DECISIONS:
            raise InputError(f"Fixture '{name}' _expected must be allow, warn, or deny.")
        before = evaluate_policy_fixture(name, fixture, before_policy)
        after = evaluate_policy_fixture(name, fixture, after_policy)
        transition = f"{before.decision}->{after.decision}"
        transitions.append(transition)
        before_rank = DECISION_RANK[before.decision]
        after_rank = DECISION_RANK[after.decision]
        if before_rank > after_rank:
            classification = "relaxation"
            diff_decision = "deny" if transition == "deny->allow" else "warn"
        elif before_rank < after_rank:
            classification = "tightening"
            diff_decision = "allow"
        else:
            classification = "unchanged"
            diff_decision = "allow"
        reasons = []
        if classification == "relaxation":
            effect = "deny" if diff_decision == "deny" else "warn"
            reasons.append(
                {
                    "rule": "policy-diff.relaxation",
                    "effect": effect,
                    "matched": transition,
                    "message": (
                        f"Fixture decision relaxed from {before.decision} to {after.decision}."
                    ),
                }
            )
        for reason in after.reasons:
            after_matches.add((reason.rule, canonical_json(reason.matched)))
        results.append(
            {
                "subject": name,
                "decision": diff_decision,
                "risk_level": risk_for(diff_decision),
                "classification": classification,
                "before_decision": before.decision,
                "after_decision": after.decision,
                "transition": transition,
                "before_receipt": _evaluation_receipt(name, fixture, before_policy, before),
                "after_receipt": _evaluation_receipt(name, fixture, after_policy, after),
                "reasons": reasons,
            }
        )

    before_entries = _rule_entries(before_policy)
    after_entries = _rule_entries(after_policy)
    added = sorted(after_entries - before_entries)
    removed = sorted(before_entries - after_entries)
    changes = []
    ineffective = []
    for change, entries in (("added", added), ("removed", removed)):
        for rule, encoded in entries:
            entry = {
                "rule": rule,
                "change": change,
                "pattern_fingerprint": _hash({"rule": rule, "value": encoded}),
            }
            if change == "added" and (rule, encoded) not in after_matches:
                entry["observed_in_corpus"] = False
                ineffective.append(entry)
            else:
                entry["observed_in_corpus"] = True
            changes.append(entry)

    lint = lint_policy_document(after_policy, after_label)
    shadowed = [
        {
            "rule": reason["rule"],
            "pattern_fingerprint": _hash({"rule": reason["rule"], "matched": reason["matched"]}),
        }
        for reason in lint["reasons"]
        if reason["rule"] == "policy-lint.shadowed-warning"
    ]
    relaxations = sum(result["classification"] == "relaxation" for result in results)
    tightenings = sum(result["classification"] == "tightening" for result in results)
    transition_counts = {
        transition: transitions.count(transition) for transition in sorted(set(transitions))
    }
    gate_failed = _gate_failed(gate, transitions)
    decision = max((result["decision"] for result in results), key=DECISION_RANK.get)
    before_hash = canonical_policy_hash(before_policy)
    after_hash = canonical_policy_hash(after_policy)
    comparison_core = {
        "before_policy_hash": before_hash,
        "after_policy_hash": after_hash,
        "fixtures": [
            {
                "subject": result["subject"],
                "transition": result["transition"],
                "before_receipt": result["before_receipt"],
                "after_receipt": result["after_receipt"],
            }
            for result in results
        ],
        "rule_changes": changes,
    }
    return {
        "schema_version": 1,
        "kind": "policy_diff",
        "source": Path(source).name,
        "decision": decision,
        "risk_level": risk_for(decision),
        "summary": {
            "fixtures": len(results),
            "changed": relaxations + tightenings,
            "relaxations": relaxations,
            "tightenings": tightenings,
            "unchanged": len(results) - relaxations - tightenings,
            "transitions": transition_counts,
        },
        "gate": {"fail_on": gate, "failed": gate_failed},
        "policies": {
            "before": {
                "label": before_label,
                "hash": before_hash,
                "provenance": policy_provenance(before_policy),
            },
            "after": {
                "label": after_label,
                "hash": after_hash,
                "provenance": policy_provenance(after_policy),
            },
        },
        "comparison_fingerprint": _hash(comparison_core),
        "rule_summary": {
            "added": len(added),
            "removed": len(removed),
            "ineffective_in_corpus": len(ineffective),
            "shadowed": len(shadowed),
            "changes": changes,
            "shadowed_rules": shadowed,
        },
        "counterexample_suggestions": [
            {
                "rule": entry["rule"],
                "pattern_fingerprint": entry["pattern_fingerprint"],
                "suggestion": "Add a synthetic fixture that exercises this rule entry.",
            }
            for entry in ineffective[:20]
        ],
        "results": results,
    }


def policy_diff_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    rules = report["rule_summary"]
    lines = [
        "# PolicyLatch policy diff",
        "",
        f"Comparison: `{report['comparison_fingerprint']}`",
        f"Gate: **{'FAILED' if report['gate']['failed'] else 'PASSED'}** "
        f"(`{report['gate']['fail_on']}`)",
        "",
        "| Fixture | Before | After | Classification |",
        "|---|---|---|---|",
    ]
    for result in report["results"]:
        subject = (
            str(result["subject"])
            .replace("\r", " ")
            .replace("\n", " ")
            .replace("|", "\\|")
            .replace("`", "'")
        )
        lines.append(
            f"| `{subject}` | {result['before_decision']} | "
            f"{result['after_decision']} | {result['classification']} |"
        )
    lines += [
        "",
        "## Summary",
        "",
        f"- Changed: {summary['changed']}",
        f"- Relaxations: {summary['relaxations']}",
        f"- Tightenings: {summary['tightenings']}",
        f"- Added rule entries: {rules['added']}",
        f"- Removed rule entries: {rules['removed']}",
        f"- Ineffective in this corpus (heuristic): {rules['ineffective_in_corpus']}",
        f"- Shadowed warnings (heuristic): {rules['shadowed']}",
        "",
        "> Simulation over supplied fixtures only; this is not proof that a policy is safe.",
        "",
    ]
    return "\n".join(lines)

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Decision = Literal["allow", "warn", "deny"]
RiskLevel = Literal["low", "medium", "high"]
DECISION_RANK: dict[Decision, int] = {"allow": 0, "warn": 1, "deny": 2}


@dataclass(frozen=True)
class Reason:
    rule: str
    effect: Literal["warn", "deny"]
    matched: str
    message: str


@dataclass
class Evaluation:
    decision: Decision
    risk_level: RiskLevel
    reasons: list[Reason] = field(default_factory=list)
    subject: str | None = None

    @property
    def recommended_action(self) -> str:
        return {
            "allow": "Proceed only within the declared scope.",
            "warn": "Require human approval or an additional review before execution.",
            "deny": "Do not execute this proposed action under the current policy.",
        }[self.decision]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["recommended_action"] = self.recommended_action
        if self.subject is None:
            data.pop("subject")
        return data


def decision_for(reasons: list[Reason], default: Decision) -> Decision:
    if any(reason.effect == "deny" for reason in reasons):
        return "deny"
    if reasons:
        return "warn"
    return default


def risk_for(decision: Decision) -> RiskLevel:
    return {"allow": "low", "warn": "medium", "deny": "high"}[decision]


def aggregate(evaluations: list[Evaluation]) -> tuple[Decision, RiskLevel]:
    decision = max((item.decision for item in evaluations), key=DECISION_RANK.get)
    return decision, risk_for(decision)

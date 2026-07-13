from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, cast

from .validation import InputError

VerificationState = Literal["proposed", "observed", "verified"]
WindowsCategory = Literal["registry", "service", "firewall", "policy", "setting"]
ChangeKind = Literal["created", "updated", "deleted", "unchanged", "unknown"]

VERIFICATION_STATES = frozenset({"proposed", "observed", "verified"})
WINDOWS_CATEGORIES = frozenset({"registry", "service", "firewall", "policy", "setting"})
CHANGE_KINDS = frozenset({"created", "updated", "deleted", "unchanged", "unknown"})

_ALLOWED_ACTION_FIELDS = frozenset(
    {
        "action_type",
        "timestamp",
        "verification_state",
        "source",
        "category",
        "target",
        "operation",
        "change",
        "before",
        "after",
        "actor",
        "tool",
    }
)
_RAW_VALUE_FIELDS = frozenset(
    {
        "value",
        "raw_value",
        "before_value",
        "after_value",
        "value_hash",
        "before_hash",
        "after_hash",
    }
)
_ALLOWED_STATE_FIELDS = frozenset({"present", "redacted"})


@dataclass(frozen=True)
class StateSummary:
    """Presence-only state: actual Windows values never enter the audit record."""

    present: bool | None
    redacted: bool = True


@dataclass(frozen=True)
class WindowsAuditRecord:
    """Versioned, summary-only record for one declared Windows setting action."""

    timestamp: str
    verification_state: VerificationState
    source: str
    category: WindowsCategory
    target: str
    operation: str
    change: ChangeKind
    before: StateSummary
    after: StateSummary
    actor: str | None = None
    tool: str | None = None
    schema_version: int = 1
    kind: str = "windows_audit_record"

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "schema_version": self.schema_version,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "verification_state": self.verification_state,
            "source": self.source,
            "category": self.category,
            "target": self.target,
            "operation": self.operation,
            "change": self.change,
            "before": {
                "present": self.before.present,
                "redacted": self.before.redacted,
            },
            "after": {
                "present": self.after.present,
                "redacted": self.after.redacted,
            },
        }
        if self.actor is not None:
            data["actor"] = self.actor
        if self.tool is not None:
            data["tool"] = self.tool
        return data


def _required_text(action: dict[str, Any], field: str) -> str:
    value = action.get(field)
    if not isinstance(value, str) or not value.strip():
        raise InputError(f"windows_setting.{field} must be a non-empty string.")
    return value.strip()


def _enum_value(action: dict[str, Any], field: str, allowed: frozenset[str]) -> str:
    value = _required_text(action, field).lower()
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise InputError(f"windows_setting.{field} must be one of: {choices}.")
    return value


def _timestamp(value: str) -> str:
    candidate = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise InputError("windows_setting.timestamp must be a valid ISO-8601 datetime.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise InputError("windows_setting.timestamp must include a UTC offset or Z suffix.")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _state_summary(action: dict[str, Any], field: str) -> StateSummary:
    value = action.get(field)
    if not isinstance(value, dict):
        raise InputError(f"windows_setting.{field} must be a summary object.")

    unknown = set(value) - _ALLOWED_STATE_FIELDS
    if unknown:
        if unknown & _RAW_VALUE_FIELDS:
            raise InputError(f"windows_setting.{field} cannot contain raw values or value hashes.")
        names = ", ".join(sorted(unknown))
        raise InputError(f"Unknown windows_setting.{field} fields: {names}.")

    if "present" not in value or not isinstance(value["present"], (bool, type(None))):
        raise InputError(f"windows_setting.{field}.present must be true, false, or null.")
    if "redacted" in value and value["redacted"] is not True:
        raise InputError(f"windows_setting.{field}.redacted must be true when provided.")
    return StateSummary(present=value["present"])


def _validate_verified_change(change: str, before: StateSummary, after: StateSummary) -> None:
    if before.present is None or after.present is None:
        raise InputError("Verified records require known before.present and after.present values.")

    expected_presence = {
        "created": (False, True),
        "deleted": (True, False),
        "updated": (True, True),
        "unchanged": (True, True),
    }.get(change)
    if expected_presence and (before.present, after.present) != expected_presence:
        raise InputError(f"Verified '{change}' change is inconsistent with before/after presence.")


def parse_windows_setting_action(action: dict[str, Any]) -> WindowsAuditRecord:
    """Validate a declared action without reading or changing the host system."""

    if not isinstance(action, dict):
        raise InputError("windows_setting action must be an object.")

    unknown = set(action) - _ALLOWED_ACTION_FIELDS
    if unknown:
        if unknown & _RAW_VALUE_FIELDS:
            raise InputError("windows_setting actions cannot contain raw values or value hashes.")
        names = ", ".join(sorted(unknown))
        raise InputError(f"Unknown windows_setting fields: {names}.")

    action_type = _required_text(action, "action_type").lower()
    if action_type != "windows_setting":
        raise InputError("windows_setting.action_type must be 'windows_setting'.")

    timestamp = _timestamp(_required_text(action, "timestamp"))
    verification_state = _enum_value(action, "verification_state", VERIFICATION_STATES)
    category = _enum_value(action, "category", WINDOWS_CATEGORIES)
    change = _enum_value(action, "change", CHANGE_KINDS)
    before = _state_summary(action, "before")
    after = _state_summary(action, "after")

    if verification_state == "verified":
        _validate_verified_change(change, before, after)

    optional: dict[str, str | None] = {}
    for field in ("actor", "tool"):
        optional[field] = _required_text(action, field) if field in action else None

    return WindowsAuditRecord(
        timestamp=timestamp,
        verification_state=cast(VerificationState, verification_state),
        source=_required_text(action, "source"),
        category=cast(WindowsCategory, category),
        target=_required_text(action, "target"),
        operation=_required_text(action, "operation"),
        change=cast(ChangeKind, change),
        before=before,
        after=after,
        actor=optional["actor"],
        tool=optional["tool"],
    )

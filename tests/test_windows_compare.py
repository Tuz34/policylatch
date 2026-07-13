import pytest

from mcp_guard.windows_audit import StateSummary, parse_windows_setting_action
from mcp_guard.windows_compare import ComparisonError, compare_windows_snapshots
from mcp_guard.windows_providers import ObservedWindowsSnapshot


def _snapshot(timestamp, present, *, category="registry", target="HKCU\\Demo"):
    return ObservedWindowsSnapshot(
        collected_at=timestamp,
        source="synthetic_provider",
        category=category,
        target=target,
        state=StateSummary(present=present),
    )


@pytest.mark.parametrize(
    "before_present,after_present,change",
    [
        (False, True, "created"),
        (True, False, "deleted"),
        (False, False, "unchanged"),
        (True, True, "unchanged"),
    ],
)
def test_verifies_presence_transitions(before_present, after_present, change):
    record = compare_windows_snapshots(
        _snapshot("2026-01-15T10:00:00Z", before_present),
        _snapshot("2026-01-15T10:01:00Z", after_present),
    )

    assert record.verification_state == "verified"
    assert record.change == change
    assert record.before.present is before_present
    assert record.after.present is after_present


def test_unknown_presence_remains_observed():
    record = compare_windows_snapshots(
        _snapshot("2026-01-15T10:00:00Z", None),
        _snapshot("2026-01-15T10:01:00Z", True),
    )

    assert record.verification_state == "observed"
    assert record.change == "unknown"


def test_carries_matching_proposed_intent_metadata():
    proposed = parse_windows_setting_action(
        {
            "action_type": "windows_setting",
            "timestamp": "2026-01-15T09:59:00Z",
            "verification_state": "proposed",
            "source": "synthetic_agent",
            "category": "registry",
            "target": "HKCU\\Demo",
            "operation": "create_key",
            "change": "unknown",
            "before": {"present": None},
            "after": {"present": None},
            "actor": "demo-agent",
            "tool": "demo-tool",
        }
    )

    record = compare_windows_snapshots(
        _snapshot("2026-01-15T10:00:00Z", False),
        _snapshot("2026-01-15T10:01:00Z", True),
        proposed=proposed,
    )

    assert record.operation == "create_key"
    assert record.actor == "demo-agent"
    assert record.tool == "demo-tool"


@pytest.mark.parametrize(
    "before,after,message",
    [
        (
            _snapshot("2026-01-15T10:00:00Z", False, category="registry"),
            _snapshot("2026-01-15T10:01:00Z", True, category="service"),
            "same category",
        ),
        (
            _snapshot("2026-01-15T10:00:00Z", False, target="HKCU\\One"),
            _snapshot("2026-01-15T10:01:00Z", True, target="HKCU\\Two"),
            "same target",
        ),
        (
            _snapshot("2026-01-15T10:02:00Z", False),
            _snapshot("2026-01-15T10:01:00Z", True),
            "cannot be older",
        ),
    ],
)
def test_rejects_incomparable_snapshots(before, after, message):
    with pytest.raises(ComparisonError, match=message):
        compare_windows_snapshots(before, after)

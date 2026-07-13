# Windows audit contract (experimental)

The Windows audit foundation defines how `mcp-guard` can describe a requested or
detected Windows setting change without storing the setting value. It is an
explicit, opt-in capability under development.

> [!IMPORTANT]
> This release performs **zero Windows system reads**. It has no background
> process, provider, command execution, elevation, remediation, telemetry, or
> network access. The module only validates an in-memory JSON-compatible object.

## Trust states

Every record carries exactly one verification state:

- `proposed`: an agent or tool declared an intended change.
- `observed`: a named read-only source reported a state; it is not independently
  proven.
- `verified`: known before and after snapshots were compared consistently.

An `observed` record is never promoted to `verified`. The producer must create a
new verified record from an independent comparison.

## Summary-only input

```json
{
  "action_type": "windows_setting",
  "timestamp": "2026-01-15T10:02:00Z",
  "verification_state": "verified",
  "source": "synthetic_snapshot_comparison",
  "category": "registry",
  "target": "HKCU\\Software\\SyntheticDemo\\Theme",
  "operation": "compare_setting_presence",
  "change": "created",
  "before": {"present": false},
  "after": {"present": true},
  "actor": "demo-agent",
  "tool": "synthetic-registry-adapter"
}
```

Supported categories are `registry`, `service`, `firewall`, `policy`, and
`setting`. Change kinds are `created`, `updated`, `deleted`, `unchanged`, and
`unknown`. Timestamps must include a UTC offset or `Z` suffix.

`before` and `after` deliberately contain presence only. The normalized record
adds `redacted: true` to both summaries. Raw values and value hashes are rejected,
because hashes can still disclose low-entropy settings through guessing. Unknown
fields are also rejected so an adapter cannot silently leak data through an
undocumented property.

The pure parser is available to integrations:

```python
from mcp_guard.windows_audit import parse_windows_setting_action

record = parse_windows_setting_action(action)
document = record.to_dict()
```

Parsing does not inspect the host and does not evaluate policy. The existing
`mcp-guard check` command continues to support its documented shell, file, and
network action types only.

## Opt-in provider boundary

`collect_windows_snapshot` is the single call gate for future read-only providers.
Its `enabled` keyword is required and only the literal value `True` opens the gate.
When disabled, it does not inspect the platform or call provider code. When
enabled outside Windows, it returns a clear `UnsupportedPlatformError` without
calling the provider.

Providers implement the small `WindowsSnapshotProvider` protocol and may return
only a redacted `StateSummary`. Their result is always labeled `observed`; a
provider cannot claim independent verification. No built-in Registry, service,
firewall, or policy provider exists yet, so this interface still performs no host
read on its own.

Historical JSONL and HTML filtering will consume records only after the concrete
provider and independent comparison boundaries are implemented and tested.

All examples in [`examples/windows-audit`](../examples/windows-audit) are
synthetic and contain no user or machine data.

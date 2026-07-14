# Runtime adapters

PolicyLatch can translate saved `PreToolUse` events from Claude Code and Codex
into the same local, deterministic policy decision used by `gateway-check`. The
adapter never forwards a tool call and never copies transcript paths, working
directories, prompt text, file content, or unknown field values into its report.

## Capability boundary

| Runtime | Current integration | Deny behavior | Important bypass |
|---|---|---|---|
| Claude Code | `PreToolUse` command hook | Blocking: `allow`, `ask`, or `deny` | Calls outside the configured hook are unseen |
| Codex | `PreToolUse` command hook | Advisory `systemMessage` only | Current command-hook output cannot stop the tool |

Claude Code documents a synchronous `PreToolUse` decision response with
`permissionDecision`. PolicyLatch maps `allow` to `allow`, `warn` to `ask`, and
`deny` to `deny`. See the official [Claude Code hooks reference](https://code.claude.com/docs/en/hooks).

Codex documents command hooks and the `systemMessage` output available to
`PreToolUse`. PolicyLatch therefore labels this adapter **advisory**, not an
enforcement boundary. See the official [Codex hooks reference](https://developers.openai.com/codex/config-advanced/#hooks).

## Review-first setup

Generate a snippet for the target runtime and review it before manually merging
it into `.claude/settings.json` or `.codex/hooks.json`:

```bash
policylatch adapter-config --runtime claude-code --profile strict --output claude-hook.json
policylatch adapter-config --runtime codex --profile strict --output codex-hook.json
policylatch adapter-doctor --runtime claude-code --config claude-hook.json
```

For a Claude Code config generated on another operating system, select the
command quoting explicitly with `--platform posix` or `--platform windows`.
Codex snippets include both POSIX and Windows command forms.

PolicyLatch does not edit either runtime's configuration. Removal is equally
explicit: delete the copied PolicyLatch `PreToolUse` matcher group. Claude Code's
`/hooks` and Codex's `/hooks` views can be used to inspect the active result.

## Synthetic verification

```bash
policylatch adapter-check \
  --runtime claude-code \
  --input examples/adapters/claude-code-denied-shell.json \
  --policy examples/policies/gateway-strict.yaml
```

`adapter-hook` reads one bounded JSON event from standard input by default. A
malformed event or policy exits with code `3`. A valid Claude Code event exits
with code `0` because the returned JSON is the hook control signal; its
`permissionDecision` carries the block or approval request.

These adapters do not install plugins, execute the proposed tool, start an MCP
server, or claim visibility into actions that bypass their configured hook.

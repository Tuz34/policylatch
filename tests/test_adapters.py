import json
from pathlib import Path

import pytest

from policylatch.adapters import (
    adapter_config_document,
    adapter_decision_document,
    hook_response,
    normalize_hook_event,
    validate_adapter_config,
)
from policylatch.cli import main
from policylatch.policy import load_policy
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]
POLICY_PATH = ROOT / "examples/policies/gateway-strict.yaml"
POLICY = load_policy(POLICY_PATH)


def event(tool_name="Bash", tool_input=None):
    return {
        "session_id": "synthetic-session",
        "transcript_path": "SYNTHETIC_TRANSCRIPT_PATH",
        "cwd": "SYNTHETIC_PRIVATE_CWD",
        "hook_event_name": "PreToolUse",
        "tool_name": tool_name,
        "tool_input": tool_input or {"command": "Remove-Item -Recurse D:\\Synthetic"},
        "tool_use_id": "synthetic-tool-use",
    }


@pytest.mark.parametrize("runtime", ["claude-code", "codex"])
def test_adapter_normalizes_only_policy_relevant_fields(runtime):
    payload = normalize_hook_event(runtime, event())
    rendered = json.dumps(payload)

    assert payload["method"] == "tools/call"
    assert payload["params"]["arguments"]["command"].startswith("Remove-Item")
    assert "SYNTHETIC_TRANSCRIPT_PATH" not in rendered
    assert "SYNTHETIC_PRIVATE_CWD" not in rendered


def test_claude_code_hook_blocks_deny_and_asks_on_warn():
    denied = adapter_decision_document("claude-code", event(), POLICY, "synthetic-policy")
    blocked = hook_response("claude-code", denied)
    assert blocked["hookSpecificOutput"]["permissionDecision"] == "deny"

    warned = adapter_decision_document(
        "claude-code",
        event("read_file", {"file_path": "docs/example.pem"}),
        POLICY,
        "synthetic-policy",
    )
    asked = hook_response("claude-code", warned)
    assert asked["hookSpecificOutput"]["permissionDecision"] == "ask"


def test_codex_hook_is_explicitly_advisory():
    document = adapter_decision_document("codex", event(), POLICY, "synthetic-policy")
    response = hook_response("codex", document)

    assert set(response) == {"systemMessage"}
    assert "advisory" in response["systemMessage"]
    assert "permissionDecision" not in json.dumps(response)


def test_unclassified_hook_values_never_reach_output():
    marker = "SYNTHETIC_SECRET_PROMPT_VALUE"
    document = adapter_decision_document(
        "claude-code",
        event("read_file", {"path": "README.md", "content": marker}),
        POLICY,
        "synthetic-policy",
    )

    assert document["decision"] == "warn"
    assert marker not in json.dumps(document)
    assert marker not in json.dumps(hook_response("claude-code", document))


@pytest.mark.parametrize("runtime", ["claude-code", "codex"])
def test_generated_config_is_reviewable_and_valid(runtime):
    path = "D:\\Synthetic Project\\policy.yaml"
    config = adapter_config_document(runtime, policy=path, platform="windows")
    result = validate_adapter_config(runtime, config)

    assert result["status"] == "ok"
    assert result["files_modified"] is False
    assert result["network_access"] is False
    handler = config["hooks"]["PreToolUse"][0]["hooks"][0]
    assert path in handler.get("commandWindows", handler["command"])


def test_config_doctor_rejects_remote_or_async_handlers():
    remote = adapter_config_document("claude-code", profile="strict")
    remote["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = "https://example.invalid"
    with pytest.raises(InputError, match="remote"):
        validate_adapter_config("claude-code", remote)

    asynchronous = adapter_config_document("codex", profile="strict")
    asynchronous["hooks"]["PreToolUse"][0]["hooks"][0]["async"] = True
    with pytest.raises(InputError, match="synchronous"):
        validate_adapter_config("codex", asynchronous)


def test_adapter_cli_checks_and_emits_hook_response_without_forwarding(tmp_path):
    decision_output = tmp_path / "decision.json"
    hook_output = tmp_path / "hook.json"
    source = ROOT / "examples/adapters/claude-code-denied-shell.json"

    assert (
        main(
            [
                "adapter-check",
                "--runtime",
                "claude-code",
                "--input",
                str(source),
                "--policy",
                str(POLICY_PATH),
                "--output",
                str(decision_output),
            ]
        )
        == 2
    )
    decision = json.loads(decision_output.read_text(encoding="utf-8"))
    assert decision["adapter"] == {
        "runtime": "claude-code",
        "event": "PreToolUse",
        "mode": "blocking",
        "forwarded": False,
    }

    assert (
        main(
            [
                "adapter-hook",
                "--runtime",
                "claude-code",
                "--input",
                str(source),
                "--policy",
                str(POLICY_PATH),
                "--output",
                str(hook_output),
            ]
        )
        == 0
    )
    assert (
        json.loads(hook_output.read_text(encoding="utf-8"))["hookSpecificOutput"][
            "permissionDecision"
        ]
        == "deny"
    )


def test_adapter_config_cli_does_not_install_configuration(tmp_path):
    output = tmp_path / "snippet.json"
    assert (
        main(
            [
                "adapter-config",
                "--runtime",
                "codex",
                "--profile",
                "strict",
                "--output",
                str(output),
            ]
        )
        == 0
    )

    assert output.exists()
    assert not (tmp_path / ".codex/hooks.json").exists()
    assert json.loads(output.read_text(encoding="utf-8"))["hooks"]["PreToolUse"]

import json
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.policy import PolicyError, load_policy, load_profile

ROOT = Path(__file__).parents[1]


def test_all_builtin_profiles_are_resolved_and_versioned():
    for name in ("minimal", "balanced", "strict", "ci"):
        policy = load_profile(name)
        assert policy["version"] == 1
        assert policy["_provenance"]["profiles"] == [name]
        assert policy["_provenance"]["sources"][0] == f"profile:{name}"


def test_profile_policy_overrides_are_deterministic():
    policy = load_policy(ROOT / "examples/policies/project-balanced.yaml")

    assert policy["default_decision"] == "warn"
    assert policy["rules"]["network"]["allow_domains"] == [
        "github.com",
        "api.github.com",
    ]
    assert policy["_provenance"]["rule_sources"]["network.allow_domains"] == (
        "policy:project-balanced.yaml"
    )
    assert policy["_provenance"]["sources"] == [
        "profile:balanced",
        "policy:project-balanced.yaml",
    ]


def test_local_inheritance_replaces_named_rule_lists(tmp_path):
    base = tmp_path / "base.yaml"
    child = tmp_path / "child.yaml"
    base.write_text(
        "version: 1\ndefault_decision: warn\nrules:\n  shell:\n    warn_patterns: ['git push']\n",
        encoding="utf-8",
    )
    child.write_text(
        "version: 1\nextends: base.yaml\nrules:\n  shell:\n    warn_patterns: []\n",
        encoding="utf-8",
    )

    policy = load_policy(child)

    assert policy["default_decision"] == "warn"
    assert policy["rules"]["shell"]["warn_patterns"] == []
    assert policy["_provenance"]["default_decision_source"] == "policy:base.yaml"
    assert policy["_provenance"]["rule_sources"]["shell.warn_patterns"] == ("policy:child.yaml")


@pytest.mark.parametrize("reference", ["../outside.yaml", "https://example.test/base.yaml"])
def test_inheritance_rejects_workspace_escape_and_remote_urls(tmp_path, reference):
    policy = tmp_path / "policy.yaml"
    policy.write_text(f"version: 1\nextends: {reference!r}\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="inside the root|Remote policy"):
        load_policy(policy)


def test_inheritance_cycle_fails_closed(tmp_path):
    (tmp_path / "a.yaml").write_text("version: 1\nextends: b.yaml\n", encoding="utf-8")
    (tmp_path / "b.yaml").write_text("version: 1\nextends: a.yaml\n", encoding="utf-8")

    with pytest.raises(PolicyError, match="cycle detected"):
        load_policy(tmp_path / "a.yaml")


def test_doctor_and_explain_profile_provenance(tmp_path, capsys):
    assert main(["doctor", "--profile", "balanced"]) == 0
    doctor = json.loads(capsys.readouterr().out)
    assert doctor["status"] == "ok"
    assert doctor["policy_provenance"]["sources"] == ["profile:balanced"]
    assert doctor["network_access"] is False

    result = tmp_path / "result.json"
    assert (
        main(
            [
                "check",
                "--action",
                str(ROOT / "examples/actions/risky-shell-command.json"),
                "--profile",
                "balanced",
                "--output",
                str(result),
            ]
        )
        == 2
    )
    capsys.readouterr()
    assert main(["explain", "--input", str(result), "--format", "json"]) == 0
    explanation = json.loads(capsys.readouterr().out)
    assert explanation["decision"] == "deny"
    assert explanation["findings"][0]["source"] == "profile:balanced"
    assert "matched" not in explanation["findings"][0]

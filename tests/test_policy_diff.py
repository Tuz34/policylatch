import json
from pathlib import Path

import pytest

from policylatch.cli import main
from policylatch.policy import load_policy
from policylatch.policy_diff import policy_diff_document, policy_diff_markdown
from policylatch.sarif_report import sarif_report
from policylatch.validation import InputError

ROOT = Path(__file__).parents[1]


def write_policy(path, decision, rules=""):
    path.write_text(
        f"version: 1\ndefault_decision: {decision}\n" + rules,
        encoding="utf-8",
    )
    return load_policy(path)


def fixture(name="fixture.json", marker="synthetic-safe"):
    return (
        name,
        {
            "_expected": "allow",
            "_private": "SYNTHETIC_FIXTURE_METADATA",
            "action_type": "shell",
            "command": f"echo {marker}",
        },
    )


@pytest.mark.parametrize("before", ["allow", "warn", "deny"])
@pytest.mark.parametrize("after", ["allow", "warn", "deny"])
def test_all_decision_transitions_are_classified(tmp_path, before, after):
    before_policy = write_policy(tmp_path / "before.yaml", before)
    after_policy = write_policy(tmp_path / "after.yaml", after)
    report = policy_diff_document(
        [fixture()],
        before_policy,
        after_policy,
        "before.yaml",
        "after.yaml",
        "fixtures",
        "none",
    )
    result = report["results"][0]
    assert result["transition"] == f"{before}->{after}"
    expected = (
        "relaxation"
        if {"allow": 0, "warn": 1, "deny": 2}[before] > {"allow": 0, "warn": 1, "deny": 2}[after]
        else "tightening"
        if before != after
        else "unchanged"
    )
    assert result["classification"] == expected


def test_fixture_order_does_not_change_diff(tmp_path):
    before = write_policy(tmp_path / "before.yaml", "deny")
    after = write_policy(tmp_path / "after.yaml", "allow")
    fixtures = [fixture("z.json", "z"), fixture("a.json", "a")]
    first = policy_diff_document(
        fixtures, before, after, "before", "after", "fixtures", "deny-to-allow"
    )
    second = policy_diff_document(
        list(reversed(fixtures)),
        before,
        after,
        "before",
        "after",
        "fixtures",
        "deny-to-allow",
    )
    assert first == second
    assert [result["subject"] for result in first["results"]] == ["a.json", "z.json"]


def test_case_insensitive_duplicate_fixture_names_are_rejected(tmp_path):
    policy = write_policy(tmp_path / "policy.yaml", "allow")
    with pytest.raises(InputError, match="case-insensitively"):
        policy_diff_document(
            [fixture("A.json"), fixture("a.json")],
            policy,
            policy,
            "before",
            "after",
            "fixtures",
            "none",
        )


def test_equivalent_policy_has_stable_empty_diff(tmp_path):
    policy = write_policy(tmp_path / "same.yaml", "warn")
    first = policy_diff_document(
        [fixture()], policy, policy, "same", "same", "fixtures", "deny-to-allow"
    )
    second = policy_diff_document(
        [fixture()], policy, policy, "same", "same", "fixtures", "deny-to-allow"
    )
    assert first["summary"]["changed"] == 0
    assert first["rule_summary"]["changes"] == []
    assert first["comparison_fingerprint"] == second["comparison_fingerprint"]
    assert first["gate"]["failed"] is False


def test_rule_summary_and_counterexample_are_redacted(tmp_path):
    before = write_policy(tmp_path / "before.yaml", "allow")
    rules = (
        "rules:\n"
        "  shell:\n"
        "    deny_patterns: [git]\n"
        "    warn_patterns: [git push, SYNTHETIC_PRIVATE_POLICY_PATTERN]\n"
    )
    after = write_policy(tmp_path / "after.yaml", "allow", rules)
    report = policy_diff_document([fixture()], before, after, "before", "after", "fixtures", "none")
    rendered = json.dumps(report)
    assert report["rule_summary"]["added"] == 3
    assert report["rule_summary"]["ineffective_in_corpus"] == 3
    assert report["rule_summary"]["shadowed"] == 1
    assert report["counterexample_suggestions"]
    assert "SYNTHETIC_PRIVATE_POLICY_PATTERN" not in rendered


def test_raw_fixture_values_do_not_reach_json_markdown_or_sarif(tmp_path):
    marker = "SYNTHETIC_PRIVATE_FIXTURE_COMMAND"
    before = write_policy(tmp_path / "before.yaml", "deny")
    after = write_policy(tmp_path / "after.yaml", "allow")
    report = policy_diff_document(
        [fixture(marker=marker)],
        before,
        after,
        "before",
        "after",
        "fixtures",
        "deny-to-allow",
    )
    for rendered in (json.dumps(report), policy_diff_markdown(report), sarif_report(report)):
        assert marker not in rendered
        assert "SYNTHETIC_FIXTURE_METADATA" not in rendered
    assert report["results"][0]["before_receipt"].startswith("sha256:")
    assert report["results"][0]["after_receipt"].startswith("sha256:")


def test_deny_to_allow_gate_returns_nonzero_cli_exit(tmp_path):
    before_path = tmp_path / "before.yaml"
    after_path = tmp_path / "after.yaml"
    write_policy(before_path, "deny")
    write_policy(after_path, "allow")
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "safe.json").write_text(json.dumps(fixture()[1]), encoding="utf-8")
    output = tmp_path / "diff.json"

    code = main(
        [
            "policy-diff",
            "--before",
            str(before_path),
            "--after",
            str(after_path),
            "--fixtures",
            str(fixtures),
            "--fail-on",
            "deny-to-allow",
            "--output",
            str(output),
        ]
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert code == 2
    assert payload["gate"] == {"fail_on": "deny-to-allow", "failed": True}


def test_gate_none_reports_relaxation_without_ci_failure(tmp_path):
    before_path = tmp_path / "before.yaml"
    after_path = tmp_path / "after.yaml"
    write_policy(before_path, "warn")
    write_policy(after_path, "allow")
    fixtures = tmp_path / "fixtures"
    fixtures.mkdir()
    (fixtures / "safe.json").write_text(json.dumps(fixture()[1]), encoding="utf-8")
    assert (
        main(
            [
                "policy-diff",
                "--before",
                str(before_path),
                "--after",
                str(after_path),
                "--fixtures",
                str(fixtures),
                "--fail-on",
                "none",
            ]
        )
        == 0
    )

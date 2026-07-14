from pathlib import Path

import pytest

from policylatch.policy import PolicyError, load_policy

ROOT = Path(__file__).parents[1]


def test_loads_balanced_policy():
    policy = load_policy(ROOT / "examples/policies/balanced.yaml")
    assert policy["version"] == 1
    assert policy["default_decision"] == "allow"


def test_rejects_unknown_version(tmp_path):
    path = tmp_path / "bad.yaml"
    path.write_text("version: 2\nrules: {}\n", encoding="utf-8")
    with pytest.raises(PolicyError, match="version 1"):
        load_policy(path)


def test_rejects_unknown_rule_name(tmp_path):
    path = tmp_path / "typo.yaml"
    path.write_text(
        "version: 1\nrules:\n  shell:\n    deny_pattern: ['rm -rf']\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="Unknown rule"):
        load_policy(path)


def test_rejects_empty_pattern(tmp_path):
    path = tmp_path / "empty.yaml"
    path.write_text(
        "version: 1\nrules:\n  shell:\n    deny_patterns: ['']\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError, match="empty patterns"):
        load_policy(path)


def test_rejects_oversized_policy_before_parse(tmp_path, monkeypatch):
    path = tmp_path / "oversized.yaml"
    path.write_bytes(b"version: 1\n" + b" " * 32)
    monkeypatch.setattr("policylatch.policy.MAX_POLICY_BYTES", 16)

    with pytest.raises(PolicyError, match="16-byte limit"):
        load_policy(path)


def test_rejects_non_utf8_policy(tmp_path):
    path = tmp_path / "invalid-utf8.yaml"
    path.write_bytes(b"version: 1\n\xff")

    with pytest.raises(PolicyError, match="valid UTF-8"):
        load_policy(path)

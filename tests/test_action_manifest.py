from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_composite_action_exposes_a_small_explicit_contract():
    manifest = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))

    assert manifest["runs"]["using"] == "composite"
    assert set(manifest["inputs"]) == {
        "command",
        "input-file",
        "policy-file",
        "format",
        "output-file",
        "fail-on",
        "python-version",
    }
    assert set(manifest["outputs"]) == {"exit-code", "decision", "report-path"}


def test_composite_action_runs_only_the_local_policylatch_cli():
    manifest = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    steps = manifest["runs"]["steps"]
    scripts = "\n".join(step.get("run", "") for step in steps)

    assert steps[0]["uses"] == "actions/setup-python@v6"
    assert 'pip install "$GITHUB_ACTION_PATH"' in scripts
    assert 'python -m policylatch "$POLICYLATCH_COMMAND"' in scripts
    assert 'gateway-check) input_flag="--request"' in scripts
    assert 'gateway-replay) input_flag="--input"' in scripts
    assert "MCP_GUARD_" not in scripts
    assert "curl" not in scripts
    assert "Invoke-WebRequest" not in scripts
    assert "powershell" not in scripts.lower()


def test_composite_action_rejects_multiline_output_paths_before_writing_outputs():
    manifest = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    script = next(step["run"] for step in manifest["runs"]["steps"] if step.get("id") == "guard")

    assert "*$'\\n'*|*$'\\r'*" in script
    assert "output-file must be a non-empty single-line path" in script
    assert "printf 'report-path=%s\\n'" in script
    assert 'echo "report-path=$POLICYLATCH_OUTPUT"' not in script

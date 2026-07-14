import importlib
from pathlib import Path

from policylatch import __version__
from policylatch.environment import windows_integration_enabled

ROOT = Path(__file__).resolve().parents[1]


def test_primary_distribution_and_cli_keep_a_legacy_entry_point():
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

    assert 'name = "policylatch"' in metadata
    assert 'policylatch = "policylatch.cli:main"' in metadata
    assert 'mcp-guard = "policylatch.cli:main"' in metadata


def test_legacy_imports_resolve_to_the_primary_implementation():
    module_names = {
        path.stem
        for path in (ROOT / "src/policylatch").glob("*.py")
        if path.stem not in {"__init__", "__main__"}
    }
    assert module_names
    for module_name in module_names:
        legacy = importlib.import_module(f"mcp_guard.{module_name}")
        primary = importlib.import_module(f"policylatch.{module_name}")
        assert legacy is primary
    assert importlib.import_module("mcp_guard").__version__ == __version__


def test_primary_windows_integration_variable_takes_precedence():
    assert windows_integration_enabled({"POLICYLATCH_WINDOWS_INTEGRATION": "1"})
    assert not windows_integration_enabled(
        {
            "POLICYLATCH_WINDOWS_INTEGRATION": "0",
            "MCP_GUARD_WINDOWS_INTEGRATION": "1",
        }
    )


def test_legacy_windows_integration_variable_remains_supported():
    assert windows_integration_enabled({"MCP_GUARD_WINDOWS_INTEGRATION": "1"})
    assert not windows_integration_enabled({})

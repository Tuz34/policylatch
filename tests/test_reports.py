from mcp_guard.reports import markdown_report


def test_markdown_report_escapes_user_controlled_structure():
    report = markdown_report(
        {
            "source": "demo`\nsource.json",
            "decision": "warn",
            "risk_level": "medium",
            "results": [
                {
                    "subject": "tool|name\nnext",
                    "decision": "warn",
                    "risk_level": "medium",
                    "reasons": [
                        {
                            "rule": "mcp_tools.warn_if_name_contains",
                            "effect": "warn",
                            "matched": "exec`\nvalue",
                            "message": "Review|required",
                        }
                    ],
                }
            ],
        }
    )
    assert "demo' source.json" in report
    assert "tool\\|name next" in report
    assert "`exec' value`" in report
    assert "Review\\|required" in report

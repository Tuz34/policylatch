from html.parser import HTMLParser

from policylatch.html_report import html_report


class _Parser(HTMLParser):
    pass


def _payload() -> dict:
    return {
        "schema_version": 1,
        "kind": "manifest_scan",
        "source": "synthetic-server.json",
        "decision": "deny",
        "risk_level": "high",
        "results": [
            {
                "subject": "shell_exec",
                "decision": "deny",
                "risk_level": "high",
                "reasons": [
                    {
                        "rule": "mcp_tools.deny_if_description_contains",
                        "effect": "deny",
                        "matched": "send file contents",
                        "message": "Tool description contains a blocked phrase.",
                    }
                ],
            }
        ],
    }


def test_html_report_is_self_contained_and_semantic():
    report = html_report(_payload())
    parser = _Parser()
    parser.feed(report)
    assert report.startswith("<!doctype html>")
    assert "PolicyLatch" in report
    assert '<html lang="en">' in report
    assert "Overall decision" not in report
    assert 'aria-label="Decision summary"' in report
    assert "Policy findings" in report
    assert "Blocked" in report
    assert "Needs review" not in report
    assert '<ul class="finding-list">' in report
    assert '<li class="finding-item finding-deny">' in report
    assert "DENY" in report
    assert "<script" not in report
    assert "https://" not in report
    assert "http://" not in report


def test_html_report_escapes_input_values():
    payload = _payload()
    payload["source"] = '<script>alert("source")</script>'
    payload["results"][0]["subject"] = "<img src=x onerror=alert(1)>"
    payload["results"][0]["reasons"][0]["matched"] = "<unsafe>"
    report = html_report(payload)
    assert '<script>alert("source")</script>' not in report
    assert "&lt;script&gt;" in report
    assert "&lt;img src=x onerror=alert(1)&gt;" in report
    assert "&lt;unsafe&gt;" in report


def test_html_report_has_responsive_and_print_styles():
    report = html_report(_payload())
    assert "@media (max-width: 760px)" in report
    assert "@media print" in report
    assert "prefers-color-scheme: light" in report


def test_html_report_groups_deny_before_warn_findings():
    payload = _payload()
    payload["results"].append(
        {
            "subject": "browser_tool",
            "decision": "warn",
            "risk_level": "medium",
            "reasons": [
                {
                    "rule": "mcp_tools.warn_if_name_contains",
                    "effect": "warn",
                    "matched": "browser",
                    "message": "Tool name indicates a powerful capability.",
                }
            ],
        }
    )
    report = html_report(payload)
    assert "Needs review" in report
    assert report.index("Blocked") < report.index("Needs review")

import json

from socket_basics.core.connector.opengrep.github_pr import format_notifications


def test_comment_keeps_distinct_rule_ids_for_findings_in_the_same_file():
    items = [
        {
            "component": {},
            "alert": {
                "severity": severity,
                "props": {
                    "filePath": "src/app.py",
                    "ruleId": rule,
                    "startLine": line,
                    "endLine": line,
                },
            },
        }
        for rule, severity, line in [("first-rule", "high", 1), ("second-rule", "medium", 2)]
    ]
    rendered = json.dumps(format_notifications({"sast-python": items}))
    assert "first-rule" in rendered
    assert "second-rule" in rendered

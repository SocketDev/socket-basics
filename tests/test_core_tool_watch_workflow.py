from pathlib import Path


WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "core-tool-watch.yml"


def test_issue_reconciliation_prefers_an_open_issue() -> None:
    workflow = WORKFLOW.read_text()
    reconcile = workflow[workflow.index("- name: Reconcile drift tracking issue") :]

    open_lookup = reconcile.index("--state open --limit 1")
    closed_fallback = reconcile.index('if [ -z "$existing" ]; then')
    closed_lookup = reconcile.index("--state closed --limit 1")

    assert open_lookup < closed_fallback < closed_lookup
    assert "--state all" not in reconcile

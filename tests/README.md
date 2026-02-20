# Tests

Quick-start for running tests locally:

```bash
./venv/bin/python -m pytest
```

Notes:
- Tests are lightweight and should not require external services.
- Use the local config-wiring script for Jira setup validation:
  `./venv/bin/python scripts/verify_jira_dashboard_config.py`
